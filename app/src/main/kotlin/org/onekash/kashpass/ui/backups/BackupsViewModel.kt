package org.onekash.kashpass.ui.backups

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlin.time.Duration
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.onekash.kashpass.session.BackupChange
import org.onekash.kashpass.session.BackupSettings
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.vault.backup.BackupDeletion
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupRetention
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpening
import org.onekash.kashpass.vault.policy.SlowKdf

/** What the Vault backups sheet shows; null while the sheet is closed. */
data class BackupsUiState(
    /** The copies, newest first; null until they are listed. */
    val items: List<BackupInfo>? = null,
    val opening: Boolean = false,
    val failed: Boolean = false,
    /** The picked copy didn't open with the vault's password: it was kept under an older one. */
    val oldPassword: Boolean = false,
    /** The picked copy, when it can open from the lock screen with its own password. */
    val passwordTarget: PasswordTarget? = null,
    /** The picked backup doesn't match its hash. */
    val damaged: Boolean = false,
    /** The picked backup's unlock settings are far slower than the file's. */
    val slow: Boolean = false,
    /** How many copies each vault keeps. */
    val keep: Int = BackupRetention.DEFAULT_KEEP,
    /** A save is unverified (its save marker is pending), so no copy can be deleted. */
    val pinned: Boolean = false,
    /** False for a backup opened read-only: the count and the copies belong to the file itself. */
    val isFile: Boolean = true,
    /**
     * A count the store refused because more copies would go than shown; the sheet shows the
     * confirm again.
     */
    val askKeep: Int? = null,
    /** A change to the count is running. */
    val applying: Boolean = false,
    /** Copies hidden by a staged delete; the Undo snackbar shows above 0. */
    val undo: Int = 0,
    /** Why a staged delete was refused when it ran; null once shown. */
    val notice: BackupsNotice? = null,
) {
    /** True when the count takes a change: the file itself, copies listed, nothing applying. */
    val canChangeBackups: Boolean get() = isFile && items != null && !applying

    /**
     * True when a copy can be swiped away: as [canChangeBackups], no save is unverified and no
     * copy is opening, so the copy being opened is never deleted under it.
     */
    val canDelete: Boolean get() = canChangeBackups && !pinned && !opening
}

/** A copy to open from the lock screen with the password typed there; [slow] when it is slow. */
data class PasswordTarget(val backup: BackupInfo, val slow: SlowKdf?)

/** Why a staged delete was refused when it ran. */
enum class BackupsNotice {
    /** A save started and isn't verified yet; nothing is deleted until it is. */
    PINNED,

    /** The copy couldn't be deleted. */
    FAILED,
}

/**
 * Drives the Vault backups sheet, opened from Settings while a vault is open: the copies and
 * how many to keep ([BackupSettings]). Opening a copy shows it read-only in place of the file,
 * with the session's key. A lock closes the sheet.
 *
 * A swiped copy is hidden at once and deleted after the Undo window, unless Undo brings it back.
 * Closing the sheet, opening a copy, changing the count and a lock delete it at once, with the
 * location taken when it was swiped, so no session is needed. The timer runs here, not in the
 * snackbar, so the delete runs with the sheet off screen. A process that dies before then keeps
 * the copy.
 * [BackupsViewModelTest] pins it.
 */
class BackupsViewModel(
    private val sessions: SessionHolder,
    private val saves: SaveCoordinator,
    private val opener: VaultOpening,
    private val backups: BackupSettings,
) : ViewModel() {

    private val mutable = MutableStateFlow<BackupsUiState?>(null)
    val state: StateFlow<BackupsUiState?> = mutable.asStateFlow()

    // The store's copies, newest first; the sheet shows them less the staged and committing ones.
    private var listed: List<BackupInfo>? = null

    // Swiped copies Undo can bring back, by id, with the location taken when each was swiped.
    private val staged = LinkedHashMap<String, String>()

    // Copies being deleted; they stay hidden until the list is read again.
    private val committing = mutableSetOf<String>()

    private var window: Job? = null

    // Bumped by every list read; a read that started before a newer one drops its result, so a
    // read from before a delete can't bring the deleted copy back.
    private var listReads = 0

    // Running count changes; main thread only.
    private var inFlight = 0

    init {
        viewModelScope.launch {
            sessions.current.filter { it == null }.collect {
                mutable.value = null
                commitNow()
            }
        }
    }

    private fun visible(): List<BackupInfo>? = listed?.filterNot { it.id in staged || it.id in committing }

    /** Opens the sheet for the open vault and loads its backups, newest first. */
    fun show() {
        val unlocked = sessions.current.value ?: return
        mutable.value = BackupsUiState(keep = backups.keep(), isFile = unlocked.backup == null, applying = inFlight > 0)
        viewModelScope.launch { reload(unlocked.location) }
    }

    private suspend fun reload(location: String) {
        val read = ++listReads
        val copies = opener.backups(location)
        if (read != listReads) return
        listed = copies
        mutable.update { it?.copy(items = visible(), pinned = backups.pinned()) }
    }

    /** Saves [count] by [BackupSettings.setKeep]; [confirmed] is the removal shown. */
    fun setKeep(count: Int, confirmed: Int) {
        val location = sessions.current.value?.location ?: return
        inFlight++
        mutable.update { it?.copy(applying = true) }
        viewModelScope.launch {
            try {
                // The count shown leaves out staged copies; delete them so it matches the store.
                commitNow()
                when (val change = backups.setKeep(count, confirmed)) {
                    is BackupChange.Done -> mutable.update { it?.copy(keep = change.keep, askKeep = null) }
                    is BackupChange.Recount -> mutable.update { it?.copy(askKeep = count) }
                    null -> Unit
                }
                reload(location)
            } finally {
                inFlight--
                mutable.update { it?.copy(applying = inFlight > 0) }
            }
        }
    }

    /** Clears a repeated question after the user cancels it. */
    fun dismissAsk() {
        mutable.update { it?.copy(askKeep = null) }
    }

    /** Closes the sheet; a staged delete runs at once. */
    fun close() {
        mutable.value = null
        viewModelScope.launch { commitNow() }
    }

    /** Hides [backup] and deletes it when the Undo [window] ends; the newest is never staged. */
    fun stageDelete(backup: BackupInfo, window: Duration) {
        if (mutable.value?.canDelete != true || listed?.firstOrNull()?.id == backup.id) return
        val location = backups.deletable() ?: return
        staged[backup.id] = location
        mutable.update { it?.copy(items = visible(), undo = staged.size, notice = null) }
        this.window?.cancel()
        this.window = viewModelScope.launch {
            delay(window)
            // Past the window nothing cancels this job, so a close or lock can't stop a delete.
            this@BackupsViewModel.window = null
            commit()
        }
    }

    /** Brings back every staged copy; nothing is deleted. */
    fun undoDelete() {
        window?.cancel()
        staged.clear()
        mutable.update { it?.copy(items = visible(), undo = 0) }
    }

    /** Clears [BackupsUiState.notice] once the sheet showed it. */
    fun noticeShown() {
        mutable.update { it?.copy(notice = null) }
    }

    // Stops the Undo window and deletes the staged copies now.
    private suspend fun commitNow() {
        window?.cancel()
        commit()
    }

    private suspend fun commit() {
        if (staged.isEmpty()) return
        val batch = LinkedHashMap(staged)
        staged.clear()
        committing += batch.keys
        mutable.update { it?.copy(undo = 0) }
        var notice: BackupsNotice? = null
        for ((id, location) in batch) {
            when (backups.delete(location, id)) {
                BackupDeletion.Pinned -> notice = BackupsNotice.PINNED
                BackupDeletion.Failed -> if (notice == null) notice = BackupsNotice.FAILED
                // The newest is never staged; a copy already gone counts as deleted.
                BackupDeletion.Newest, BackupDeletion.NotFound, BackupDeletion.Deleted -> Unit
            }
        }
        if (mutable.value != null) reload(batch.values.first())
        committing -= batch.keys
        mutable.update { it?.copy(items = visible(), notice = notice ?: it.notice) }
    }

    /** Opens [backup] read-only in place of the file. */
    fun select(backup: BackupInfo) {
        if (sessions.current.value == null) return
        mutable.update { it?.copy(opening = true, failed = false, oldPassword = false, passwordTarget = null, damaged = false, slow = false) }
        viewModelScope.launch {
            // The copy on screen replaces the file's session; a staged delete runs first.
            commitNow()
            when (val result = saves.openBackup(backup)) {
                is OpenResult.Unlocked -> close()
                OpenResult.BackupDamaged -> mutable.update { it?.copy(opening = false, damaged = true) }
                is OpenResult.TooSlow -> mutable.update { it?.copy(opening = false, slow = true, passwordTarget = PasswordTarget(backup, result.slow)) }
                // The session's key didn't fit: the copy was kept under another password.
                OpenResult.WrongPassword -> mutable.update { it?.copy(opening = false, failed = true, oldPassword = true, passwordTarget = PasswordTarget(backup, null)) }
                // A lock (the lock collector closes the sheet), or a session-only file, which
                // Settings never offers backups for.
                null -> Unit
                else -> mutable.update { it?.copy(opening = false, failed = true) }
            }
        }
    }

    /**
     * Runs a staged delete, closes the sheet, then hands [BackupsUiState.passwordTarget] to
     * [onReady], which locks and opens it from the lock screen.
     */
    fun openWithPassword(onReady: (PasswordTarget) -> Unit) {
        val target = mutable.value?.passwordTarget ?: return
        viewModelScope.launch {
            commitNow()
            // A lock during the delete already closed the sheet; there is no vault left to lock.
            if (sessions.current.value == null) return@launch
            mutable.value = null
            onReady(target)
        }
    }
}
