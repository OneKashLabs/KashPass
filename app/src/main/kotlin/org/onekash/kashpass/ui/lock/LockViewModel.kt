package org.onekash.kashpass.ui.lock

import android.net.Uri
import androidx.core.net.toUri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.onekash.kashpass.platform.ChooseResult
import org.onekash.kashpass.platform.KeyFileChoice
import org.onekash.kashpass.platform.KeyFiles
import org.onekash.kashpass.platform.RememberedVault
import org.onekash.kashpass.platform.VaultFiles
import org.onekash.kashpass.session.BiometricResult
import org.onekash.kashpass.session.BiometricStatus
import org.onekash.kashpass.session.BiometricUnlock
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.open.LastCopyReason
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpening
import org.onekash.kashpass.vault.policy.SlowKdf
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.CryptoHandle
import org.onekash.kashpass.vault.storage.KeyFileRead

/**
 * Drives the lock screen: checks the remembered file when the screen appears (so unsafe or
 * unreadable files are reported before a password is typed), applies file picks, and unlocks with
 * the password or, when it is on, with [biometric].
 *
 * The system prompt opens once per appearance (a lock, or the activity starting while locked) when
 * biometric unlock is on and the file checked out; the user's Cancel or Use password stops it
 * until the next appearance, an interruption by the system doesn't. A rotation isn't a new
 * appearance. Nothing prompts while a picker KashPass launched is open: its result arrives after
 * the activity starts again.
 *
 * The vault's key file ([keyFiles]) is read again for each unlock, password, backup and
 * biometric alike, while its chip shows ([LockUiState.keyFileName]).
 *
 * A file another app hands over ([onIncoming]) never replaces the remembered vault without the
 * user's tap. A file KashPass can't keep a read and write grant for opens read-only for this
 * session: no biometric prompt, no biometric state check, a key file kept in memory only, and an
 * unlock that stores nothing ([FileAccess.SESSION_ONLY]). The next lock drops it and the screen
 * returns to the remembered vault.
 */
class LockViewModel(
    private val files: VaultFiles,
    private val opener: VaultOpening,
    private val sessions: SessionHolder,
    private val biometric: BiometricUnlock? = null,
    private val keyFiles: KeyFiles? = null,
) : ViewModel() {

    // False once the user dismissed the prompt during this appearance.
    private var autoPrompt = true
    // True once the activity stopped without a rotation; the next start is a new appearance.
    private var stopped = false
    // The last prompt and pick requests the screen served, so a rotation doesn't repeat them.
    private var promptServed = 0
    private var pickServed = 0
    private var pickPending = false

    // A file to make the vault after the vault locks ([useFile]).
    private var pendingFile: Uri? = null

    // A copy to open with its own password after the vault locks ([requestBackup]).
    private var pendingBackup: PendingBackup? = null

    private class PendingBackup(val backup: BackupInfo, val slow: SlowKdf?)

    /**
     * True once Kash has waved on first run, once per view model (the activity's): a rotation or a
     * return to first run shows Kash at rest. Kept apart from [uiState], which each refresh
     * rebuilds.
     */
    var wavePlayed = false
        private set

    /** Records that Kash's first-run wave has started. */
    fun markWavePlayed() {
        wavePlayed = true
    }

    // A file another app handed over while a vault was unlocked, handled after the next lock.
    private var pendingIncoming: Incoming? = null

    private class Incoming(val uri: Uri, val writableGrant: Boolean)

    // A file another app handed over that opens read-only for this session, and its key file.
    private var sessionTarget: SessionTarget? = null

    // A key-file pick or removal replaces it with a copy, so a check that the target is still the
    // one shown compares its fields: an unlock compares the location, a key-file pick the location
    // and the hand-over number. Only [handleIncoming] sets that number, one per hand-over, so the
    // same file handed over again gets a new one.
    private data class SessionTarget(
        val location: String,
        val name: String,
        val handover: Int,
        val keyFile: Uri? = null,
        val keyFileName: String? = null,
    )

    // Bumped by each hand-over that becomes a session target.
    private var handovers = 0

    // Bumped by each session-only key-file pick and removal; a pick whose name loads under an
    // older number drops its result, so the last pick or removal wins.
    private var sessionKeyFileChanges = 0

    // A file another app handed over with a read and write grant, shown with Open this file.
    private var offered: Uri? = null

    // Where the next picker opens when no session target is shown ([requestPick]).
    private var pickFrom: Uri? = null

    private val state = MutableStateFlow(LockUiState())
    val uiState: StateFlow<LockUiState> = state.asStateFlow()

    init {
        refresh()
        // A lock (screen off, the timer) after an unlock started stops it, as Back does, so its key
        // derivation stops with the lock. LockViewModelTest pins it.
        viewModelScope.launch {
            sessions.lockCounts.collect { count -> if (count > attemptLocks) cancelUnlock() }
        }
        // The view model outlives the lock screen (activity scope), so each return to it after a
        // lock checks the file again, as the first appearance does.
        viewModelScope.launch {
            sessions.current.drop(1).filter { it == null }.collect {
                autoPrompt = true
                val file = pendingFile
                val backup = pendingBackup
                val incoming = pendingIncoming
                pendingFile = null
                pendingBackup = null
                pendingIncoming = null
                // A session-only file is dropped on lock; the screen returns to the remembered
                // vault.
                dropIncoming()
                when {
                    file != null -> onPicked(file)
                    backup != null -> refresh { asBackupTarget(backup.backup, null, backup.slow) }
                    incoming != null -> handleIncoming(incoming)
                    else -> refresh()
                }
            }
        }
    }

    // Bumped by every refresh and pick; a check started under an older number drops its result.
    private var checkGeneration = 0

    // Forgets the session target, its key file and an offered file.
    private fun dropIncoming(keep: Uri? = null) {
        sessionTarget = null
        dropOffered(keep)
    }

    // Forgets an offered file and releases the grant taken for it, unless [keep] is that file
    // (picked as the vault, which takes the grant again).
    private fun dropOffered(keep: Uri? = null) {
        val uri = offered ?: return
        offered = null
        if (uri != keep) viewModelScope.launch { files.releaseOffered(uri) }
    }

    // Shows an Open with that arrived while an unlock ran, once the attempt didn't open the
    // vault; after an unlock it stays pending until the next lock.
    private fun showPendingIncoming() {
        if (sessions.current.value != null) return
        val incoming = pendingIncoming ?: return
        pendingIncoming = null
        handleIncoming(incoming)
    }

    /**
     * Re-reads and checks the session target, else the remembered file, then applies [after] to
     * the result. An offered file goes back to the remembered vault and its grant is released.
     */
    fun refresh(after: LockUiState.() -> LockUiState = { this }) {
        val generation = ++checkGeneration
        dropOffered()
        val target = sessionTarget
        if (target != null) {
            state.value = freshState(target.name, checking = true)
            viewModelScope.launch {
                val result = opener.check(target.location, FileAccess.SESSION_ONLY)
                if (generation != checkGeneration) return@launch
                state.update { it.copy(checking = false).withResult(result).after() }
            }
            return
        }
        val vault = files.current()
        if (vault == null) {
            state.value = freshState(null, checking = false).after()
            return
        }
        state.value = freshState(vault.displayName, checking = true)
        viewModelScope.launch {
            val result = opener.check(vault.location)
            val turnedOff = biometric?.reconcile(vault.location)
            val biometricOn = result is OpenResult.Ready && result.slow == null && biometric?.status(vault.location) == BiometricStatus.On
            if (generation != checkGeneration) return@launch
            state.update { it.copy(checking = false, biometricOn = biometricOn, turnedOff = turnedOff ?: it.turnedOff).withResult(result).after() }
            requestPromptIfDue()
        }
    }

    // A fresh screen for [name]. The request counters carry over: a pick requested before a lock
    // opens after it.
    private fun freshState(name: String?, checking: Boolean) = state.value.let {
        val target = sessionTarget
        val vault = files.current()?.location?.takeIf { target == null }
        val keyFileName = if (target != null) {
            target.keyFileName
        } else {
            vault?.let { location -> keyFiles?.current(location) }?.displayName
        }
        LockUiState(
            vaultName = name, checking = checking, promptRequest = it.promptRequest, pickRequest = it.pickRequest,
            keyFileName = keyFileName, openedFromApp = target != null,
            openedInPlaceOf = files.current()?.displayName?.takeIf { target != null },
            keyFileUnlockedBefore = vault?.let { location -> keyFiles?.keyFileUnlock(location) } == true,
        )
    }

    // Records whether an unlock of the remembered vault at [location] used a key file. Callers
    // skip backups and session-only files, so those record nothing.
    private fun recordKeyFileUse(location: String, origin: UnlockOrigin) {
        keyFiles?.saveKeyFileUnlock(location, origin in KEY_FILE_ORIGINS)
    }

    /**
     * Takes a file another app handed over with Open with; [writableGrant] is true when the
     * intent offers a persistable write grant. While a vault is unlocked (or the lock screen only
     * covers a save) it stays pending until the next lock, so nothing changes under the open
     * vault; while an unlock runs it stays pending until that attempt ends and shows when the
     * attempt doesn't open the vault.
     * The remembered vault itself shows the lock screen. A file whose read and write grant can be
     * kept ([VaultFiles.takeOffered]) is shown with Open this file and Cancel
     * ([LockUiState.offered]), whether or not a vault is remembered; it never becomes the vault
     * without that tap. Any other file opens read-only for this session
     * ([LockUiState.openedFromApp]). Every path that drops an offered file releases its grant.
     */
    fun onIncoming(uri: Uri, writableGrant: Boolean) {
        val incoming = Incoming(uri, writableGrant)
        if (sessions.current.value != null || state.value.unlocking) {
            pendingIncoming = incoming
            return
        }
        handleIncoming(incoming)
    }

    private fun handleIncoming(incoming: Incoming) {
        dropIncoming()
        val location = incoming.uri.toString()
        if (files.current()?.location == location) {
            refresh()
            return
        }
        val generation = ++checkGeneration
        state.value = freshState(state.value.vaultName, checking = true)
        viewModelScope.launch {
            val writable = incoming.writableGrant && files.takeOffered(incoming.uri)
            val name = files.displayName(incoming.uri)
            if (generation != checkGeneration) {
                // Overtaken by a refresh, a pick or another file: the grant isn't offered.
                if (writable) files.releaseOffered(incoming.uri)
                return@launch
            }
            if (writable) {
                offered = incoming.uri
                state.value = freshState(name, checking = false).copy(offered = true, offeredInPlaceOf = files.current()?.displayName)
            } else {
                sessionTarget = SessionTarget(location, name, ++handovers)
                refresh()
            }
        }
    }

    /** Makes the offered file the vault, as a pick does (Open this file). */
    fun openOffered() {
        val uri = offered ?: return
        offered = null
        onPicked(uri)
    }

    /**
     * Goes back to the remembered vault from an offered file (releasing the grant taken for it) or
     * from a session-only file (Cancel).
     */
    fun cancelIncoming() {
        dropIncoming()
        refresh()
    }

    /** Returns where the file picker opens: a session-only file's folder, else [requestPick]'s. */
    fun pickStart(): Uri? = sessionTarget?.location?.toUri() ?: pickFrom

    /** Call when the lock screen appears (the activity started while locked). */
    fun onAppear() {
        if (stopped) autoPrompt = true
        stopped = false
        requestPromptIfDue()
    }

    /** Call when the activity stops; [changingConfigurations] is true for a rotation. */
    fun onDisappear(changingConfigurations: Boolean) {
        stopped = !changingConfigurations
    }

    /**
     * Makes the lock screen open the file picker once it shows (Choose another file), in the
     * folder of [from] when set.
     */
    fun requestPick(from: Uri? = null) {
        pickFrom = from
        pickPending = true
        state.update { it.copy(pickRequest = it.pickRequest + 1) }
    }

    /** Returns true once for each [requestPick]; the screen then launches the picker. */
    fun takePickRequest(): Boolean {
        val request = state.value.pickRequest
        if (request <= pickServed || sessions.current.value != null) return false
        pickServed = request
        return true
    }

    /** Call right before launching the file picker; no prompt shows until its result arrives. */
    fun startPick() {
        pickPending = true
    }

    /** Call right before launching the key-file picker; no prompt shows until its result. */
    fun startKeyFilePick() {
        pickPending = true
    }

    /**
     * Applies the key-file picker's result; null means the user cancelled. Ignored while
     * unlocking. A KeePass vault or a refused grant leaves the key file as it was and says why.
     */
    fun onKeyFilePicked(uri: Uri?) {
        pickPending = false
        val access = keyFiles ?: return
        if (uri == null || state.value.unlocking || sessions.current.value != null) return
        val target = sessionTarget
        if (target != null) {
            useSessionKeyFile(target, uri)
            return
        }
        val vault = files.current() ?: return
        viewModelScope.launch {
            val choice = access.choose(vault.location, uri)
            if (files.current()?.location != vault.location) return@launch
            state.update {
                when (choice) {
                    // A key file biometric unlock needed brings the fingerprint button back.
                    KeyFileChoice.Chosen -> it.copy(
                        keyFileName = access.current(vault.location)?.displayName,
                        message = it.message.takeUnless(::clearedByKeyFile),
                        keyFileNeeded = false,
                        passwordChosen = it.passwordChosen && !it.keyFileNeeded,
                    )
                    KeyFileChoice.Failed -> it.copy(message = LockMessage.ChooseFailed)
                    KeyFileChoice.KeePassVault -> it.copy(message = LockMessage.NotKeyFile)
                }
            }
        }
    }

    // A session-only file's key file is kept in memory, with the picker's grant for this session.
    private fun useSessionKeyFile(target: SessionTarget, uri: Uri) {
        if (uri.toString() == target.location) {
            state.update { it.copy(message = LockMessage.NotKeyFile) }
            return
        }
        val change = ++sessionKeyFileChanges
        viewModelScope.launch {
            val name = files.displayName(uri)
            val current = sessionTarget
            if (change != sessionKeyFileChanges || current == null) return@launch
            if (current.handover != target.handover || current.location != target.location) return@launch
            sessionTarget = current.copy(keyFile = uri, keyFileName = name)
            state.update { it.copy(keyFileName = name, message = it.message.takeUnless(::clearedByKeyFile)) }
        }
    }

    /** Forgets the vault's key file; the next unlock uses the password alone. */
    fun removeKeyFile() {
        if (state.value.unlocking) return
        val target = sessionTarget
        if (target != null) {
            sessionKeyFileChanges++
            sessionTarget = target.copy(keyFile = null, keyFileName = null)
            state.update { it.copy(keyFileName = null, message = it.message.takeUnless(::clearedByKeyFile)) }
            return
        }
        val access = keyFiles ?: return
        val vault = files.current() ?: return
        // The chip goes at once, and an unlock reads the key file only while it shows.
        state.update { it.copy(keyFileName = null, message = it.message.takeUnless(::clearedByKeyFile)) }
        viewModelScope.launch { access.remove(vault.location) }
    }

    // Messages about the password or the key file, which a change of key file answers.
    private fun clearedByKeyFile(message: LockMessage?) =
        message == LockMessage.WrongPassword || message == LockMessage.ChooseFailed || message?.isKeyFileProblem == true

    // Reads the key file for one unlock while its chip shows; None otherwise. [sessionKey] is a
    // session-only file's key file.
    private suspend fun readKeyFile(location: String, shown: Boolean, sessionKey: Uri? = null): KeyFileRead = when {
        !shown -> KeyFileRead.None
        sessionKey != null -> keyFiles?.readOnce(sessionKey) ?: KeyFileRead.None
        else -> keyFiles?.read(location) ?: KeyFileRead.None
    }

    // The access a password or biometric unlock of the remembered vault requests.
    private fun accessOf(vault: RememberedVault) = if (vault.readOnly) FileAccess.PROVIDER_READ_ONLY else FileAccess.READ_WRITE

    /** Shows the password field instead of the biometric for this appearance. */
    fun usePassword() {
        autoPrompt = false
        state.update { it.copy(passwordChosen = true) }
    }

    private fun requestPromptIfDue() {
        val s = state.value
        if (!autoPrompt || pickPending || !s.biometricOn || s.passwordChosen || s.unlocking || s.backupTarget != null) return
        if (sessionTarget != null || offered != null) return
        if (sessions.current.value != null) return
        state.update { it.copy(promptRequest = it.promptRequest + 1) }
    }

    /** Shows the prompt for the newest request once; the screen calls it when the count changes. */
    fun servePromptRequest(confirm: suspend (CryptoHandle) -> Confirmation) {
        val request = state.value.promptRequest
        if (request <= promptServed) return
        promptServed = request
        unlockWithBiometric(confirm)
    }

    /**
     * Unlocks with the stored key after [confirm] shows the system prompt. Runs in the view
     * model's scope, so a rotation doesn't cancel it; a lock cancels it ([cancelUnlock]), and an
     * attempt overtaken by a change of file, or by a lock before the cancel arrives, is discarded,
     * as for a password. An Open with that arrived meanwhile shows after an attempt that didn't
     * open the vault, as for a password.
     */
    fun unlockWithBiometric(confirm: suspend (CryptoHandle) -> Confirmation) {
        val unlock = biometric ?: return
        val vault = files.current() ?: return
        if (state.value.unlocking || sessions.current.value != null || !state.value.biometricOn) return
        if (sessionTarget != null || offered != null) return
        val locksBefore = sessions.lockCount
        attemptLocks = locksBefore
        val keyFileShown = state.value.keyFileName != null
        // Unlocking blocks a password attempt, a pick and another prompt while this one runs.
        state.update { it.copy(biometricFailed = false, unlocking = true) }
        // Undispatched, as viewModelScope's Main.immediate starts it from a tap, so a lock's cancel
        // always finds the attempt started and its cleanup runs.
        unlockJob = viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                finishBiometric(vault, locksBefore, unlock.unlock(vault.location, { readKeyFile(vault.location, keyFileShown) }, accessOf(vault), confirm))
            } finally {
                state.update { it.copy(unlocking = false) }
                showPendingIncoming()
            }
        }
    }

    // The running password, backup or fingerprint unlock, for [cancelUnlock].
    private var unlockJob: Job? = null

    // The lock count when the running attempt started; only a later lock cancels it.
    private var attemptLocks = Long.MAX_VALUE

    /**
     * Cancels the running unlock (Back on the lock screen, or a lock): the key derivation stops, no
     * vault is opened, and the screen shows as before the attempt ([VaultOpening.open] says what a
     * late cancel leaves stored). Does nothing when no attempt runs.
     */
    fun cancelUnlock() {
        if (!state.value.unlocking) return
        unlockJob?.cancel()
    }

    // Applies a biometric attempt's [result]; one overtaken by a lock or a change of file is
    // discarded.
    private fun finishBiometric(vault: RememberedVault, locksBefore: Long, result: BiometricResult) {
        state.update { it.copy(unlocking = false) }
        when (result) {
            is BiometricResult.Opened -> {
                val opened = result.opened
                if (sessions.lockCount != locksBefore || files.current()?.location != vault.location) {
                    opened.session.release()
                    return
                }
                recordKeyFileUse(vault.location, opened.session.opened.origin)
                sessions.set(
                    Unlocked(
                        vault.location, opened.session, opened.kdf, opened.showWeakWarning,
                        olderThan = opened.olderThan, fileNewest = opened.fileNewest, bytesAfterEnd = opened.bytesAfterEnd,
                    ),
                )
            }
            BiometricResult.Cancelled -> autoPrompt = false
            BiometricResult.UsePassword -> usePassword()
            BiometricResult.Interrupted, BiometricResult.Busy -> Unit
            BiometricResult.Failed -> state.update { it.copy(biometricFailed = true) }
            BiometricResult.NotStored -> state.update { it.copy(biometricOn = false) }
            is BiometricResult.TurnedOff -> state.update { it.copy(biometricOn = false, turnedOff = result.reason, showPasswordField = true) }
            // A slow, unreadable or damaged file reads as it does for a password.
            is BiometricResult.NotOpened -> state.update { it.copy(passwordChosen = true).withResult(result.result) }
            is BiometricResult.KeyFileUnreadable -> state.update { it.copy(passwordChosen = true).withKeyFileProblem(result.read) }
            // The password field shows with Add key file.
            BiometricResult.KeyFileNeeded -> state.update { it.copy(passwordChosen = true, showPasswordField = true, keyFileNeeded = true) }
            BiometricResult.KeyFileMismatch -> state.update {
                it.copy(passwordChosen = true, showPasswordField = true, message = LockMessage.KeyFileMismatch)
            }
        }
    }

    /**
     * Makes [uri] the remembered vault, as a pick does: at once while locked, otherwise after the
     * vault locks. Save as new file uses it after the copy is verified.
     */
    fun useFile(uri: Uri) {
        if (sessions.current.value == null) onPicked(uri) else pendingFile = uri
    }

    /** Applies the picker's result; null means the user cancelled. Ignored while unlocking. */
    fun onPicked(uri: Uri?) {
        pickPending = false
        pickFrom = null
        if (uri == null || state.value.unlocking || sessions.current.value != null) return
        dropIncoming(keep = uri)
        // The spinner shows while [VaultFiles.choose] takes the grant; the old file's password
        // field and fingerprint button are hidden, no prompt is requested, and a running check
        // of it drops its result.
        checkGeneration++
        state.value = freshState(state.value.vaultName, checking = true)
        viewModelScope.launch {
            when (files.choose(uri)) {
                ChooseResult.Chosen -> refresh()
                // A refused grant leaves the old file remembered: check it again and say why.
                ChooseResult.Failed -> refresh { copy(message = LockMessage.ChooseFailed) }
            }
        }
    }

    /**
     * Makes the password field open [backup] read-only instead of the file; [lastCopy] opens it as
     * the last copy of a file that can't be opened.
     */
    fun openBackup(backup: BackupInfo, lastCopy: LastCopyReason? = null) {
        if (state.value.unlocking || sessions.current.value != null) return
        state.update { it.asBackupTarget(backup, lastCopy, slow = null) }
    }

    /**
     * Makes the lock screen open [backup] with its own password after the next lock, whether
     * or not the file checks out; [slow] shows that copy's warning at once, so the first Unlock
     * accepts those settings. Call it right before locking.
     */
    fun requestBackup(backup: BackupInfo, slow: SlowKdf? = null) {
        pendingBackup = PendingBackup(backup, slow)
    }

    // The password field opens [backup] instead of the file; [lastCopy] when it is the last copy.
    private fun LockUiState.asBackupTarget(backup: BackupInfo, lastCopy: LastCopyReason?, slow: SlowKdf?) =
        copy(backupTarget = backup, targetLastCopy = lastCopy, showPasswordField = true, message = null, slow = slow)

    /** Makes the password field open the last good copy offered for the file. */
    fun openLastCopy() {
        state.value.lastCopy?.let { openBackup(it.backup, it.reason) }
    }

    /** Goes back from opening a backup to the file. */
    fun cancelBackup() = refresh()

    /**
     * Unlocks the session target, else the remembered vault, with [password], and the key file
     * while its chip shows; the password is zero-filled on every path. Ignored while an attempt
     * runs; [cancelUnlock] stops it, and a lock (screen off) calls it. An attempt overtaken by a
     * change of file, or by a lock before the cancel arrives, is discarded. A key file that can't
     * be read stops the attempt with its message. An Open with that arrived during an attempt that
     * didn't open the vault shows after it ([onIncoming]).
     */
    fun unlock(password: CharArray) {
        val target = sessionTarget
        // The session target, else the remembered vault; null before the first pick.
        val opening = if (target != null) target.location to FileAccess.SESSION_ONLY else files.current()?.let { it.location to accessOf(it) }
        // A set session means the lock screen only covers a save that is ending.
        if (opening == null || state.value.unlocking || !state.value.showPasswordField || sessions.current.value != null) {
            password.fill('\u0000')
            return
        }
        val (location, access) = opening
        val sessionKey = target?.keyFile
        val locksBefore = sessions.lockCount
        attemptLocks = locksBefore
        val backup = state.value.backupTarget
        val lastCopy = state.value.targetLastCopy
        // The warning is on screen when Unlock is tapped, so the tap accepts those settings.
        val accepted = state.value.slow?.kdf
        val keyFileShown = state.value.keyFileName != null
        state.update { it.copy(unlocking = true, message = null) }
        // Undispatched, as viewModelScope's Main.immediate starts it from a tap, so a lock's cancel
        // always finds the attempt started: its catch and the opener zero-fill the password.
        unlockJob = viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                val read = try {
                    readKeyFile(location, keyFileShown, sessionKey)
                } catch (e: CancellationException) {
                    password.fill('\u0000')
                    throw e
                }
                val keyFile = when (read) {
                    KeyFileRead.None -> null
                    is KeyFileRead.Bytes -> read.bytes
                    is KeyFileRead.Failed, KeyFileRead.KeePassVault -> {
                        password.fill('\u0000')
                        state.update { it.copy(unlocking = false).withKeyFileProblem(read) }
                        return@launch
                    }
                }
                val result = if (backup == null) {
                    opener.open(location, password, accepted, keyFile, access)
                } else {
                    opener.openBackup(location, backup, password, lastCopy, accepted, keyFile, access)
                }
                val current = sessionTarget?.location ?: files.current()?.location
                val stale = sessions.lockCount != locksBefore || current != location || sessionTarget?.location != target?.location
                if (result is OpenResult.Unlocked && stale) {
                    result.session.release()
                    state.update { it.copy(unlocking = false) }
                    return@launch
                }
                if (result is OpenResult.Unlocked) {
                    if (target == null && backup == null) recordKeyFileUse(location, result.session.opened.origin)
                    sessions.set(
                        Unlocked(
                            location, result.session, result.kdf, result.showWeakWarning, result.backup,
                            olderThan = result.olderThan, fileNewest = result.fileNewest,
                            sessionName = target?.name, bytesAfterEnd = result.bytesAfterEnd,
                        ),
                    )
                }
                state.update { it.copy(unlocking = false).withResult(result) }
            } finally {
                state.update { it.copy(unlocking = false) }
                showPendingIncoming()
            }
        }
    }

    private fun LockUiState.withResult(result: OpenResult): LockUiState = when (result) {
        is OpenResult.Ready -> copy(showPasswordField = true, message = null, slow = result.slow, lostCutOffSave = result.lostCutOffSave)
        is OpenResult.Unlocked -> copy(showPasswordField = true, message = null, slow = null)
        is OpenResult.TooSlow -> copy(showPasswordField = true, message = null, slow = result.slow)
        OpenResult.WrongPassword -> copy(showPasswordField = true, message = LockMessage.WrongPassword)
        // The backup stays the target, so the user can cancel back to the file.
        is OpenResult.Damaged -> if (backupTarget != null) {
            copy(message = LockMessage.BackupDamaged)
        } else {
            val (message, reason) = if (result.reason.afterHeaderHmac) {
                LockMessage.DamagedAfterHeader to LastCopyReason.CORRUPTED_AFTER_HEADER
            } else {
                LockMessage.Damaged to LastCopyReason.CORRUPTED
            }
            copy(showPasswordField = false, message = message).withLastCopy(result.lastCopy, reason)
        }
        OpenResult.BackupDamaged -> copy(message = LockMessage.BackupDamaged)
        is OpenResult.NotEnoughMemory -> copy(showPasswordField = false, message = LockMessage.NotEnoughMemory).let {
            if (backupTarget == null) it.withLastCopy(result.lastCopy, LastCopyReason.UNAVAILABLE) else it
        }
        is OpenResult.Failed -> copy(showPasswordField = false, message = LockMessage.Failed(result.cause))
        OpenResult.KeyFileDamaged -> copy(showPasswordField = true, message = LockMessage.KeyFileDamaged)
        OpenResult.KeyFileTooLarge -> copy(showPasswordField = true, message = LockMessage.KeyFileTooLarge)
        is OpenResult.Refused -> copy(showPasswordField = false, message = LockMessage.Refused(result.rejection))
        is OpenResult.Unsupported -> copy(showPasswordField = false, message = LockMessage.Unsupported(result.reason))
        // A backup that can't be read is reported like a corrupted one, next to Cancel.
        is OpenResult.Unreadable -> if (backupTarget != null) {
            copy(message = LockMessage.BackupDamaged)
        } else {
            copy(showPasswordField = false, message = LockMessage.Unreadable(result.cause)).withLastCopy(result.lastCopy, LastCopyReason.UNAVAILABLE)
        }
    }

    // The key file can't be used; the password field stays for another try.
    private fun LockUiState.withKeyFileProblem(read: KeyFileRead): LockUiState = copy(
        showPasswordField = true,
        message = if (read is KeyFileRead.Failed) LockMessage.KeyFileUnreadable(read.cause) else LockMessage.NotKeyFile,
    )

    private fun LockUiState.withLastCopy(backup: BackupInfo?, reason: LastCopyReason): LockUiState =
        copy(lastCopy = backup?.let { LastCopy(it, reason) })

    private companion object {
        val KEY_FILE_ORIGINS = setOf(UnlockOrigin.PASSWORD_AND_KEY_FILE, UnlockOrigin.KEY_FILE_ONLY, UnlockOrigin.STORED_KEY_AND_KEY_FILE)
    }
}
