package org.onekash.kashpass.ui.browse

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.onekash.kashpass.vault.index.FieldValue
import kotlinx.coroutines.Job
import java.time.Clock
import java.time.Instant
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.PendingDeletes
import kotlin.time.Duration
import org.onekash.kashpass.vault.storage.CryptoHandle
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.session.EnableResult
import org.onekash.kashpass.session.BiometricUnlock
import org.onekash.kashpass.vault.edit.DeleteKind
import org.onekash.kashpass.vault.edit.EntryDelete
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.EntryDetails
import org.onekash.kashpass.vault.index.EntryField
import org.onekash.kashpass.vault.index.EntryRow
import org.onekash.kashpass.vault.index.FieldKind
import org.onekash.kashpass.vault.index.SearchMatch
import org.onekash.kashpass.vault.index.SearchText
import org.onekash.kashpass.vault.open.VaultOpening

/** What the browser shows for the unlocked vault. */
data class BrowseUiState(
    val chips: List<Chip>,
    val selectedChip: Chip,
    val query: String,
    /** True when [query] has text, so [rows] are search results and the chips don't apply. */
    val searching: Boolean,
    /** True for the full A to Z list (All, no query), which gets letter headers. */
    val letterHeaders: Boolean,
    /** True when rows can come from more than one group (All, search), so each names its group. */
    val groupInRows: Boolean,
    val rows: List<EntryRow>,
    /** True until the screen has given the search field focus once in this unlocked session. */
    val searchFocusPending: Boolean = false,
    /** Why each shown row matched, by row id; empty unless [searching]. */
    val matches: Map<String, SearchMatch> = emptyMap(),
    /** True when no entry exists outside the recycle bin. */
    val vaultEmpty: Boolean,
    /** The settings to warn about, or null when there is no banner. */
    val weakKdf: KdfSettings?,
    /** The entry in the details sheet, or null when the sheet is closed. */
    val openEntry: EntryDetails?,
    /**
     * The open entry's fields as the sheet shows and copies them, by field name, with `{REF:}`
     * references resolved; null while they are being resolved or when no entry is open.
     */
    val shownFields: Map<String, ShownField>? = null,
    /** The field whose copy waits for the inline confirm, or null. */
    val copyConfirm: String? = null,
    /** Names of the open entry's protected fields that are shown in clear. */
    val revealed: Set<String>,
    /** True when the vault can be saved, so edit, add and delete controls show. */
    val canEdit: Boolean = false,
    /**
     * Why the vault is read-only, for the banner that can't be dismissed; null when it can be
     * saved.
     */
    val readOnly: ReadOnlyBanner? = null,
    /** The newest change seen in an earlier version, while this file is older; else null. */
    val olderThan: Instant? = null,
    /**
     * True while a saveable vault's bytes have data after their end block
     * ([org.onekash.kashpass.session.Unlocked.bytesAfterEnd]) and the user has not dismissed the
     * row about it.
     */
    val bytesAfterEnd: Boolean = false,
    /** True when the one-time offer of biometric unlock shows. */
    val biometricOffer: Boolean = false,
    /** Number of deletes Undo restores; the Undo snackbar shows while it is above 0. */
    val pendingDeletes: Int = 0,
    /** The time the state was built, for marking expired entries. */
    val now: Instant = Instant.EPOCH,
    /** True while the app reads, reopens or writes the file ([SaveCoordinator.working]). */
    val working: Boolean = false,
    /** True while Turn on from the offer card runs. */
    val enabling: Boolean = false,
) {
    /**
     * True when a warning banner shows above the list (read-only, older file, weak KDF, bytes after
     * the end); BrowseScreen draws one row for each. The biometric offer is not a warning.
     */
    val warningShown: Boolean
        get() = readOnly != null || olderThan != null || weakKdf != null || bytesAfterEnd
}

/**
 * A field of the open entry as shown: [value] with its references resolved, masked when the field
 * is ([EntryField.isProtected]) or when it inserts a password ([insertsPassword], which makes a
 * copy show a confirm first), and [keepsPlaceholders] when it holds a placeholder after resolution,
 * which KashPass shows as written.
 */
data class ShownField(val value: FieldValue, val insertsPassword: Boolean, val keepsPlaceholders: Boolean)

/** What a copy tap did: copied, failed, or waiting for the inline confirm. */
enum class CopyOutcome { COPIED, FAILED, CONFIRM }

/** The read-only banner: [reason], and the backup shown when one is open instead of the file. */
data class ReadOnlyBanner(
    val reason: ReadOnlyReason,
    val backup: BackupInfo?,
)

/**
 * Drives the vault browser from [SessionHolder.current]. State lives only in memory (never in
 * saved instance state) and belongs to one session: [uiState] is null while locked, and a new
 * unlock starts again from All with no query, no open entry and nothing revealed.
 */
class BrowseViewModel(
    private val sessions: SessionHolder,
    private val opener: VaultOpening,
    private val saves: SaveCoordinator? = null,
    private val clock: Clock = Clock.systemUTC(),
    /** Runs whole-document work (copy, delete, undo) off the main thread. */
    private val compute: CoroutineDispatcher = Dispatchers.Default,
    private val biometric: BiometricUnlock? = null,
    private val copyToClipboard: (text: String) -> Boolean,
) : ViewModel() {

    // The unlock the offer card belongs to (by lock count and file), set once when it opens.
    private data class Offer(val location: String, val lockCount: Long)

    private val offer = MutableStateFlow<Offer?>(null)
    private val enabling = MutableStateFlow(false)
    private val biometricOn = MutableSharedFlow<String>(extraBufferCapacity = 2)

    /** The file name, once biometric unlock was turned on from the offer card. */
    val biometricTurnedOn: SharedFlow<String> = biometricOn.asSharedFlow()

    private val biometricFailure = MutableSharedFlow<Unit>(extraBufferCapacity = 2)

    /** Emits when the prompt passed but the phone couldn't store the key; the card stays. */
    val biometricFailed: SharedFlow<Unit> = biometricFailure.asSharedFlow()

    private val deleteEvents = MutableSharedFlow<DeleteEvent>(extraBufferCapacity = 4)

    /** Results of deletes, to show once. */
    val deletes: SharedFlow<DeleteEvent> = deleteEvents.asSharedFlow()

    private val noDeletes = MutableStateFlow(PendingDeletes(emptyList(), emptySet()))
    private val idle = MutableStateFlow(false)

    private data class Local(
        val owner: Unlocked?,
        val query: String = "",
        val chip: Chip = Chip.All,
        val entryId: String? = null,
        val revealed: Set<String> = emptySet(),
        // The open entry's resolved fields, by field name, for [entryId] once resolved.
        val shown: Pair<String, Map<String, ShownField>>? = null,
        val copyConfirm: String? = null,
        val bannerDismissed: Boolean = false,
        // Bumped to rebuild the state after Unlocked.searchFocusGiven, olderThan or
        // bytesAfterEndDismissed changes.
        val focusRevision: Int = 0,
    )

    private val local = MutableStateFlow(Local(owner = null))

    // Eagerly, not WhileSubscribed: the browser leaves composition on lock, and its state must
    // turn null at once instead of keeping the last rows.
    val uiState: StateFlow<BrowseUiState?> = combine(
        sessions.current,
        local,
        // Paired, since combine's typed overloads take five flows at most; canEdit reads busy only.
        combine(saves?.busy ?: idle, saves?.working ?: idle, ::Pair),
        combine(offer, enabling, ::Pair),
        saves?.pendingDeletes ?: noDeletes,
    ) { u, l, (saving, working), (o, enablingNow), pending ->
        build(u, l, saving, pending)?.copy(
            biometricOffer = o != null && u != null && o.location == u.location && o.lockCount == sessions.lockCount && u.backup == null,
            working = working,
            enabling = enablingNow,
        )
    }.stateIn(
        viewModelScope,
        SharingStarted.Eagerly,
        build(sessions.current.value, local.value, saves?.busy?.value == true, saves?.pendingDeletes?.value ?: noDeletes.value)
            ?.copy(working = saves?.working?.value == true),
    )

    init {
        // The offer is set when a file session opens and stays for that unlock, so the card
        // doesn't vanish when it is first shown or when a save swaps the session.
        viewModelScope.launch {
            sessions.current.collect { u ->
                val o = offer.value
                if (u == null) {
                    offer.value = null
                } else if (o == null || o.lockCount != sessions.lockCount || o.location != u.location) {
                    offer.value = if (biometric?.offerVisible(u) == true) Offer(u.location, sessions.lockCount) else null
                }
            }
        }
        // Drop the query, open entry, revealed names and resolved fields as soon as the vault
        // locks.
        viewModelScope.launch {
            sessions.current.filter { it == null }.collect {
                resolving?.cancel()
                local.value = Local(owner = null)
            }
        }
    }

    fun setQuery(query: String) = change { copy(query = query) }

    fun selectChip(chip: Chip) = change { copy(chip = chip) }

    private var resolving: Job? = null

    /**
     * Opens [id] in the sheet and resolves its fields on [compute] once per opening; reveal and
     * state rebuilds reuse the result.
     */
    fun openEntry(id: String) {
        val unlocked = sessions.current.value ?: return
        change { copy(entryId = id, revealed = emptySet(), shown = null, copyConfirm = null) }
        resolving?.cancel()
        if (!unlocked.session.isOpen) return
        val details = unlocked.session.index.details(id) ?: return
        val refs = unlocked.session.refs
        val customNames = details.fields.filter { it.kind == FieldKind.CUSTOM }.map { it.name }
        resolving = viewModelScope.launch {
            val fields = withContext(compute) {
                details.fields.associate { field ->
                    val resolved = refs.resolve(field.value, customNames)
                    field.name to ShownField(resolved.value, resolved.insertsPassword, resolved.keepsPlaceholders)
                }
            }
            if (sessions.current.value !== unlocked) return@launch
            change { if (entryId == id && shown == null) copy(shown = id to fields) else this }
        }
    }

    fun closeEntry() {
        resolving?.cancel()
        change { copy(entryId = null, revealed = emptySet(), shown = null, copyConfirm = null) }
    }

    /**
     * Opens the only result of the current search, read from the index at call time (the query
     * as typed); does nothing with no query or with zero or more than one result.
     */
    fun openSingleResult() {
        val unlocked = sessions.current.value ?: return
        if (!unlocked.session.isOpen) return
        val l = local.value.forSession(unlocked)
        if (l.query.isBlank()) return
        val only = unlocked.session.index.rows(l.chip, l.query).singleOrNull() ?: return
        openEntry(only.id)
    }

    /** Records that the search field got its focus for this unlocked session. */
    fun consumeSearchFocus() {
        val unlocked = sessions.current.value ?: return
        unlocked.searchFocusGiven = true
        change { copy(focusRevision = focusRevision + 1) }
    }

    // Match reasons depend only on the session, chip and query; other changes (reveal, open,
    // close) reuse them instead of re-snippeting every result.
    private var matchesKey: Triple<Unlocked, Chip, String>? = null
    private var matchesValue: Map<String, SearchMatch> = emptyMap()

    private fun matchesFor(unlocked: Unlocked, chip: Chip, query: String, rows: List<EntryRow>): Map<String, SearchMatch> {
        val key = Triple(unlocked, chip, query)
        if (key != matchesKey) {
            val index = unlocked.session.index
            matchesValue = rows.mapNotNull { row -> index.matchFor(row.id, query)?.let { row.id to it } }.toMap()
            matchesKey = key
        }
        return matchesValue
    }

    fun toggleReveal(fieldName: String) = change {
        copy(revealed = if (fieldName in revealed) revealed - fieldName else revealed + fieldName)
    }

    // The open entry's shown [field], once resolved.
    private fun shownField(field: EntryField): ShownField? {
        val unlocked = sessions.current.value ?: return null
        val l = local.value.forSession(unlocked)
        val (id, fields) = l.shown ?: return null
        return fields[field.name].takeIf { id == l.entryId }
    }

    /**
     * Copies [field]'s shown value (marked sensitive, cleared later). A value that inserts another
     * entry's password waits for [confirmCopy] instead; nothing is copied before the entry is
     * resolved.
     */
    fun copy(field: EntryField): CopyOutcome {
        val shown = shownField(field) ?: return CopyOutcome.FAILED
        if (shown.insertsPassword) {
            change { copy(copyConfirm = field.name) }
            return CopyOutcome.CONFIRM
        }
        return if (copyToClipboard(shown.value.reveal())) CopyOutcome.COPIED else CopyOutcome.FAILED
    }

    /** Copies [field] after its inline confirm; returns false if nothing was copied. */
    fun confirmCopy(field: EntryField): Boolean {
        val unlocked = sessions.current.value ?: return false
        if (local.value.forSession(unlocked).copyConfirm != field.name) return false
        val shown = shownField(field) ?: return false
        change { copy(copyConfirm = null) }
        return copyToClipboard(shown.value.reveal())
    }

    /** Closes the inline confirm without copying. */
    fun cancelCopy() = change { copy(copyConfirm = null) }

    /**
     * Hides the weak-settings banner at once and, through the opener, for later unlocks; for a
     * session-only file only for this session, since nothing is stored for it.
     */
    fun dismissWeakWarning() {
        val unlocked = sessions.current.value ?: return
        change { copy(bannerDismissed = true) }
        if (unlocked.sessionOnly) return
        viewModelScope.launch { opener.dismissWeakWarning(unlocked.location, unlocked.kdf) }
    }

    /** Returns how [id] is deleted: to the recycle bin (undoable) or for good (confirm first). */
    fun deleteKind(id: String): DeleteKind? {
        val unlocked = sessions.current.value ?: return null
        return EntryDelete.kindOf(unlocked.session.opened.document, id)
    }

    /**
     * Moves [id] to the recycle bin after an undo [window], writing nothing until then
     * ([SaveCoordinator.stageDelete]); its row hides at once. Ignored for a permanent delete,
     * which goes through [deletePermanently] after the row's confirm.
     */
    fun delete(id: String, window: Duration) {
        val coordinator = saves ?: return
        if (local.value.entryId == id) closeEntry()
        coordinator.stageDelete(id, window)
    }

    /** Restores every staged delete; nothing is written. */
    fun undoDeletes() {
        saves?.undoStaged()
    }

    /** Deletes [id] permanently and saves at once; staged deletes go into the same save. */
    fun deletePermanently(id: String) {
        val coordinator = saves ?: return
        if (local.value.entryId == id) closeEntry()
        viewModelScope.launch {
            // Built after a running commit ends, from the session it leaves, so the two saves can't
            // conflict; staged deletes go into this save.
            coordinator.awaitCommit()
            val unlocked = sessions.current.value ?: return@launch
            val deleted = withContext(compute) { EntryDelete.delete(unlocked.session.opened.document, id, clock.instant()) } ?: return@launch
            val result = coordinator.save(deleted.document, basedOn = unlocked).await() ?: return@launch
            deleteEvents.emit(if (result is SaveResult.Saved) DeleteEvent.Deleted else DeleteEvent.NotSaved)
        }
    }

    /** Closes the open entry and searches for [tag] ([SearchText.tagQuery]). */
    fun searchTag(tag: String) {
        resolving?.cancel()
        change { copy(entryId = null, revealed = emptySet(), shown = null, copyConfirm = null, query = SearchText.tagQuery(tag)) }
    }

    /** Records that the offer card was shown, so it isn't offered again for this file. */
    fun offerShown() {
        offer.value?.let { biometric?.markOfferShown(it.location) }
    }

    /** Hides the offer card ("Not now"); [offerShown] already recorded it. */
    fun dismissOffer() {
        offer.value = null
    }

    /** Runs "Turn on" on the offer card: seals the key after [confirm]; Cancel leaves the card. */
    fun enableBiometric(confirm: suspend (CryptoHandle) -> Confirmation, fileName: String) {
        val unlock = biometric ?: return
        val unlocked = sessions.current.value ?: return
        // A second tap before the card disables its buttons is ignored.
        if (enabling.value) return
        enabling.value = true
        viewModelScope.launch {
            try {
                when (unlock.enable(unlocked, confirm)) {
                    EnableResult.Enabled -> {
                        offer.value = null
                        biometricOn.tryEmit(fileName)
                    }
                    EnableResult.Failed -> biometricFailure.tryEmit(Unit)
                    // A cancelled or interrupted prompt (NotEnabled) and Busy leave the card,
                    // with no message.
                    is EnableResult.NotEnabled, EnableResult.Busy -> Unit
                }
            } finally {
                enabling.value = false
            }
        }
    }

    /** Hides the row about data after the end of the file for the rest of this unlock. */
    fun dismissBytesAfterEnd() {
        val unlocked = sessions.current.value ?: return
        unlocked.bytesAfterEndDismissed = true
        change { copy(focusRevision = focusRevision + 1) }
    }

    /** Accepts a file older than a version seen before ("Use this version"). */
    fun acceptOlderFile() {
        val coordinator = saves ?: return
        viewModelScope.launch {
            coordinator.acceptOlderFile()
            change { copy(focusRevision = focusRevision + 1) }
        }
    }

    /** Leaves the open backup and opens the file again. */
    fun closeBackup() {
        val coordinator = saves ?: return
        viewModelScope.launch { coordinator.closeBackup() }
    }

    /** Returns the group a new entry goes into: the selected group chip's, else null (top). */
    fun addTarget(): String? {
        val unlocked = sessions.current.value ?: return null
        val l = local.value.forSession(unlocked)
        return (l.chip as? Chip.Group)?.id?.takeIf { l.query.isBlank() }
    }

    private fun change(block: Local.() -> Local) {
        val unlocked = sessions.current.value ?: return
        local.update { current -> current.forSession(unlocked).block() }
    }

    private fun Local.forSession(unlocked: Unlocked) = if (owner === unlocked) this else Local(owner = unlocked)

    private fun build(unlocked: Unlocked?, stored: Local, saving: Boolean, pending: PendingDeletes): BrowseUiState? {
        if (unlocked == null || !unlocked.session.isOpen) return null
        val l = stored.forSession(unlocked)
        val index = unlocked.session.index
        val hidden = pending.hidden
        val rows = index.rows(l.chip, l.query).filter { it.id !in hidden }
        val searching = l.query.isNotBlank()
        return BrowseUiState(
            chips = index.chips,
            selectedChip = l.chip,
            query = l.query,
            searching = searching,
            letterHeaders = !searching && l.chip == Chip.All,
            groupInRows = searching || l.chip == Chip.All,
            rows = rows,
            matches = if (searching) matchesFor(unlocked, l.chip, l.query, rows) else emptyMap(),
            vaultEmpty = index.isEmpty || hidden.isNotEmpty() && index.rows(Chip.All, "").all { it.id in hidden },
            weakKdf = unlocked.kdf.takeIf { unlocked.showWeakWarning && !l.bannerDismissed },
            openEntry = l.entryId?.takeIf { it !in hidden }?.let(index::details),
            shownFields = l.shown?.takeIf { it.first == l.entryId }?.second,
            copyConfirm = l.copyConfirm,
            revealed = l.revealed,
            searchFocusPending = !unlocked.searchFocusGiven,
            // While a save runs nothing else changes the vault: a change made then would be built
            // from a document the running save is about to replace.
            canEdit = unlocked.session.saveability == Saveability.Saveable && !saving,
            readOnly = (unlocked.session.saveability as? Saveability.ReadOnly)?.let { ReadOnlyBanner(it.reason, unlocked.backup) },
            olderThan = unlocked.olderThan.takeIf { unlocked.backup == null },
            bytesAfterEnd = unlocked.bytesAfterEnd && !unlocked.bytesAfterEndDismissed && unlocked.session.saveability == Saveability.Saveable,
            pendingDeletes = pending.count,
            now = clock.instant(),
        )
    }
}

/** A delete result to show once. */
enum class DeleteEvent { Deleted, NotSaved }
