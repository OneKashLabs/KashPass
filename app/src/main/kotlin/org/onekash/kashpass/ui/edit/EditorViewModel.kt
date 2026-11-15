package org.onekash.kashpass.ui.edit

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import java.time.Instant
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.onekash.kashpass.session.EditCheck
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.edit.GroupChoice
import org.onekash.kashpass.vault.generate.PasswordGenerator
import org.onekash.kashpass.vault.save.SaveResult

/** What the editor shows; null while no entry is being edited or added. */
data class EditorUiState(
    /** The entry being edited, or null when adding one. */
    val entryId: String?,
    val title: String,
    val userName: String,
    val url: String,
    val notes: String,
    /** The group a new entry goes into (null: the top level); unused when editing. */
    val groupId: String?,
    val groups: List<GroupChoice>,
    val length: Int = PasswordGenerator.DEFAULT_LENGTH,
    val symbols: Boolean = false,
    val saving: Boolean = false,
    /** Why the last save stopped, shown in the editor, or null. */
    val problem: SaveResult? = null,
    /** Standard fields stored protected; the editor shows them without keyboard learning. */
    val protectedKeys: Set<String> = emptySet(),
    /** True after a close with unsaved changes; the close button reads "Discard?" until tapped. */
    val discardConfirm: Boolean = false,
) {
    val adding: Boolean get() = entryId == null

    override fun toString() = "EditorUiState(adding=$adding, saving=$saving)"
}

/** What a close request does; see [resolveEditorDismiss]. */
enum class EditorDismiss { DISMISS, SHOW_CONFIRM, BLOCKED }

/**
 * Resolves a close request. A running save blocks it; with nothing changed it closes; with changes
 * the first request shows the confirmation and the second, once it shows, closes.
 */
fun resolveEditorDismiss(saving: Boolean, hasChanges: Boolean, confirmShowing: Boolean): EditorDismiss = when {
    saving -> EditorDismiss.BLOCKED
    !hasChanges -> EditorDismiss.DISMISS
    confirmShowing -> EditorDismiss.DISMISS
    else -> EditorDismiss.SHOW_CONFIRM
}

/** A short message for the screen behind the editor. */
enum class EditorNotice { UPDATED, ENTRY_GONE, CHECK_FAILED, TIMED_OUT, SLOW, SAVED }

/**
 * Edits and adds entries for the unlocked session. Lives in the activity's view model store, so a
 * configuration change keeps an edit in progress; nothing is saved to instance state, and a lock
 * ([SessionHolder.current] turning null) discards the edit and wipes the password field.
 * [EditorViewModelTest] pins each transition.
 */
class EditorViewModel(
    private val sessions: SessionHolder,
    private val coordinator: SaveCoordinator,
    private val now: () -> Instant = Instant::now,
    /** Runs whole-document work (copy, history, index) off the main thread. */
    private val compute: CoroutineDispatcher = Dispatchers.Default,
) : ViewModel() {

    private val mutable = MutableStateFlow<EditorUiState?>(null)
    private val notices = MutableSharedFlow<EditorNotice>(extraBufferCapacity = 4)

    val state: StateFlow<EditorUiState?> = mutable.asStateFlow()

    /** Messages for the browser behind the editor. */
    val messages: SharedFlow<EditorNotice> = notices.asSharedFlow()

    /** The password field. Never saved to instance state; cleared whenever the editor closes. */
    val password = TextFieldState()

    // The fields as the editor opened them, to tell whether a close loses anything. The password
    // copy is wiped on close, like the field.
    private var baseline: EditorUiState? = null
    private var baselinePassword = CharArray(0)

    init {
        viewModelScope.launch {
            sessions.current.filter { it == null }.collect {
                // A running check would use the key of a released session.
                checking?.cancel()
                retry = null
                close()
            }
        }
        // A retry from the choices sheet that succeeds finishes this edit too.
        viewModelScope.launch {
            coordinator.results.collect { event ->
                if (event.result is SaveResult.Saved && mutable.value?.problem != null) {
                    notices.tryEmit(EditorNotice.SAVED)
                    close()
                }
            }
        }
    }

    /**
     * Opens the editor on [entryId] after re-reading the file: when it changed, the session is
     * reloaded first and the editor shows the latest version, or reports the entry gone. A tap
     * while a check runs is ignored.
     */
    fun startEdit(entryId: String) {
        if (checking?.isActive == true) return
        checking = viewModelScope.launch {
            when (val check = coordinator.refreshForEdit(entryId)) {
                EditCheck.Locked -> return@launch
                EditCheck.EntryGone -> {
                    notices.tryEmit(EditorNotice.ENTRY_GONE)
                    return@launch
                }
                is EditCheck.Failed -> {
                    retry = { startEdit(entryId) }
                    notices.tryEmit(
                        when {
                            check.timedOut -> EditorNotice.TIMED_OUT
                            check.slow -> EditorNotice.SLOW
                            else -> EditorNotice.CHECK_FAILED
                        },
                    )
                    return@launch
                }
                EditCheck.Updated -> notices.tryEmit(EditorNotice.UPDATED)
                EditCheck.Ready -> Unit
            }
            val document = sessions.current.value?.session?.opened?.document ?: return@launch
            val draft = EntryEdits.draftOf(document, entryId)
            if (draft == null) {
                notices.tryEmit(EditorNotice.ENTRY_GONE)
                return@launch
            }
            password.setTextAndPlaceCursorAtEnd(draft.password.reveal())
            open(
                EditorUiState(
                    entryId, draft.title, draft.userName, draft.url, draft.notes, null, emptyList(),
                    protectedKeys = EntryEdits.protectedKeys(document, entryId),
                ),
            )
        }
    }

    // The re-read before Edit or New entry; a tap while it runs is ignored.
    private var checking: kotlinx.coroutines.Job? = null

    // The last failed check, for Try again.
    private var retry: (() -> Unit)? = null

    /** Runs the last failed check again: Try again on [EditorNotice.TIMED_OUT]. */
    fun retryCheck() {
        retry?.also { retry = null }?.invoke()
    }


    /**
     * Opens the editor on a new entry in [groupId] (the top level when null, or when the latest
     * version of the file doesn't have it), with the vault's default user name and a generated
     * password. The file is re-read first, as for an edit; a tap while that
     * check runs is ignored.
     */
    fun startAdd(groupId: String?) {
        if (checking?.isActive == true) return
        checking = viewModelScope.launch {
            when (val check = coordinator.refreshForAdd()) {
                EditCheck.Locked -> return@launch
                is EditCheck.Failed -> {
                    retry = { startAdd(groupId) }
                    notices.tryEmit(
                        when {
                            check.timedOut -> EditorNotice.TIMED_OUT
                            check.slow -> EditorNotice.SLOW
                            else -> EditorNotice.CHECK_FAILED
                        },
                    )
                    return@launch
                }
                EditCheck.Updated -> notices.tryEmit(EditorNotice.UPDATED)
                EditCheck.Ready, EditCheck.EntryGone -> Unit
            }
            val document = sessions.current.value?.session?.opened?.document ?: return@launch
            val groups = EntryEdits.groups(document)
            val target = groupId?.takeIf { id -> groups.any { it.id == id } }
            val draft = EntryEdits.newDraft(document, ProtectedText.of(""))
            mutable.value = EditorUiState(null, "", draft.userName, "", "", target, groups, protectedKeys = EntryEdits.protectedKeys(document, null))
            generate()
            open(mutable.value!!)
        }
    }

    private fun open(state: EditorUiState) {
        mutable.value = state
        baseline = state
        baselinePassword.fill('\u0000')
        baselinePassword = password.text.toString().toCharArray()
    }

    /**
     * Returns true when a field differs from how the editor opened; the generator settings don't
     * count.
     */
    private fun hasChanges(s: EditorUiState): Boolean {
        val b = baseline ?: return false
        if (s.title != b.title || s.userName != b.userName || s.url != b.url || s.notes != b.notes || s.groupId != b.groupId) return true
        val text = password.text
        if (text.length != baselinePassword.size) return true
        return text.indices.any { text[it] != baselinePassword[it] }
    }

    /** Runs Close and Back: see [resolveEditorDismiss]. */
    fun requestClose() {
        val s = mutable.value ?: return
        when (resolveEditorDismiss(s.saving, hasChanges(s), s.discardConfirm)) {
            EditorDismiss.DISMISS -> close()
            EditorDismiss.SHOW_CONFIRM -> change { copy(discardConfirm = true) }
            EditorDismiss.BLOCKED -> Unit
        }
    }

    fun setTitle(value: String) = change { copy(title = value) }
    fun setUserName(value: String) = change { copy(userName = value) }
    fun setUrl(value: String) = change { copy(url = value) }
    fun setNotes(value: String) = change { copy(notes = value) }
    fun selectGroup(id: String?) = change { copy(groupId = id) }

    fun setLength(length: Int) = change { copy(length = length.coerceIn(PasswordGenerator.MIN_LENGTH, PasswordGenerator.MAX_LENGTH)) }
    fun setSymbols(symbols: Boolean) = change { copy(symbols = symbols) }

    /** Replaces the password with a generated one using the current length and symbols. */
    fun generate() {
        val s = mutable.value ?: return
        val chars = PasswordGenerator.generate(s.length, s.symbols)
        try {
            password.setTextAndPlaceCursorAtEnd(String(chars))
        } finally {
            chars.fill('\u0000')
        }
    }

    /**
     * Saves the entry. With no field changed it closes without saving; otherwise the change is
     * saved at once and the editor closes after a verified save, or stays open with the reason.
     */
    fun save() {
        val s = mutable.value ?: return
        if (s.saving) return
        val unlocked = sessions.current.value ?: return
        val document = unlocked.session.opened.document
        val chars = password.text.toString().toCharArray()
        val draft = EntryDraft(s.title, s.userName, ProtectedText.of(chars), s.url, s.notes)
        change { copy(saving = true, problem = null) }
        viewModelScope.launch {
            val edited = withContext(compute) {
                if (s.entryId == null) {
                    EntryEdits.add(document, s.groupId, draft, now()).document
                } else {
                    when (val result = EntryEdits.edit(document, s.entryId, draft, now())) {
                        EditResult.Unchanged -> null
                        EditResult.EntryNotFound -> {
                            notices.tryEmit(EditorNotice.ENTRY_GONE)
                            null
                        }
                        is EditResult.Changed -> result.document
                    }
                }
            }
            if (edited == null) return@launch close()
            val result = coordinator.save(edited, basedOn = unlocked).await()
            when (result) {
                null -> close()
                is SaveResult.Saved -> {
                    notices.tryEmit(EditorNotice.SAVED)
                    close()
                }
                else -> change { copy(saving = false, problem = result) }
            }
        }
    }

    /** Closes the editor without saving; the password field is wiped. */
    fun close() {
        mutable.value = null
        password.clearText()
        baseline = null
        baselinePassword.fill('\u0000')
        baselinePassword = CharArray(0)
    }

    private fun change(block: EditorUiState.() -> EditorUiState) = mutable.update { it?.block() }
}
