package org.onekash.kashpass.ui.browse

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.merge
import org.onekash.kashpass.R
import org.onekash.kashpass.platform.BiometricAvailability
import org.onekash.kashpass.platform.PromptTexts
import org.onekash.kashpass.platform.SystemBiometricPrompt
import org.onekash.kashpass.session.BiometricUnlock
import org.onekash.kashpass.ui.components.openWebLink
import org.onekash.kashpass.ui.components.rememberUndoWindow
import org.onekash.kashpass.ui.format.biometricNames
import androidx.compose.runtime.getValue
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.ui.format.UiMessage
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.vault.open.VaultOpening

/**
 * Wires [BrowseScreen] to its view model and the sensitive clipboard; empty while locked.
 * [messages] are texts to show once (results of edits and saves made elsewhere); [onEdit] and
 * [onAdd] open the editor, which the activity hosts.
 */
@Composable
fun BrowseRoute(
    sessions: SessionHolder,
    opener: VaultOpening,
    copyToClipboard: (String) -> Boolean,
    messages: Flow<UiMessage> = emptyFlow(),
    onEdit: (entryId: String) -> Unit = {},
    onAdd: (groupId: String?) -> Unit = {},
    saves: SaveCoordinator? = null,
    /** Opens Settings (the gear). */
    onOpenSettings: () -> Unit,
    biometric: BiometricUnlock? = null,
    availability: BiometricAvailability? = null,
    fileName: () -> String = { "" },
    /** Opens the picker for Save as new file; the activity's root host runs it. */
    onSaveAsNewFile: () -> Unit = {},
    /** The remembered vault that Save as new file puts a copy in place of, or null. */
    saveAsNewReplaces: () -> String? = { null },
) {
    val vm = viewModel { BrowseViewModel(sessions, opener, saves, copyToClipboard = copyToClipboard, biometric = biometric) }
    val state by vm.uiState.collectAsStateWithLifecycle()
    val current = state ?: return
    val names = biometricNames(availability)
    val context = LocalContext.current
    val prompt = remember(context) { SystemBiometricPrompt.forContext(context) }
    val title = stringResource(R.string.biometric_prompt_turn_on, names.name.lowercase())
    val cancel = stringResource(R.string.biometric_prompt_cancel)
    val resources = LocalResources.current
    val undoWindow = rememberUndoWindow()
    // The offer card's confirmation joins the screen's other one-off messages.
    val allMessages = remember(messages, vm) {
        merge(
            messages,
            vm.biometricTurnedOn.map { file -> UiMessage(resources.getString(R.string.offer_turned_on, names.name, file)) },
            vm.biometricFailed.map { UiMessage(resources.getString(R.string.offer_failed, names.name.lowercase())) },
        )
    }
    BrowseScreen(
        state = current,
        onQueryChange = vm::setQuery,
        onSelectChip = vm::selectChip,
        onOpenEntry = vm::openEntry,
        onCloseEntry = vm::closeEntry,
        onToggleReveal = vm::toggleReveal,
        onCopy = vm::copy,
        onDismissWeakWarning = vm::dismissWeakWarning,
        onOpenSettings = onOpenSettings,
        onSubmitSearch = vm::openSingleResult,
        onSearchFocused = vm::consumeSearchFocus,
        messages = allMessages,
        onEdit = { id ->
            vm.closeEntry()
            onEdit(id)
        },
        onAdd = { onAdd(vm.addTarget()) },
        deletes = vm.deletes,
        deleteKind = vm::deleteKind,
        onDelete = { id -> vm.delete(id, undoWindow) },
        onDeletePermanently = vm::deletePermanently,
        onUndoDelete = vm::undoDeletes,
        onOpenUrl = { link -> openWebLink(context, link) },
        onSearchTag = vm::searchTag,
        onConfirmCopy = vm::confirmCopy,
        onCancelCopy = vm::cancelCopy,
        onSaveAsNewFile = onSaveAsNewFile,
        saveAsNewReplaces = saveAsNewReplaces(),
        onCloseBackup = vm::closeBackup,
        onAcceptOlderFile = vm::acceptOlderFile,
        onDismissBytesAfterEnd = vm::dismissBytesAfterEnd,
        offerNoun = names.noun,
        onTurnOnBiometric = {
            val file = fileName()
            vm.enableBiometric({ handle -> prompt.confirm(PromptTexts(title, file, cancel), handle) }, file)
        },
        onDismissOffer = vm::dismissOffer,
        onOfferShown = vm::offerShown,
    )
}
