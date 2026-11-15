package org.onekash.kashpass.ui.edit

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * Shows the editor while [vm] has an entry open. Back and Close go to
 * [EditorViewModel.requestClose], which shows "Discard?" before dropping changes.
 */
@Composable
fun EditorRoute(vm: EditorViewModel) {
    val state by vm.state.collectAsStateWithLifecycle()
    val current = state ?: return
    BackHandler(enabled = !current.saving) { vm.requestClose() }
    EntryEditor(
        state = current,
        password = vm.password,
        onTitle = vm::setTitle,
        onUserName = vm::setUserName,
        onUrl = vm::setUrl,
        onNotes = vm::setNotes,
        onGroup = vm::selectGroup,
        onLength = vm::setLength,
        onSymbols = vm::setSymbols,
        onGenerate = vm::generate,
        onSave = vm::save,
        onClose = vm::requestClose,
    )
}
