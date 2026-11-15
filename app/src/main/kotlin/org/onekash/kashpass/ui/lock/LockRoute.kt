package org.onekash.kashpass.ui.lock

import android.content.ActivityNotFoundException
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import org.onekash.kashpass.R
import org.onekash.kashpass.platform.BiometricAvailability
import org.onekash.kashpass.platform.KeyFiles
import org.onekash.kashpass.platform.OpenDocumentFrom
import org.onekash.kashpass.platform.PromptTexts
import org.onekash.kashpass.platform.SystemBiometricPrompt
import org.onekash.kashpass.session.BiometricUnlock
import org.onekash.kashpass.ui.format.biometricNames
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.CryptoHandle
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import org.onekash.kashpass.session.LostChange
import org.onekash.kashpass.platform.VaultFiles
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.vault.open.VaultOpening

/**
 * Wires [LockScreen] to its view model and the system file pickers. The key-file picker leaves
 * the app, so [onPickerOpened] and [onPickerClosed] bracket it for the lock timer.
 */
@Composable
fun LockRoute(
    files: VaultFiles,
    opener: VaultOpening,
    sessions: SessionHolder,
    finishingSave: Boolean = false,
    lostChange: LostChange? = null,
    biometric: BiometricUnlock? = null,
    availability: BiometricAvailability? = null,
    keyFiles: KeyFiles? = null,
    onPickerOpened: () -> Unit = {},
    onPickerClosed: () -> Unit = {},
) {
    val vm = viewModel { LockViewModel(files, opener, sessions, biometric, keyFiles) }
    val state by vm.uiState.collectAsStateWithLifecycle()
    // remember, not rememberTextFieldState: a saveable state would write the typed password into
    // the saved instance state, which can reach disk.
    val password = remember { TextFieldState() }
    DisposableEffect(password) { onDispose { password.clearText() } }
    // Opens in the folder of a file another app handed over, so choosing it is one tap.
    val picker = rememberLauncherForActivityResult(OpenDocumentFrom(vm::pickStart)) { vm.onPicked(it) }
    val keyFilePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
        onPickerClosed()
        vm.onKeyFilePicked(it)
    }
    val names = biometricNames(availability)
    val context = LocalContext.current
    val prompt = remember(context) { SystemBiometricPrompt.forContext(context) }
    val title = stringResource(R.string.biometric_prompt_unlock)
    val usePassword = stringResource(R.string.lock_use_password)
    val confirm: suspend (CryptoHandle) -> Confirmation = { handle -> prompt.confirm(PromptTexts(title, state.vaultName.orEmpty(), usePassword), handle) }
    val activity = LocalActivity.current
    LifecycleEventEffect(Lifecycle.Event.ON_START) { vm.onAppear() }
    LifecycleEventEffect(Lifecycle.Event.ON_STOP) { vm.onDisappear(activity?.isChangingConfigurations == true) }
    LaunchedEffect(state.promptRequest) { vm.servePromptRequest(confirm) }
    LaunchedEffect(state.pickRequest) {
        // The cover over a finishing save leaves when the save ends, and a picker launched from it
        // would lose its result; the lock screen after it serves the request.
        if (!finishingSave && state.pickRequest > 0 && vm.takePickRequest()) picker.launch(arrayOf("application/octet-stream", "*/*"))
    }
    LockScreen(
        state = state,
        password = password,
        // Providers can label .kdbx files application/octet-stream; */* keeps every vault visible.
        onChooseFile = {
            vm.startPick()
            picker.launch(arrayOf("application/octet-stream", "*/*"))
        },
        onUnlock = { vm.unlock(password.takePassword()) },
        onRetry = vm::refresh,
        onOpenLastCopy = vm::openLastCopy,
        onCancelBackup = vm::cancelBackup,
        finishingSave = finishingSave,
        lostChange = lostChange,
        onBiometric = { vm.unlockWithBiometric(confirm) },
        onUsePassword = vm::usePassword,
        biometricButton = names.button,
        biometricName = names.name,
        onAddKeyFile = {
            vm.startKeyFilePick()
            onPickerOpened()
            // Key files have any name and type (.keyx, .key, none).
            try {
                keyFilePicker.launch(arrayOf("*/*"))
            } catch (e: ActivityNotFoundException) {
                onPickerClosed()
                vm.onKeyFilePicked(null)
            }
        },
        onRemoveKeyFile = vm::removeKeyFile,
        onOpenOffered = vm::openOffered,
        onCancelUnlock = vm::cancelUnlock,
        wavePlayed = vm.wavePlayed,
        onWavePlayed = vm::markWavePlayed,
        onCancelIncoming = vm::cancelIncoming,
    )
}
