package org.onekash.kashpass.ui.settings

import android.content.ActivityNotFoundException
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.onekash.kashpass.R
import org.onekash.kashpass.platform.BiometricAvailability
import org.onekash.kashpass.platform.PromptTexts
import org.onekash.kashpass.platform.SystemBiometricPrompt
import org.onekash.kashpass.ui.components.openWebLink
import org.onekash.kashpass.ui.format.biometricNames

/**
 * Shows Settings while [vm] has it open, with Android's prompt for turning biometric unlock on
 * and the About sheet over it. A link from About leaves the app, so the away lock applies.
 */
@Composable
fun SettingsRoute(
    vm: SettingsViewModel,
    availability: BiometricAvailability?,
    onLock: () -> Unit,
    onBackups: () -> Unit,
    onChooseFile: () -> Unit,
) {
    val state by vm.state.collectAsStateWithLifecycle()
    val current = state ?: return
    BackHandler { vm.close() }
    val context = LocalContext.current
    val prompt = remember(context) { SystemBiometricPrompt.forContext(context) }
    val names = biometricNames(availability)
    val title = stringResource(R.string.biometric_prompt_turn_on, names.name.lowercase())
    val cancel = stringResource(R.string.biometric_prompt_cancel)
    SettingsScreen(
        state = current,
        biometricNoun = names.noun,
        onBack = vm::close,
        onLock = onLock,
        onBiometric = { on -> vm.setBiometric(on) { handle -> prompt.confirm(PromptTexts(title, current.fileName, cancel), handle) } },
        onEnroll = {
            val intent = availability?.enrollIntent() ?: return@SettingsScreen
            try {
                context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            } catch (e: ActivityNotFoundException) {
                // Some phones have no enroll screen for this request; the hint text stays.
            }
        },
        onBackups = onBackups,
        onChooseFile = onChooseFile,
        onAbout = vm::openAbout,
    )
    if (current.about) {
        val version = remember(context) { AppVersion.read(context) }
        AboutSheet(
            version,
            onDismiss = vm::closeAbout,
            onOpenLink = { link -> openWebLink(context, link) },
            rowsPlayed = vm.aboutRowsPlayed,
            onRowsPlayed = vm::markAboutRowsPlayed,
        )
    }
}
