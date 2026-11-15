package org.onekash.kashpass.ui.settings

import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.onekash.kashpass.R
import org.onekash.kashpass.session.BiometricStatus
import org.onekash.kashpass.ui.components.InfoButton
import org.onekash.kashpass.vault.storage.UnlockAvailability

/**
 * Shows Settings, the full-screen page behind the browser's gear: a back arrow, the vault at the
 * top with Lock vault under it, then four rows with no section headers: Biometric unlock, Vault
 * backups (opens the sheet), Open another vault and About KashPass (opens [AboutSheet]).
 * [SettingsRoute] wires its callbacks.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    state: SettingsUiState,
    biometricNoun: String,
    onBack: () -> Unit,
    onLock: () -> Unit,
    onBiometric: (Boolean) -> Unit,
    onEnroll: () -> Unit,
    onBackups: () -> Unit,
    onChooseFile: () -> Unit,
    onAbout: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = {},
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(painterResource(R.drawable.ic_arrow_back), stringResource(R.string.settings_back)) }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState())) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 8.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Box(
                    Modifier.size(64.dp).clip(RoundedCornerShape(20.dp)).background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(painterResource(R.drawable.ic_vault_mark), contentDescription = null, tint = MaterialTheme.colorScheme.onPrimaryContainer, modifier = Modifier.size(40.dp))
                }
                Spacer(Modifier.size(12.dp))
                Text(state.fileName, style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
                OutlinedButton(onClick = onLock, modifier = Modifier.padding(top = 12.dp)) {
                    Icon(painterResource(R.drawable.ic_lock), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.settings_lock_now))
                }
            }
            Spacer(Modifier.size(8.dp))
            if (state.biometricShown) {
                BiometricRow(state.biometric, state.isFile, !state.applying, state.biometricFailed, biometricNoun, onBiometric, onEnroll)
            }
            if (state.backupsShown) {
                NavigationRow(R.drawable.ic_history, stringResource(R.string.backups_title), chevron = true, onClick = onBackups)
            }
            NavigationRow(R.drawable.ic_folder_open, stringResource(R.string.settings_choose_file), chevron = false, onClick = onChooseFile)
            NavigationRow(R.drawable.ic_info, stringResource(R.string.about_title), chevron = true, onClick = onAbout)
        }
        // After the content, so it draws over the top edge and the page doesn't move when it shows.
        if (state.applying) LinearProgressIndicator(Modifier.padding(top = padding.calculateTopPadding()).fillMaxWidth())
    }
}

// A one-line row that runs [onClick]; [chevron] marks one that opens another view.
@Composable
private fun NavigationRow(@DrawableRes icon: Int, title: String, chevron: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).heightIn(min = 56.dp).padding(horizontal = 28.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Icon(painterResource(icon), contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(title, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        if (chevron) Icon(painterResource(R.drawable.ic_chevron_right), contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun BiometricRow(
    status: BiometricStatus,
    isFile: Boolean,
    /** False while another change applies. */
    enabled: Boolean,
    failed: Boolean,
    noun: String,
    onBiometric: (Boolean) -> Unit,
    onEnroll: () -> Unit,
) {
    val on = status == BiometricStatus.On
    val usable = isFile && enabled && status !is BiometricStatus.Unavailable
    Row(
        Modifier
            .fillMaxWidth()
            .toggleable(value = on, enabled = usable, role = Role.Switch, onValueChange = onBiometric)
            .heightIn(min = 56.dp)
            .padding(horizontal = 28.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Icon(painterResource(R.drawable.ic_fingerprint), contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Column(Modifier.weight(1f)) {
            val title = stringResource(R.string.settings_biometric)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                InfoButton(title, stringResource(R.string.settings_info_biometric))
            }
            // The switch shows on or off; a line shows only when the switch can't be used.
            val reason = when {
                !isFile -> stringResource(R.string.settings_backup_read_only)
                status is BiometricStatus.Unavailable -> unavailableReason(status.reason, noun)
                else -> null
            }
            reason?.let { Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            if (failed) {
                Text(stringResource(R.string.settings_biometric_failed), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
            }
            if (isFile && status is BiometricStatus.Unavailable && status.reason != UnlockAvailability.UNAVAILABLE) {
                TextButton(onClick = onEnroll) { Text(stringResource(R.string.settings_open_device_settings)) }
            }
        }
        // The row toggles; the switch only shows the state.
        Switch(checked = on, onCheckedChange = null, enabled = usable)
    }
}

@Composable
private fun unavailableReason(reason: UnlockAvailability, noun: String): String = when (reason) {
    UnlockAvailability.NONE_ENROLLED -> stringResource(R.string.settings_biometric_enroll, noun)
    UnlockAvailability.NO_SCREEN_LOCK -> stringResource(R.string.settings_biometric_screen_lock)
    else -> stringResource(R.string.settings_biometric_unavailable)
}
