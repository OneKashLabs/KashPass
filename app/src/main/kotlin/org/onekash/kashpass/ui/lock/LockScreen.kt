package org.onekash.kashpass.ui.lock

import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.hideFromAccessibility
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import org.onekash.kashpass.R
import org.onekash.kashpass.ui.components.KASH_TAG
import org.onekash.kashpass.ui.components.KashWaveEntrance
import org.onekash.kashpass.ui.components.rememberHeroMotionEnabled
import org.onekash.kashpass.ui.input.NoPersonalizedLearning
import org.onekash.kashpass.ui.input.noAutofill
import org.onekash.kashpass.session.LostChange
import org.onekash.kashpass.session.TurnOffReason
import java.time.Instant
import java.time.ZoneId
import org.onekash.kashpass.ui.format.EntryTimes
import org.onekash.kashpass.ui.format.KdfFormat
import org.onekash.kashpass.ui.theme.Navy
import org.onekash.kashpass.vault.doc.DecodeFailure
import org.onekash.kashpass.vault.header.UnsupportedReason
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.policy.KdfSetting
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.maxVaultBytes

private val VeilText = Color.White
private val VeilMuted = Color.White.copy(alpha = 0.62f)
// 0.56 keeps the 11 sp footnote above 4.5:1 contrast on the navy ground.
private val VeilFaint = Color.White.copy(alpha = 0.56f)

/**
 * Copies the field's text into a new array and empties the field, so the only copy KashPass hands
 * on is the array the opener zero-fills.
 */
fun TextFieldState.takePassword(): CharArray {
    val chars = text.let { cs -> CharArray(cs.length) { cs[it] } }
    clearText()
    return chars
}

/**
 * Shows the lock screen: navy ground, the app icon, the vault name, and the one action that
 * applies. First run (no vault chosen, offered or checked, no field, problem or lost change)
 * shows Kash waving ([KashWaveEntrance], with [wavePlayed] and [onWavePlayed]) in place of the
 * app icon and name, and the first-run heading. Stateless; [LockRoute] wires it to
 * [LockViewModel]. With [finishingSave] it only covers the vault while a save ends behind it: no
 * field and no actions. [lostChange] says once that the last change didn't reach the file. Back
 * while unlocking calls [onCancelUnlock]; otherwise Back is left to the system.
 */
@Composable
fun LockScreen(
    state: LockUiState,
    password: TextFieldState,
    onChooseFile: () -> Unit,
    onUnlock: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenLastCopy: () -> Unit = {},
    onCancelBackup: () -> Unit = {},
    finishingSave: Boolean = false,
    lostChange: LostChange? = null,
    onBiometric: () -> Unit = {},
    onUsePassword: () -> Unit = {},
    /** Android's label for the biometric button, or KashPass's own ("Unlock with fingerprint"). */
    biometricButton: String = "",
    /** The feature's name on this device ("Fingerprint unlock", "Face unlock"). */
    biometricName: String = "",
    onAddKeyFile: () -> Unit = {},
    onRemoveKeyFile: () -> Unit = {},
    onOpenOffered: () -> Unit = {},
    onCancelIncoming: () -> Unit = {},
    onCancelUnlock: () -> Unit = {},
    /** Whether Kash has waved on first run already; read once, when first run appears. */
    wavePlayed: Boolean = false,
    onWavePlayed: () -> Unit = {},
) {
    // The quiet start: nothing chosen, offered or checked, and no problem or lost change to report.
    val firstRun = state.vaultName == null && !state.offered && !state.openedFromApp && !state.checking &&
        !state.showPasswordField && state.backupTarget == null && !state.unlocking &&
        state.message == null && !state.lostCutOffSave && !finishingSave && lostChange == null
    BackHandler(enabled = state.unlocking && !finishingSave, onBack = onCancelUnlock)
    LightSystemBarIcons()
    Box(
        modifier = modifier
            .fillMaxSize()
            // Swallows touches so nothing behind the veil reacts.
            .pointerInput(Unit) {}
            .background(Brush.radialGradient(listOf(Color(0xFF01051E), Color(0xFF010316), Color(0xFF00020E))))
            .systemBarsPadding()
            .imePadding(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (firstRun) {
                Spacer(Modifier.height(48.dp))
                KashWaveEntrance(
                    motionEnabled = rememberHeroMotionEnabled(),
                    played = wavePlayed,
                    onPlayed = onWavePlayed,
                    modifier = Modifier.size(160.dp).testTag(KASH_TAG),
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    stringResource(R.string.lock_first_run_title),
                    color = VeilText,
                    fontSize = 24.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.semantics { heading() },
                )
            } else {
                Spacer(Modifier.height(64.dp))
                AppTile()
                Spacer(Modifier.height(18.dp))
                Text(
                    stringResource(R.string.app_name),
                    color = VeilText,
                    fontSize = 21.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.semantics { heading() },
                )
                Spacer(Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(painterResource(R.drawable.ic_lock), contentDescription = null, tint = VeilMuted, modifier = Modifier.size(15.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(
                        stringResource(if (state.vaultName == null) R.string.lock_no_vault else R.string.lock_locked),
                        color = VeilMuted,
                        fontSize = 13.sp,
                    )
                }
            }
            if (finishingSave) {
                Spacer(Modifier.height(32.dp))
                CircularProgressIndicator(color = VeilMuted)
                Spacer(Modifier.height(14.dp))
                Text(
                    stringResource(R.string.lock_finishing_save),
                    color = VeilText,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                return@Column
            }
            // One line: when the lock waited on a save, its line replaces the cut-off note.
            val lostLine = when {
                lostChange == LostChange.NOT_SAVED -> R.string.lock_change_not_saved
                lostChange != null -> R.string.lock_change_maybe_not_saved
                state.lostCutOffSave -> R.string.lock_cut_off_save
                else -> null
            }
            lostLine?.let {
                Spacer(Modifier.height(14.dp))
                Text(
                    stringResource(it),
                    color = VeilText,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            if (state.vaultName != null) {
                Spacer(Modifier.height(14.dp))
                FileChip(state.vaultName)
                // A file another app handed over gets a lasting read and write grant only
                // through the picker, which opens at that file.
                val choose = if (state.openedFromApp) R.string.lock_make_it_your_vault else R.string.lock_choose_different
                if (state.showPasswordField && !state.offered) {
                    TextButton(onClick = onChooseFile, enabled = !state.unlocking) { Text(stringResource(choose)) }
                }
            }
            val incomingLine = when {
                state.offered -> state.offeredInPlaceOf?.let { stringResource(R.string.lock_offered_file, it) } ?: stringResource(R.string.lock_offered_first_file)
                state.openedFromApp -> stringResource(R.string.lock_opened_from_app)
                else -> null
            }
            incomingLine?.let {
                Spacer(Modifier.height(14.dp))
                Text(it, color = VeilText, textAlign = TextAlign.Center, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                state.openedInPlaceOf?.takeIf { state.openedFromApp }?.let { replaced ->
                    Text(stringResource(R.string.lock_opened_replaces, replaced), color = VeilText, textAlign = TextAlign.Center)
                }
                TextButton(onClick = onCancelIncoming, enabled = !state.unlocking) { Text(stringResource(R.string.lock_incoming_cancel)) }
            }
            state.message?.takeIf { it != LockMessage.WrongPassword && (state.backupTarget == null || it == LockMessage.BackupDamaged || it.isKeyFileProblem) }?.let {
                Spacer(Modifier.height(18.dp))
                ProblemCard(it)
                if (state.canRetry) {
                    TextButton(onClick = onRetry) { Text(stringResource(R.string.lock_retry)) }
                }
                // Hidden once the copy is the target: a failed copy is not shown again.
                state.lastCopy?.takeIf { state.backupTarget == null }?.let { copy ->
                    TextButton(onClick = onOpenLastCopy) {
                        Text(stringResource(R.string.lock_open_last_copy, EntryTimes.past(LocalResources.current, copy.backup.createdAt, Instant.now(), ZoneId.systemDefault())))
                    }
                }
            }
            state.backupTarget?.let { backup ->
                Spacer(Modifier.height(18.dp))
                Text(
                    stringResource(R.string.lock_backup_mode, EntryTimes.past(LocalResources.current, backup.createdAt, Instant.now(), ZoneId.systemDefault())),
                    color = VeilText,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                TextButton(onClick = onCancelBackup, enabled = !state.unlocking) { Text(stringResource(R.string.lock_backup_cancel)) }
            }
            Spacer(Modifier.weight(1f).height(24.dp))
            state.slow?.takeIf { state.showPasswordField }?.let { slow ->
                Text(
                    slow.factor?.let { stringResource(R.string.lock_slow_kdf, it) } ?: stringResource(R.string.lock_slow_kdf_first, slow.units),
                    color = VeilText,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(bottom = 12.dp).semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            state.turnedOff?.let { reason ->
                Text(
                    turnedOffText(reason, biometricName),
                    color = VeilText,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(bottom = 12.dp).semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            if (state.keyFileNeeded) {
                Text(
                    stringResource(R.string.lock_biometric_needs_key_file, biometricName.lowercase()),
                    color = VeilText,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(bottom = 12.dp).semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            if (state.biometricFailed) {
                Text(
                    stringResource(R.string.lock_biometric_failed),
                    color = VeilText,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(bottom = 12.dp).semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            val useBiometric = state.biometricOn && !state.passwordChosen && state.backupTarget == null
            if (state.showPasswordField && !useBiometric) {
                PasswordField(state, password, onUnlock)
                // Only the name shows, never the key file's location or contents.
                if (state.keyFileName == null) {
                    TextButton(onClick = onAddKeyFile, enabled = !state.unlocking) { Text(stringResource(R.string.lock_add_key_file)) }
                } else {
                    Spacer(Modifier.height(8.dp))
                    KeyFileChip(state.keyFileName, enabled = !state.unlocking, onRemove = onRemoveKeyFile)
                }
                Spacer(Modifier.height(16.dp))
            }
            if (useBiometric) {
                BiometricAction(state, biometricButton, onBiometric)
                TextButton(onClick = onUsePassword, enabled = !state.unlocking) { Text(stringResource(R.string.lock_use_password), color = VeilText) }
            } else {
                PrimaryAction(state, onChooseFile, onUnlock, onOpenOffered)
            }
            Text(
                stringResource(footnote(state, firstRun)),
                color = VeilFaint,
                fontSize = 11.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 14.dp, bottom = 22.dp),
            )
        }
    }
}

@Composable
private fun LightSystemBarIcons() {
    val view = LocalView.current
    val activity = LocalActivity.current ?: return
    DisposableEffect(view, activity) {
        val controller = WindowCompat.getInsetsController(activity.window, view)
        val status = controller.isAppearanceLightStatusBars
        val navigation = controller.isAppearanceLightNavigationBars
        controller.isAppearanceLightStatusBars = false
        controller.isAppearanceLightNavigationBars = false
        onDispose {
            controller.isAppearanceLightStatusBars = status
            controller.isAppearanceLightNavigationBars = navigation
        }
    }
}

@Composable
private fun AppTile() {
    Box(
        modifier = Modifier
            .size(84.dp)
            .clip(RoundedCornerShape(20.dp))
            .background(Navy),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            painter = painterResource(R.drawable.ic_launcher_foreground),
            contentDescription = null,
            modifier = Modifier.fillMaxSize().scale(1.3f),
        )
    }
}

@Composable
private fun FileChip(name: String) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(Color.White.copy(alpha = 0.07f))
            .padding(horizontal = 12.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(painterResource(R.drawable.ic_description), contentDescription = null, tint = VeilText.copy(alpha = 0.82f), modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text(name, color = VeilText.copy(alpha = 0.82f), fontSize = 12.5.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

// TalkBack reads the remove button as "Key file: <name>, remove"; the name itself is hidden from
// it, so it isn't read twice.
@Composable
private fun KeyFileChip(name: String, enabled: Boolean, onRemove: () -> Unit) {
    val description = stringResource(R.string.lock_key_file_remove, name)
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(Color.White.copy(alpha = 0.07f))
            .padding(start = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(painterResource(R.drawable.ic_attach_file), contentDescription = null, tint = VeilText.copy(alpha = 0.82f), modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(6.dp))
        Text(
            name,
            color = VeilText.copy(alpha = 0.82f),
            fontSize = 12.5.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f, fill = false).semantics { hideFromAccessibility() },
        )
        IconButton(onClick = onRemove, enabled = enabled, modifier = Modifier.semantics { contentDescription = description }) {
            Icon(painterResource(R.drawable.ic_close), contentDescription = null, tint = VeilText.copy(alpha = 0.82f), modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
private fun PasswordField(state: LockUiState, password: TextFieldState, onUnlock: () -> Unit) = NoPersonalizedLearning {
    var revealed by remember { mutableStateOf(false) }
    val wrong = state.message == LockMessage.WrongPassword
    OutlinedSecureTextField(
        state = password,
        modifier = Modifier.fillMaxWidth().noAutofill(),
        enabled = !state.unlocking,
        label = { Text(stringResource(R.string.lock_password_label)) },
        isError = wrong,
        supportingText = if (wrong) {
            {
                // With a key file set either input can be wrong. Without one, the error for a vault
                // last unlocked with a key file says to add the key file again.
                val text = when {
                    state.keyFileName != null -> R.string.error_wrong_password_or_key_file
                    state.keyFileUnlockedBefore -> R.string.error_wrong_password_key_file_before
                    else -> R.string.error_wrong_password
                }
                Text(stringResource(text), Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            }
        } else {
            null
        },
        textObfuscationMode = if (revealed) TextObfuscationMode.Visible else TextObfuscationMode.RevealLastTyped,
        trailingIcon = {
            val description = stringResource(if (revealed) R.string.lock_hide_password else R.string.lock_show_password)
            IconButton(onClick = { revealed = !revealed }, modifier = Modifier.semantics { contentDescription = description }) {
                Icon(
                    painterResource(if (revealed) R.drawable.ic_visibility_off else R.drawable.ic_visibility),
                    contentDescription = null,
                )
            }
        },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
        onKeyboardAction = { onUnlock() },
        colors = OutlinedTextFieldDefaults.colors(
            focusedTextColor = VeilText,
            unfocusedTextColor = VeilText,
            unfocusedLabelColor = VeilMuted,
            unfocusedBorderColor = VeilFaint,
            unfocusedTrailingIconColor = VeilMuted,
            focusedTrailingIconColor = VeilText,
        ),
    )
}

@Composable
private fun turnedOffText(reason: TurnOffReason, name: String): String = when (reason) {
    TurnOffReason.NEW_BIOMETRIC -> stringResource(R.string.lock_off_new_biometric, name)
    TurnOffReason.LOCKED_OUT -> stringResource(R.string.lock_off_locked_out, name)
    TurnOffReason.PASSWORD_CHANGED -> stringResource(R.string.lock_off_password_changed, name.lowercase())
    TurnOffReason.SCREEN_LOCK_REMOVED -> stringResource(R.string.lock_off_screen_lock, name)
    TurnOffReason.BIOMETRICS_REMOVED -> stringResource(R.string.lock_off_biometrics_removed, name)
    TurnOffReason.DAMAGED -> stringResource(R.string.lock_off_damaged, name)
    TurnOffReason.UNRECOVERABLE_KEY -> stringResource(R.string.lock_off_unrecoverable_key, name)
}

@Composable
private fun BiometricAction(state: LockUiState, label: String, onBiometric: () -> Unit) {
    Button(
        onClick = onBiometric,
        enabled = !state.unlocking,
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ),
        shape = RoundedCornerShape(25.dp),
        modifier = ActionSize,
    ) {
        if (state.unlocking) {
            UnlockingLabel()
        } else {
            Icon(painterResource(R.drawable.ic_fingerprint), contentDescription = null, modifier = Modifier.size(19.dp))
            Spacer(Modifier.width(9.dp))
            Text(label, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
        }
    }
}

@Composable
private fun UnlockingLabel() {
    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.5.dp, color = MaterialTheme.colorScheme.onPrimaryContainer)
    Spacer(Modifier.width(9.dp))
    Text(stringResource(R.string.lock_unlocking), fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
}

// A minimum, not a fixed size: a longer label or a larger font grows the button instead of
// cutting the label.
private val ActionSize = Modifier.widthIn(min = 230.dp).heightIn(min = 50.dp)

@Composable
private fun PrimaryAction(state: LockUiState, onChooseFile: () -> Unit, onUnlock: () -> Unit, onOpenOffered: () -> Unit) {
    val colors = ButtonDefaults.buttonColors(
        containerColor = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
    )
    val modifier = ActionSize
    val shape = RoundedCornerShape(25.dp)
    when {
        // First, so a file being taken or checked shows the spinner in place of every button.
        state.checking -> CircularProgressIndicator(color = VeilMuted)
        state.offered -> Button(onClick = onOpenOffered, colors = colors, shape = shape, modifier = modifier) {
            Icon(painterResource(R.drawable.ic_folder_open), contentDescription = null, modifier = Modifier.size(19.dp))
            Spacer(Modifier.width(9.dp))
            Text(stringResource(R.string.lock_open_this_file), fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
        }
        state.vaultName == null -> Button(onClick = onChooseFile, colors = colors, shape = shape, modifier = modifier) {
            Icon(painterResource(R.drawable.ic_folder_open), contentDescription = null, modifier = Modifier.size(19.dp))
            Spacer(Modifier.width(9.dp))
            Text(stringResource(R.string.lock_choose_vault), fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
        }
        state.showPasswordField -> Button(onClick = onUnlock, enabled = !state.unlocking, colors = colors, shape = shape, modifier = modifier) {
            if (state.unlocking) {
                UnlockingLabel()
            } else {
                Icon(painterResource(R.drawable.ic_lock_open), contentDescription = null, modifier = Modifier.size(19.dp))
                Spacer(Modifier.width(9.dp))
                Text(stringResource(if (state.slow != null) R.string.lock_unlock_anyway else R.string.lock_unlock), fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
            }
        }
        else -> Button(onClick = onChooseFile, colors = colors, shape = shape, modifier = modifier) {
            Icon(painterResource(R.drawable.ic_folder_open), contentDescription = null, modifier = Modifier.size(19.dp))
            Spacer(Modifier.width(9.dp))
            Text(stringResource(R.string.lock_choose_vault), fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
        }
    }
}

@Composable
private fun ProblemCard(message: LockMessage) {
    val (title, body) = problemText(message)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(Color(0x5293000A))
            .padding(horizontal = 14.dp, vertical = 12.dp)
            // Shown after a tap elsewhere (Unlock, Retry), so screen readers announce it.
            .semantics { liveRegion = LiveRegionMode.Polite },
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        if (title != null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(painterResource(R.drawable.ic_gpp_bad), contentDescription = null, tint = Color(0xFFFFDAD6), modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(title, color = Color(0xFFFFDAD6), fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            }
        }
        Text(body, color = Color(0xFFFFDAD6), fontSize = 12.5.sp)
    }
}

@Composable
private fun problemText(message: LockMessage): Pair<String?, String> = when (message) {
    LockMessage.WrongPassword -> null to stringResource(R.string.error_wrong_password)
    LockMessage.Damaged -> null to stringResource(R.string.error_damaged)
    LockMessage.DamagedAfterHeader -> null to stringResource(R.string.error_damaged_repair)
    LockMessage.BackupDamaged -> null to stringResource(R.string.backup_damaged)
    LockMessage.NotEnoughMemory -> null to stringResource(R.string.error_not_enough_memory)
    LockMessage.ChooseFailed -> null to stringResource(R.string.error_choose_failed)
    LockMessage.KeyFileDamaged -> null to stringResource(R.string.error_key_file_damaged)
    LockMessage.NotKeyFile -> null to stringResource(R.string.error_not_key_file)
    LockMessage.KeyFileMismatch -> null to stringResource(R.string.error_key_file_mismatch)
    LockMessage.KeyFileTooLarge -> null to stringResource(R.string.error_key_file_xml_too_large)
    is LockMessage.KeyFileUnreadable -> null to when (message.cause) {
        StorageFailure.NOT_FOUND -> stringResource(R.string.error_key_file_not_found)
        StorageFailure.PERMISSION_REVOKED -> stringResource(R.string.error_key_file_permission_revoked)
        StorageFailure.IO_FAILURE -> stringResource(R.string.error_key_file_io)
        StorageFailure.TOO_LARGE -> stringResource(R.string.error_key_file_too_large, readLimitMib())
        StorageFailure.TIMED_OUT -> stringResource(R.string.error_key_file_timed_out)
    }
    is LockMessage.Unreadable -> null to when (message.cause) {
        StorageFailure.NOT_FOUND -> stringResource(R.string.error_not_found)
        StorageFailure.PERMISSION_REVOKED -> stringResource(R.string.error_permission_revoked)
        StorageFailure.IO_FAILURE -> stringResource(R.string.error_io)
        StorageFailure.TOO_LARGE -> stringResource(R.string.error_too_large, readLimitMib())
        StorageFailure.TIMED_OUT -> stringResource(R.string.error_timed_out)
    }
    is LockMessage.Unsupported -> stringResource(R.string.unsupported_title) to when (val r = message.reason) {
        is UnsupportedReason.FormatVersion -> when {
            r.major == 1 -> stringResource(R.string.unsupported_keepass1)
            // A current desktop app upgrades an older file to KDBX 4 on save; a newer file has no
            // fix on the desktop.
            r.major > 4 -> stringResource(R.string.unsupported_newer, r.major, r.minor)
            else -> stringResource(R.string.unsupported_version, r.major, r.minor)
        }
        is UnsupportedReason.Cipher -> stringResource(R.string.unsupported_cipher)
        is UnsupportedReason.Kdf -> stringResource(R.string.unsupported_kdf)
        is UnsupportedReason.DictionaryVersion, is UnsupportedReason.DictionaryValueType, is UnsupportedReason.Compression,
        is UnsupportedReason.InnerStream,
        -> stringResource(R.string.unsupported_format_feature)
    }
    is LockMessage.Failed -> null to when (message.cause) {
        DecodeFailure.PLATFORM -> stringResource(R.string.error_failed_platform)
        DecodeFailure.INTERNAL -> stringResource(R.string.error_failed_internal)
    }
    is LockMessage.Refused -> stringResource(R.string.refused_title) to when (val r = message.rejection) {
        is KdfRejection.OutOfBounds -> stringResource(R.string.refused_out_of_bounds, settingName(r.setting), number(r.setting, r.value))
        is KdfRejection.Weakened ->
            stringResource(R.string.refused_weakened, settingName(r.setting), number(r.setting, r.previous), number(r.setting, r.current))
        is KdfRejection.WeakAfterTypeChange -> stringResource(R.string.refused_weak_type_change)
    }
}

@Composable
private fun settingName(setting: KdfSetting): String = stringResource(
    when (setting) {
        KdfSetting.AES_ROUNDS -> R.string.kdf_setting_aes_rounds
        KdfSetting.ARGON2_ITERATIONS -> R.string.kdf_setting_argon2_iterations
        KdfSetting.ARGON2_MEMORY -> R.string.kdf_setting_argon2_memory
        KdfSetting.ARGON2_PARALLELISM -> R.string.kdf_setting_argon2_parallelism
        KdfSetting.ARGON2_VERSION -> R.string.kdf_setting_argon2_version
        KdfSetting.ARGON2_WORK -> R.string.kdf_setting_argon2_work
        KdfSetting.WORK_UNITS -> R.string.kdf_setting_work_units
    },
)

// Argon2 work is iterations x bytes; shown as iterations x MiB so the numbers stay readable.
// Work units come in thousandths.
private fun number(setting: KdfSetting, value: ULong): String = when (setting) {
    KdfSetting.ARGON2_VERSION -> "0x" + value.toString(16)
    KdfSetting.ARGON2_WORK -> KdfFormat.mib(value)
    KdfSetting.WORK_UNITS -> KdfFormat.units(value)
    else -> KdfFormat.count(value)
}

private fun footnote(state: LockUiState, firstRun: Boolean): Int = when {
    firstRun -> R.string.lock_footnote_first_run
    state.vaultName == null -> R.string.lock_footnote_no_vault
    state.unlocking -> R.string.lock_footnote_unlocking
    state.message?.passwordUnused == true -> R.string.lock_footnote_password_unused
    else -> R.string.lock_footnote_locked
}

// The read limit of this device's heap in MiB, the same limit the opener and the key-file read use.
private fun readLimitMib(): Int = maxVaultBytes(Runtime.getRuntime().maxMemory()) / (1024 * 1024)
