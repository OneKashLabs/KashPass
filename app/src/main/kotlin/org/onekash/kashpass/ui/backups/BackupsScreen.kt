package org.onekash.kashpass.ui.backups

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetProperties
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.setProgress
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlin.math.roundToInt
import kotlinx.coroutines.launch
import org.onekash.kashpass.R
import org.onekash.kashpass.ui.components.InfoButton
import org.onekash.kashpass.ui.components.InfoChip
import org.onekash.kashpass.ui.components.InlineConfirm
import org.onekash.kashpass.ui.components.RevealedRow
import org.onekash.kashpass.ui.components.SwipeRevealRow
import org.onekash.kashpass.ui.components.rememberUndoWindow
import org.onekash.kashpass.ui.format.BackupFormat
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupRetention

/**
 * Shows the Vault backups sheet while [vm] has it open; dismissing it returns to Settings.
 * [onOpenWithPassword] gets a copy that has to open from the lock screen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupsRoute(vm: BackupsViewModel, onOpenWithPassword: (PasswordTarget) -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    val current = state ?: return
    val undoWindow = rememberUndoWindow()
    ModalBottomSheet(
        onDismissRequest = vm::close,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        modifier = Modifier.fillMaxHeight(),
        // The sheet is its own window; SecureOn sets FLAG_SECURE on it whatever the activity sets.
        properties = ModalBottomSheetProperties(securePolicy = SecureFlagPolicy.SecureOn),
    ) {
        BackupsScreen(
            current,
            onSelect = vm::select,
            onKeep = vm::setKeep,
            onDismissAsk = vm::dismissAsk,
            onDelete = { vm.stageDelete(it, undoWindow) },
            onUndo = vm::undoDelete,
            onNoticeShown = vm::noticeShown,
            onOpenWithPassword = { vm.openWithPassword(onOpenWithPassword) },
        )
    }
}

/**
 * Shows the encrypted copies KashPass keeps of the vault, newest first, each by its date and
 * time, under Copies to keep. Picking a copy opens it read-only; a swipe on any copy but the
 * newest stages its delete, with Undo in a snackbar inside the sheet's window.
 */
@Composable
fun BackupsScreen(
    state: BackupsUiState,
    onSelect: (BackupInfo) -> Unit,
    onKeep: (count: Int, confirmed: Int) -> Unit = { _, _ -> },
    onDismissAsk: () -> Unit = {},
    onDelete: (BackupInfo) -> Unit = {},
    onUndo: () -> Unit = {},
    onNoticeShown: () -> Unit = {},
    onOpenWithPassword: () -> Unit = {},
) {
    val snackbar = remember { SnackbarHostState() }
    val resources = LocalResources.current
    // Undo shows while copies are staged; 0 removes it (Undo, or the delete ran).
    LaunchedEffect(state.undo) {
        if (state.undo == 0) {
            snackbar.currentSnackbarData?.dismiss()
            return@LaunchedEffect
        }
        val result = snackbar.showSnackbar(
            resources.getString(R.string.backups_deleted),
            actionLabel = resources.getString(R.string.delete_undo),
            duration = SnackbarDuration.Indefinite,
        )
        if (result == SnackbarResult.ActionPerformed) onUndo()
    }
    // Shown from the screen's scope: clearing the notice changes this effect's key, which must
    // not cancel the snackbar it started.
    val scope = rememberCoroutineScope()
    LaunchedEffect(state.notice) {
        val notice = state.notice ?: return@LaunchedEffect
        val text = resources.getString(
            when (notice) {
                BackupsNotice.PINNED -> R.string.settings_pinned
                BackupsNotice.FAILED -> R.string.backups_delete_failed
            },
        )
        scope.launch { snackbar.showSnackbar(text, duration = SnackbarDuration.Short) }
        onNoticeShown()
    }
    val revealed = remember { RevealedRow() }
    Box(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            Row(Modifier.padding(start = 24.dp, end = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                val title = stringResource(R.string.backups_title)
                Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
                InfoButton(title, stringResource(R.string.backups_intro))
            }
            KeepRow(state, onKeep, onDismissAsk)
            HorizontalDivider(Modifier.padding(top = 8.dp))
            if (state.opening || state.items == null) LinearProgressIndicator(Modifier.fillMaxWidth())
            if (state.failed || state.damaged || state.slow) {
                Column(Modifier.padding(start = 24.dp, end = 24.dp, top = 12.dp)) {
                    Text(
                        stringResource(
                            when {
                                state.damaged -> R.string.backup_damaged
                                state.slow -> R.string.backup_slow_kdf
                                state.oldPassword -> R.string.backups_open_old_password
                                else -> R.string.backups_open_failed
                            },
                        ),
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                    )
                    if (state.passwordTarget != null) {
                        TextButton(onClick = onOpenWithPassword) {
                            Text(stringResource(R.string.backups_open_with_password))
                        }
                    }
                }
            }
            val items = state.items
            when {
                items == null -> Unit
                items.isEmpty() -> Box(Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
                    Text(stringResource(R.string.backups_empty), style = MaterialTheme.typography.bodyLarge)
                }
                else -> LazyColumn(
                    Modifier.weight(1f),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    itemsIndexed(items, key = { _, backup -> backup.id }) { index, backup ->
                        val date = BackupFormat.dateTime(backup.createdAt)
                        // Clipped to the card's corners, so a swipe shows Delete inside its shape.
                        Box(Modifier.clip(CardShape)) {
                            SwipeRevealRow(
                                enabled = state.canDelete && index > 0,
                                open = revealed.openId == backup.id,
                                onOpenChange = { revealed.set(backup.id, it) },
                                deleteLabel = stringResource(R.string.backups_delete, date),
                                onDelete = {
                                    revealed.close()
                                    onDelete(backup)
                                },
                            ) { actions ->
                                BackupCard(date, newest = index == 0, enabled = !state.opening, modifier = actions) { onSelect(backup) }
                            }
                        }
                    }
                }
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter))
    }
}

private val CardShape = RoundedCornerShape(12.dp)

// One copy: its date and time; the newest carries a chip that says why it stays.
@Composable
private fun BackupCard(date: String, newest: Boolean, enabled: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = CardShape,
        color = MaterialTheme.colorScheme.surfaceContainer,
        modifier = modifier.fillMaxWidth(),
    ) {
        Row(Modifier.heightIn(min = 56.dp).padding(start = 16.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(date, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            if (newest) InfoChip(stringResource(R.string.backups_newest), stringResource(R.string.backups_info_newest))
        }
    }
}

// The stepper: plus saves at once; a step down that removes copies shows an inline confirm first.
// TalkBack's adjust action (setProgress) goes through the same rule.
@Composable
private fun KeepRow(state: BackupsUiState, onKeep: (count: Int, confirmed: Int) -> Unit, onDismissAsk: () -> Unit) {
    var tapped by remember { mutableStateOf<Int?>(null) }
    // A refused change (more copies than shown) shows the confirm again with the new count.
    val asking = tapped ?: state.askKeep
    val enabled = state.canChangeBackups
    val keep = state.keep
    val copies = state.items?.size ?: 0
    fun removedFor(next: Int) = (copies - next).coerceAtLeast(0)
    val request: (Int) -> Unit = { wanted ->
        val next = BackupRetention.clamp(wanted)
        val removed = if (next < keep) removedFor(next) else 0
        when {
            next == keep -> Unit
            removed > 0 -> tapped = next
            else -> onKeep(next, 0)
        }
    }
    val count = pluralStringResource(R.plurals.settings_keep_state, keep, keep)
    val title = stringResource(R.string.settings_keep)
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .padding(start = 24.dp, end = 12.dp)
            .semantics(mergeDescendants = true) {
                progressBarRangeInfo = ProgressBarRangeInfo(keep.toFloat(), BackupRetention.MIN_KEEP.toFloat()..BackupRetention.MAX_KEEP.toFloat(), BackupRetention.MAX_KEEP - BackupRetention.MIN_KEEP - 1)
                stateDescription = count
                if (enabled) {
                    setProgress { target ->
                        request(target.roundToInt())
                        true
                    }
                } else {
                    disabled()
                }
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                InfoButton(title, stringResource(R.string.settings_info_keep))
            }
            if (!state.isFile) {
                Text(stringResource(R.string.settings_backup_read_only), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        IconButton(onClick = { request(keep - 1) }, enabled = enabled && keep > BackupRetention.MIN_KEEP) {
            Icon(painterResource(R.drawable.ic_remove), stringResource(R.string.settings_keep_fewer))
        }
        Text("$keep", style = MaterialTheme.typography.titleMedium, modifier = Modifier.width(28.dp), textAlign = TextAlign.Center)
        IconButton(onClick = { request(keep + 1) }, enabled = enabled && keep < BackupRetention.MAX_KEEP) {
            Icon(painterResource(R.drawable.ic_add), stringResource(R.string.settings_keep_more))
        }
    }
    asking?.let { next ->
        val removed = removedFor(next)
        InlineConfirm(
            modifier = Modifier.padding(start = 24.dp),
            // While a save is unverified no copy can go; the line says when it can.
            text = if (state.pinned) stringResource(R.string.settings_pinned) else pluralStringResource(R.plurals.settings_keep_removes, removed, removed),
            action = stringResource(R.string.settings_keep_remove),
            enabled = !state.pinned && !state.applying,
            onCancel = {
                tapped = null
                onDismissAsk()
            },
            onConfirm = {
                tapped = null
                onKeep(next, removed)
            },
        )
    }
}
