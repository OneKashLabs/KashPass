package org.onekash.kashpass.ui.save

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetProperties
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.SecureFlagPolicy
import org.onekash.kashpass.R
import org.onekash.kashpass.ui.format.BackupFormat
import org.onekash.kashpass.ui.format.SaveChoice
import org.onekash.kashpass.ui.format.SaveProblem
import org.onekash.kashpass.session.FileDetails
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.vault.save.SaveResult
import androidx.compose.material3.LinearProgressIndicator

/**
 * Shows the choices after a save that didn't succeed ([SaveProblem.choices]), with the file details
 * when they are loaded. [fileName] names the vault file in the conflict message.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SaveProblemSheet(
    result: SaveResult,
    fileName: String,
    details: FileDetails?,
    onChoice: (SaveChoice) -> Unit,
    onShowDetails: () -> Unit,
    /**
     * True while the app reads or writes the file ([SaveCoordinator.working]); the choices are
     * disabled.
     */
    working: Boolean = false,
) {
    ModalBottomSheet(
        onDismissRequest = { onChoice(SaveChoice.KEEP_EDITING) },
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        // The sheet is its own window; SecureOn sets FLAG_SECURE on it whatever the activity sets.
        properties = ModalBottomSheetProperties(securePolicy = SecureFlagPolicy.SecureOn),
    ) {
        // Swiping the sheet away while a choice runs is allowed: Keep editing clears the problem,
        // and the running job reports its own result.
        if (working) LinearProgressIndicator(Modifier.fillMaxWidth())
        Column(Modifier.padding(horizontal = 24.dp).padding(bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.problem_title), style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
            Text(
                if (result is SaveResult.Conflict) stringResource(R.string.problem_conflict, fileName) else stringResource(SaveProblem.message(result)),
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            for (choice in SaveProblem.choices(result)) {
                val label = stringResource(choice.label())
                if (choice == SaveProblem.choices(result).first()) {
                    FilledTonalButton(onClick = { onChoice(choice) }, enabled = !working, modifier = Modifier.fillMaxWidth()) { Text(label) }
                } else {
                    OutlinedButton(onClick = { onChoice(choice) }, enabled = !working, modifier = Modifier.fillMaxWidth()) { Text(label) }
                }
            }
            if (details == null) {
                TextButton(onClick = onShowDetails) { Text(stringResource(R.string.problem_details)) }
            } else {
                Details(details)
            }
        }
    }
}

@Composable
private fun Details(details: FileDetails) {
    val context = LocalContext.current
    val opened = stringResource(R.string.problem_file_state, BackupFormat.dateTime(details.openedAt), BackupFormat.size(context, details.openedSize))
    Text(stringResource(R.string.problem_opened, opened), style = MaterialTheme.typography.bodyMedium)
    val time = details.nowModified?.let(BackupFormat::dateTime)
    val size = details.nowSize?.let { BackupFormat.size(context, it) }
    // A value the provider doesn't report is left out.
    val now = when {
        time != null && size != null -> stringResource(R.string.problem_file_state, time, size)
        else -> time ?: size
    }
    if (now != null) Text(stringResource(R.string.problem_now, now), style = MaterialTheme.typography.bodyMedium)
}

private fun SaveChoice.label(): Int = when (this) {
    SaveChoice.RETRY -> R.string.problem_retry
    SaveChoice.SAVE_AS_COPY -> R.string.problem_save_copy
    SaveChoice.RELOAD -> R.string.problem_reload
    SaveChoice.KEEP_EDITING -> R.string.problem_keep_editing
}
