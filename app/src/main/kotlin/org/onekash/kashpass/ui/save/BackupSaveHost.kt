package org.onekash.kashpass.ui.save

import android.content.ActivityNotFoundException
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalResources
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.onekash.kashpass.R
import org.onekash.kashpass.session.SaveBackupResult
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.ui.format.SaveProblem

/**
 * Runs Save as new file for the open backup or read-only file and returns the function that starts
 * it: the create-document picker, the write ([SaveCoordinator.saveBackupAsNewFile]) and, when the
 * picker's file holds no verified copy, the offer to delete it. [backupTime] is the open backup's
 * time, null for a read-only file; it names the new file. Hosted at the activity root, so a
 * picker result after a process death arrives. [onSaved] receives the new file after a verified
 * write. The picker leaves the app, so [onPickerOpened] and [onPickerClosed] bracket it for the
 * lock's away timer. [BackupSaveHostTest] pins it.
 */
@Composable
fun rememberBackupSaver(
    saves: SaveCoordinator,
    fileName: () -> String,
    backupTime: () -> Instant?,
    onSaved: (location: String) -> Unit,
    onMessage: (String) -> Unit,
    onPickerOpened: () -> Unit = {},
    onPickerClosed: () -> Unit = {},
): () -> Unit {
    val resources = LocalResources.current
    val scope = rememberCoroutineScope()
    var emptyFile by remember { mutableStateOf<String?>(null) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        onPickerClosed()
        val location = uri?.toString() ?: return@rememberLauncherForActivityResult
        scope.launch {
            val result = try {
                saves.saveBackupAsNewFile(location)
            } catch (e: CancellationException) {
                // A lock cancels the save; the provider's write can finish, so the file can hold
                // part or all of the copy. When this host's own scope ends, nothing is shown.
                if (!currentCoroutineContext().isActive) throw e
                null
            }
            when (result) {
                is SaveBackupResult.Saved -> onSaved(location)
                SaveBackupResult.BackupDamaged -> {
                    onMessage(resources.getString(R.string.backup_damaged))
                    emptyFile = location
                }
                SaveBackupResult.FileChanged -> {
                    onMessage(resources.getString(R.string.copy_file_changed))
                    emptyFile = location
                }
                is SaveBackupResult.Failed, null -> emptyFile = location
                SaveBackupResult.Refused -> onMessage(resources.getString(R.string.copy_refused))
            }
        }
    }
    emptyFile?.let { location -> EmptyFileDialog(location, saves) { emptyFile = null } }
    return {
        val backup = backupTime()
        val time = LocalDateTime.ofInstant(backup ?: Instant.now(), ZoneId.systemDefault())
        val pattern = resources.getString(if (backup != null) R.string.backup_file_name else R.string.read_only_copy_name)
        val name = SaveProblem.copyName(pattern, resources.getString(R.string.copy_name_fallback), fileName(), time)
        onPickerOpened()
        try {
            launcher.launch(name)
        } catch (e: ActivityNotFoundException) {
            onPickerClosed()
            onMessage(resources.getString(R.string.copy_no_picker))
        }
    }
}
