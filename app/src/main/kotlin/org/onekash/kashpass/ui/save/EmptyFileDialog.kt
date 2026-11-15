package org.onekash.kashpass.ui.save

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import kotlinx.coroutines.launch
import org.onekash.kashpass.R
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.vault.storage.DeleteResult

/**
 * Offers to delete [location], a file the create-document picker made that holds no verified
 * copy. Delete calls the file's provider ([SaveCoordinator.deleteCopy]); the dialog then shows
 * the result itself, so it reads the same over the lock screen.
 */
@Composable
internal fun EmptyFileDialog(location: String, saves: SaveCoordinator, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    var result by remember(location) { mutableStateOf<Int?>(null) }
    var deleting by remember(location) { mutableStateOf(false) }
    val shown = result
    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        text = { Text(stringResource(shown ?: R.string.copy_failed)) },
        confirmButton = {
            if (shown != null) {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.copy_done)) }
            } else {
                TextButton(enabled = !deleting, onClick = {
                    deleting = true
                    scope.launch {
                        val done = saves.deleteCopy(location)
                        result = if (done == DeleteResult.DELETED) R.string.copy_deleted else R.string.copy_delete_unsupported
                    }
                }) { Text(stringResource(R.string.copy_delete)) }
            }
        },
        dismissButton = {
            if (shown == null) TextButton(onClick = onDismiss) { Text(stringResource(R.string.delete_cancel)) }
        },
    )
}
