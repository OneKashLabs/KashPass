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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.time.LocalDateTime
import kotlinx.coroutines.launch
import org.onekash.kashpass.R
import org.onekash.kashpass.ui.format.SaveChoice
import org.onekash.kashpass.ui.format.SaveProblem
import org.onekash.kashpass.session.FileDetails
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.save.CopyResult

/**
 * Shows the choices after a save that didn't succeed, over whatever screen is up, and runs them.
 * Hosted at the root of the activity, so the create-document picker's result also arrives after
 * the process was killed: the vault is locked then, and a file the picker created is offered for
 * deletion, since nothing was written into it. [onEditsDropped] closes the editor after a copy or
 * a reload; [onMessage] shows a message once.
 */
@Composable
fun SaveProblemHost(
    saves: SaveCoordinator,
    fileName: String,
    onEditsDropped: () -> Unit,
    onMessage: (String) -> Unit,
    /** True while the lock screen covers a save that is ending; the sheet stays hidden. */
    hidden: Boolean = false,
    /** Brackets the create-document picker, so the lock allows longer away while it shows. */
    onPickerOpened: () -> Unit = {},
    onPickerClosed: () -> Unit = {},
) {
    val resources = LocalResources.current
    val scope = rememberCoroutineScope()
    val problem by saves.problem.collectAsStateWithLifecycle()
    val working by saves.working.collectAsStateWithLifecycle()
    var details by remember { mutableStateOf<FileDetails?>(null) }
    var emptyFile by remember { mutableStateOf<String?>(null) }

    val createCopy = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        onPickerClosed()
        val location = uri?.toString() ?: return@rememberLauncherForActivityResult
        scope.launch {
            when (val copied = saves.saveCopy(location)) {
                is CopyResult.Saved -> {
                    saves.clearProblem()
                    onEditsDropped()
                    onMessage(copied.displayName?.let { resources.getString(R.string.copy_saved, it) } ?: resources.getString(R.string.copy_saved_unnamed))
                }
                is CopyResult.Failed -> emptyFile = copied.location
                is CopyResult.Refused -> onMessage(resources.getString(R.string.copy_refused))
                // Nothing to copy (the vault locked, or the process restarted): the file is empty.
                null -> emptyFile = location
            }
        }
    }

    val current = problem
    if (current != null && !SaveProblem.inline(current) && !hidden) {
        SaveProblemSheet(
            result = current,
            fileName = fileName,
            details = details,
            onChoice = { choice ->
                details = null
                when (choice) {
                    SaveChoice.RETRY -> scope.launch { saves.retry().await() }
                    SaveChoice.SAVE_AS_COPY -> {
                        onPickerOpened()
                        try {
                            createCopy.launch(SaveProblem.copyName(resources.getString(R.string.copy_name), resources.getString(R.string.copy_name_fallback), fileName, LocalDateTime.now()))
                        } catch (e: ActivityNotFoundException) {
                            // No app on the phone can create a document.
                            onPickerClosed()
                            onMessage(resources.getString(R.string.copy_no_picker))
                        }
                    }
                    SaveChoice.RELOAD -> scope.launch {
                        when (saves.reload()) {
                            // A lock ran first: the editor closes itself on a lock, and an editor
                            // opened after a new unlock is not this edit's.
                            null -> Unit
                            // A file that became far slower to unlock isn't derived; the edit
                            // stays.
                            is OpenResult.TooSlow -> onMessage(resources.getString(R.string.notice_slow_kdf))
                            else -> onEditsDropped()
                        }
                    }
                    SaveChoice.KEEP_EDITING -> saves.clearProblem()
                }
            },
            onShowDetails = { scope.launch { details = saves.fileDetails() } },
            working = working,
        )
    }

    emptyFile?.let { location -> EmptyFileDialog(location, saves) { emptyFile = null } }
}
