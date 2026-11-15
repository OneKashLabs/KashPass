package org.onekash.kashpass

import android.content.ContentResolver
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.viewModels
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import androidx.lifecycle.viewmodel.compose.viewModel
import org.onekash.kashpass.ui.backups.BackupsRoute
import org.onekash.kashpass.ui.backups.BackupsViewModel
import org.onekash.kashpass.ui.browse.BrowseRoute
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.merge
import org.onekash.kashpass.ui.save.SaveProblemHost
import org.onekash.kashpass.ui.edit.EditorNotice
import org.onekash.kashpass.ui.format.UiMessage
import org.onekash.kashpass.ui.edit.EditorRoute
import org.onekash.kashpass.ui.edit.EditorViewModel
import org.onekash.kashpass.ui.lock.LockRoute
import org.onekash.kashpass.ui.settings.SettingsRoute
import org.onekash.kashpass.ui.settings.SettingsViewModel
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import org.onekash.kashpass.ui.lock.LockViewModel
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.ui.save.rememberBackupSaver
import android.net.Uri
import androidx.core.net.toUri
import org.onekash.kashpass.platform.VaultFiles
import org.onekash.kashpass.session.Unlocked

/**
 * Returns the file an Open with intent hands over: the data URI of an ACTION_VIEW intent with the
 * `content` scheme. Anything else is ignored: a `file:` URI, another action, and a launch from
 * Recents ([Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY]), which replays an intent already handled.
 * Extras are never read. The URI is untrusted; it goes through every check of a picked file, and
 * nothing opens without the vault's password or key file. [MainActivityTest] pins it.
 */
internal fun openWithUri(intent: Intent?): Uri? {
    if (intent == null || intent.action != Intent.ACTION_VIEW) return null
    if (intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY != 0) return null
    val data = intent.data ?: return null
    return data.takeIf { it.scheme == ContentResolver.SCHEME_CONTENT }
}

/**
 * Returns true when an Open with intent offers a grant KashPass can keep for reading and writing.
 * The provider's answer when KashPass takes the grant says whether it is kept.
 */
internal fun offersWritableGrant(intent: Intent): Boolean {
    val needed = Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
    return intent.flags and needed == needed
}

/**
 * Returns the name shown for the open file: a session-only file's own name, else the remembered
 * vault's.
 */
internal fun shownFileName(unlocked: Unlocked?, files: VaultFiles): String =
    unlocked?.sessionName ?: files.current()?.displayName.orEmpty()

/**
 * Returns the remembered vault's name when Save as new file would put a copy in its place: the
 * open file is session-only and another vault is remembered. Null otherwise.
 */
internal fun savedCopyReplaces(unlocked: Unlocked?, files: VaultFiles): String? =
    files.current()?.displayName?.takeIf { unlocked?.sessionOnly == true }

class MainActivity : ComponentActivity() {

    // The same instance the lock screen's composition uses (activity scope, default key), so an
    // Open with intent reaches it before the first frame.
    private val lock: LockViewModel by viewModels {
        viewModelFactory { initializer { LockViewModel(graph.files, graph.opener, graph.sessions, graph.biometricUnlock, graph.keyFiles) } }
    }

    // True once the launch intent was handled; kept across recreation, so a rotation or a restart
    // after process death doesn't hand the same file over again.
    private var launchIntentHandled = false

    override fun onCreate(savedInstanceState: Bundle?) {
        // Set in onCreate, before the first frame, so no frame reaches screenshots,
        // screen recording or the recents thumbnail. MainActivityTest pins it.
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        // Other apps' overlay windows are hidden while this window shows, so none can sit over
        // a button to trick a tap (tapjacking). The permission is granted at install; without it
        // Android throws, and the app opens anyway.
        try {
            window.setHideOverlayWindows(true)
        } catch (e: SecurityException) {
            // Defence in depth: FLAG_SECURE and the lock apply without it.
        }
        // No autofill service fills or offers to save anything typed here. The text fields also
        // set noAutofill(), since Compose reports fields by data type whatever this says.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        launchIntentHandled = savedInstanceState?.getBoolean(KEY_LAUNCH_INTENT_HANDLED) == true
        if (!launchIntentHandled) handleOpenWith(intent)
        launchIntentHandled = true
        showContent()
        // A stopped activity doesn't recompose, so its composition would keep the last unlocked
        // screen (rows, the open entry) after a lock until the user returns. A lock while stopped
        // removes the content, which disposes the composition; onStart builds it again.
        lifecycleScope.launch {
            graph.sessions.current.collect { unlocked ->
                if (unlocked == null && contentShown && !lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                    findViewById<ViewGroup>(android.R.id.content).removeAllViews()
                    contentShown = false
                }
            }
        }
    }

    private var contentShown = false

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_LAUNCH_INTENT_HANDLED, launchIntentHandled)
    }

    // singleTask: an Open with intent while KashPass runs arrives here, in the existing task.
    public override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Not passed to setIntent: nothing reads getIntent after onCreate, and the launch intent
        // stays the one the handled flag in the saved state describes.
        handleOpenWith(intent)
    }

    // An unlocked vault stays as it is; the lock screen offers the file after the next lock.
    private fun handleOpenWith(intent: Intent?) {
        val uri = openWithUri(intent ?: return) ?: return
        lock.onIncoming(uri, offersWritableGrant(intent))
    }

    private fun showContent() {
        val graph = graph
        setContent {
            KashPassTheme {
                val unlocked by graph.sessions.current.collectAsStateWithLifecycle()
                val covering by graph.locker.covering.collectAsStateWithLifecycle()
                val lostChange by graph.locker.lostChange.collectAsStateWithLifecycle()
                LaunchedEffect(unlocked) { if (unlocked != null) graph.locker.acknowledgeLostChange() }
                // Activity-scoped, so a configuration change keeps an edit in progress.
                val editor = viewModel { EditorViewModel(graph.sessions, graph.saves) }
                val editing by editor.state.collectAsStateWithLifecycle()
                // Remembered: a new flow on each recomposition would restart collection and drop
                // messages.
                val rootMessages = remember { MutableSharedFlow<UiMessage>(extraBufferCapacity = 4) }
                val messages = remember(editor) {
                    merge(
                        rootMessages,
                        editor.messages.map { notice ->
                            when (notice) {
                                EditorNotice.UPDATED -> UiMessage(getString(R.string.notice_updated))
                                EditorNotice.ENTRY_GONE -> UiMessage(getString(R.string.notice_entry_gone))
                                EditorNotice.CHECK_FAILED -> UiMessage(getString(R.string.notice_check_failed))
                                EditorNotice.SLOW -> UiMessage(getString(R.string.notice_slow_kdf))
                                EditorNotice.TIMED_OUT -> UiMessage(getString(R.string.error_timed_out_short), getString(R.string.action_try_again), editor::retryCheck)
                                EditorNotice.SAVED -> UiMessage(getString(R.string.notice_saved))
                            }
                        },
                    )
                }
                // Hosted whether locked or not, so a picker result after process death arrives.
                SaveProblemHost(
                    saves = graph.saves,
                    fileName = shownFileName(unlocked, graph.files),
                    onEditsDropped = editor::close,
                    onMessage = { rootMessages.tryEmit(UiMessage(it)) },
                    hidden = covering,
                    onPickerOpened = graph.locker::onPickerOpened,
                    onPickerClosed = graph.locker::onPickerClosed,
                )
                val fileName = { shownFileName(graph.sessions.current.value, graph.files) }
                val backups = viewModel { BackupsViewModel(graph.sessions, graph.saves, graph.opener, graph.backupSettings) }
                // A verified copy becomes the vault: the app locks and the lock screen checks it.
                val saveAsNewFile = rememberBackupSaver(
                    saves = graph.saves,
                    fileName = fileName,
                    // Null for a file read-only for its grant; its copy is named with today's date.
                    backupTime = { graph.sessions.current.value?.backup?.createdAt },
                    onSaved = { location ->
                        graph.locker.lock()
                        lock.useFile(location.toUri())
                    },
                    onMessage = { rootMessages.tryEmit(UiMessage(it)) },
                    onPickerOpened = graph.locker::onPickerOpened,
                    onPickerClosed = graph.locker::onPickerClosed,
                )
                val settings = viewModel {
                    SettingsViewModel(graph.sessions, graph.biometricUnlock, fileName = fileName)
                }
                val settingsState by settings.state.collectAsStateWithLifecycle()
                // The sheet sits on Settings. When Settings closes (a lock, a switch to a
                // backup) the sheet closes too, so it doesn't reappear when Settings opens again.
                val settingsOpen = settingsState != null
                LaunchedEffect(settingsOpen) { if (!settingsOpen) backups.close() }
                // The cover comes first: nothing behind it, Settings and the Vault backups sheet
                // included, can act on the session that is about to lock.
                when {
                    covering -> LockRoute(graph.files, graph.opener, graph.sessions, finishingSave = true)
                    unlocked == null -> LockRoute(
                        graph.files, graph.opener, graph.sessions, lostChange = lostChange,
                        biometric = graph.biometricUnlock, availability = graph.biometrics,
                        keyFiles = graph.keyFiles,
                        onPickerOpened = graph.locker::onPickerOpened,
                        onPickerClosed = graph.locker::onPickerClosed,
                    )
                    editing != null -> EditorRoute(editor)
                    else -> Box(Modifier.fillMaxSize()) {
                        BrowseRoute(
                            sessions = graph.sessions,
                            opener = graph.opener,
                            copyToClipboard = graph.clipboard::copy,
                            messages = messages,
                            onEdit = editor::startEdit,
                            onAdd = editor::startAdd,
                            saves = graph.saves,
                            onOpenSettings = settings::open,
                            biometric = graph.biometricUnlock,
                            availability = graph.biometrics,
                            fileName = fileName,
                            onSaveAsNewFile = saveAsNewFile,
                            saveAsNewReplaces = { savedCopyReplaces(graph.sessions.current.value, graph.files) },
                        )
                        // Settings slides in from the trailing edge and reverses on back. The
                        // offset flips in RTL.
                        val sign = if (LocalLayoutDirection.current == LayoutDirection.Rtl) -1 else 1
                        AnimatedVisibility(
                            visible = settingsState != null,
                            enter = slideInHorizontally { width -> sign * width } + fadeIn(),
                            exit = slideOutHorizontally { width -> sign * width } + fadeOut(),
                        ) {
                            Surface(Modifier.fillMaxSize()) {
                                SettingsRoute(
                                    vm = settings,
                                    availability = graph.biometrics,
                                    onLock = graph.locker::lock,
                                    onBackups = backups::show,
                                    onChooseFile = {
                                        // Locks; the lock screen opens the picker once it shows,
                                        // in a session-only file's folder.
                                        settings.close()
                                        lock.requestPick(graph.sessions.current.value?.takeIf { it.sessionOnly }?.location?.toUri())
                                        graph.locker.lock()
                                    },
                                )
                                BackupsRoute(backups) { target ->
                                    // Locks; the lock screen then shows that copy's password field.
                                    settings.close()
                                    lock.requestBackup(target.backup, target.slow)
                                    graph.locker.lock()
                                }
                            }
                        }
                    }
                }
            }
        }
        contentShown = true
    }

    // onStart runs before the returning activity draws, so an expired session never shows.
    override fun onStart() {
        super.onStart()
        enterForeground()
        if (!contentShown) showContent()
    }

    private fun enterForeground() {
        graph.inForeground = true
        graph.locker.onForeground()
        graph.clipboard.clearIfDue()
    }

    // Android 10+ refuses the clipboard to a window without focus or in the background, so the
    // clipboard uses its background rule.
    private fun leaveForeground() {
        graph.inForeground = false
        graph.locker.onBackground()
    }

    // In split screen and desktop windows the activity stays resumed while another window has
    // focus, so onStop doesn't run. Losing the top resumed position starts the same away period;
    // KashPass's own picker sets its allowance before it launches. A configuration change regains
    // focus in the new activity, whose onStart ends the away period.
    // (developer.android.com/develop/adaptive-apps/guides/support-multi-window-mode)
    override fun onTopResumedActivityChanged(isTopResumedActivity: Boolean) {
        super.onTopResumedActivityChanged(isTopResumedActivity)
        if (isTopResumedActivity) {
            enterForeground()
        } else if (!isChangingConfigurations) {
            leaveForeground()
        }
    }

    // A configuration change stops and recreates the activity without leaving the app.
    override fun onStop() {
        super.onStop()
        if (isChangingConfigurations) return
        leaveForeground()
        // Every running save, including the staged-delete commit onBackground started, gets an
        // expedited job so the process isn't frozen before the save ends.
        SaveKeepAlive.scheduleIfBusy(this, graph.saves.busy.value)
    }

    private companion object {
        const val KEY_LAUNCH_INTENT_HANDLED = "launch_intent_handled"
    }
}
