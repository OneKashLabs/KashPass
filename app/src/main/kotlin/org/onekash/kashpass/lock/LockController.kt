package org.onekash.kashpass.lock

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.SystemClock
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.onekash.kashpass.session.LostChange
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder

/**
 * Locks on screen off, after [TIMEOUT_MS] in the background or without window focus
 * ([PICKER_TIMEOUT_MS] while a picker KashPass opened is showing), and on request. Every path
 * calls [SessionHolder.lock], which also cancels a running lock-screen unlock (LockViewModel).
 *
 * A lock that arrives while [saves] has a job running covers the vault at once ([covering]),
 * refuses new saves, and waits up to [SAVE_WAIT_MS] for the job to end and its result to be
 * recorded; then it cancels every running job and locks, so nothing keeps the vault or its key. A
 * change that didn't reach the file is reported once on the lock screen ([lostChange]); its bytes
 * are not kept ([SaveCoordinator.cancelRunning]). The pending-save marker covers a write the cancel
 * cut short.
 *
 * The background timer can run late or never in a frozen process, so [onForeground] also compares
 * elapsed time since boot (which counts deep sleep) before any content draws.
 */
class LockController(
    private val sessions: SessionHolder,
    private val scope: CoroutineScope,
    private val elapsed: () -> Long = SystemClock::elapsedRealtime,
    private val saves: SaveCoordinator? = null,
) {
    private var backgroundAt: Long? = null
    private var allowance = TIMEOUT_MS
    private var pickerOpen = false
    private var timer: Job? = null
    private var pending: Job? = null

    private val coveringState = MutableStateFlow(false)
    private val lost = MutableStateFlow<LostChange?>(null)

    /** True from a lock request during a save until the vault is locked; the UI hides the vault. */
    val covering: StateFlow<Boolean> = coveringState.asStateFlow()

    /** Set when the last lock dropped a change that isn't in the file, until the next unlock. */
    val lostChange: StateFlow<LostChange?> = lost.asStateFlow()

    /** Marks a picker as open; call right before KashPass launches a system picker. */
    fun onPickerOpened() {
        pickerOpen = true
    }

    /** Marks the picker as closed; call when it returns, is cancelled or fails to launch. */
    fun onPickerClosed() {
        pickerOpen = false
    }

    /**
     * Call when the app loses window focus or leaves the foreground (not for a configuration
     * change). A call while an away period runs keeps its start time and allowance, so a stop
     * after a focus loss counts from the focus loss.
     */
    fun onBackground() {
        // Save staged deletes at once: a background process can be frozen or stopped.
        saves?.commitStaged()
        if (backgroundAt != null) return
        backgroundAt = elapsed()
        allowance = if (pickerOpen) PICKER_TIMEOUT_MS else TIMEOUT_MS
        timer?.cancel()
        timer = scope.launch {
            delay(allowance)
            lock()
        }
    }

    /**
     * Call when the app returns or regains window focus; locks if it was away for its allowance
     * or more, and ends the away period.
     */
    fun onForeground() {
        timer?.cancel()
        timer = null
        val since = backgroundAt ?: return
        backgroundAt = null
        if (elapsed() - since >= allowance) lock()
    }

    fun onScreenOff() = lock()

    fun lock() {
        timer?.cancel()
        timer = null
        pickerOpen = false
        val coordinator = saves
        // Save staged deletes before locking; the cover waits for that save.
        coordinator?.commitStaged()
        if (coordinator == null || !coordinator.hasRunningJobs) {
            finish(if (coordinator?.lastProblem != null) LostChange.NOT_SAVED else null)
            return
        }
        if (pending?.isActive == true) return
        val save = coordinator.runningSave()
        coordinator.refuseNewSaves()
        // The lock's listener (the clipboard) runs now, not after the wait.
        sessions.announceLock()
        coveringState.value = true
        pending = scope.launch {
            val settled = withTimeoutOrNull(SAVE_WAIT_MS) { coordinator.settle(save) }
            finish(
                when {
                    settled == null -> LostChange.MAYBE_NOT_SAVED
                    settled.lostChange || coordinator.lastProblem != null -> LostChange.NOT_SAVED
                    else -> null
                },
            )
        }
    }

    /** Clears [lostChange]; call when the next unlock shows the vault. */
    fun acknowledgeLostChange() {
        lost.value = null
    }

    private fun finish(lostChange: LostChange?) {
        pending?.cancel()
        pending = null
        saves?.cancelRunning()
        sessions.lock()
        if (lostChange != null) lost.value = lostChange
        coveringState.value = false
    }

    /**
     * Registers for screen off in the application context for the life of the process, so the
     * lock also reaches an unlock in progress. The system sends ACTION_SCREEN_OFF, which a
     * not-exported receiver receives
     * (developer.android.com/develop/background-work/background-tasks/broadcasts).
     */
    fun registerScreenOff(context: Context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action == Intent.ACTION_SCREEN_OFF) onScreenOff()
            }
        }
        ContextCompat.registerReceiver(
            context.applicationContext,
            receiver,
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    companion object {
        const val TIMEOUT_MS = 60_000L

        /** Longest a lock waits for a running save: the deadline of the save's write. */
        const val SAVE_WAIT_MS = 30_000L

        /**
         * Longest time KashPass is away while a picker it opened shows: twice [TIMEOUT_MS], since
         * finding a file in a storage app takes longer than leaving the app.
         */
        const val PICKER_TIMEOUT_MS = 120_000L
    }
}
