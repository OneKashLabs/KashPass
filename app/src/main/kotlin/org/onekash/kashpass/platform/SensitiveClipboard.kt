package org.onekash.kashpass.platform

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.PersistableBundle
import android.os.SystemClock
import androidx.core.content.edit
import java.security.SecureRandom
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Schedules the system alarm that wakes KashPass to clear the clipboard. */
interface ClearAlarm {
    fun schedule(atMillis: Long)
    fun cancel()
}

/**
 * Schedules an inexact wall-clock alarm (`setAndAllowWhileIdle`, no exact-alarm permission) to
 * [receiver], which calls [SensitiveClipboard.clearIfDue]. The intent is explicit, immutable and
 * carries no extras.
 */
class AlarmClearAlarm(
    private val context: Context,
    private val receiver: Class<out BroadcastReceiver>,
) : ClearAlarm {

    private val alarms = context.getSystemService(AlarmManager::class.java)

    private fun intent() = PendingIntent.getBroadcast(
        context,
        0,
        Intent(context, receiver),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    override fun schedule(atMillis: Long) = alarms.setAndAllowWhileIdle(AlarmManager.RTC, atMillis, intent())

    override fun cancel() = alarms.cancel(intent())
}

/** Stores the pending clear: when it is due and the random label of the clip it belongs to. */
class ClipboardDeadlineStore(context: Context) {

    data class Deadline(val atMillis: Long, val label: String)

    private val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun read(): Deadline? {
        val label = prefs.getString(KEY_LABEL, null) ?: return null
        return Deadline(prefs.getLong(KEY_DEADLINE, 0L), label)
    }

    fun write(deadline: Deadline) = prefs.edit {
        putLong(KEY_DEADLINE, deadline.atMillis)
        putString(KEY_LABEL, deadline.label)
    }

    fun clear() = prefs.edit { clear() }

    companion object {
        const val FILE = "kashpass_clipboard"
        const val KEY_DEADLINE = "deadline_wall_ms"
        const val KEY_LABEL = "clip_label"
    }
}

/**
 * Copies values marked sensitive and clears them [TIMEOUT_MS] later, best effort: an in-process
 * timer while KashPass runs, a [ClearAlarm] that wakes a frozen process, and [clearIfDue] on every
 * start. In the foreground a clip that another app or the user replaced is left in place. A clip
 * KashPass can't read is cleared regardless: Android 10+ hides the clip from an app in the
 * background or without window focus. A deadline from before the current boot is dropped without
 * clearing, because Android empties the clipboard on reboot. No method throws: a clear that fails
 * keeps the deadline and the alarm, so the alarm, the next start or the next lock tries again.
 */
class SensitiveClipboard(
    private val clipboard: ClipboardManager,
    private val deadlines: ClipboardDeadlineStore,
    private val alarm: ClearAlarm,
    private val scope: CoroutineScope,
    private val now: () -> Long = System::currentTimeMillis,
    private val bootedAt: () -> Long = { System.currentTimeMillis() - SystemClock.elapsedRealtime() },
    private val isForeground: () -> Boolean,
) {
    private var timer: Job? = null

    /**
     * Puts [text] on the clipboard, marked sensitive, and schedules its clear. The clip label is a
     * random tag: other apps can read labels, and field names are vault content. Returns false,
     * with nothing scheduled, when the system refuses the clip (one over the binder transaction
     * limit, such as a very long note). Returns false also when the clear can't be scheduled; the
     * clip is then taken off the clipboard.
     */
    fun copy(text: String): Boolean {
        val clipLabel = "KashPass ${randomTag()}"
        try {
            val clip = ClipData.newPlainText(clipLabel, text)
            clip.description.extras = PersistableBundle().apply { putBoolean(SENSITIVE_KEY, true) }
            clipboard.setPrimaryClip(clip)
        } catch (e: Exception) {
            return false
        }
        return try {
            scheduleClear(clipLabel)
            true
        } catch (e: Exception) {
            withdraw()
            false
        }
    }

    private fun scheduleClear(clipLabel: String) {
        val at = now() + TIMEOUT_MS
        deadlines.write(ClipboardDeadlineStore.Deadline(at, clipLabel))
        alarm.cancel()
        alarm.schedule(at)
        timer?.cancel()
        timer = scope.launch {
            delay(TIMEOUT_MS)
            clearIfDue()
        }
    }

    // Takes a clip whose clear couldn't be scheduled off the clipboard. When that fails too, a
    // deadline already written stays, so the next start or lock clears the clip.
    private fun withdraw() {
        try {
            clipboard.clearPrimaryClip()
            forget()
        } catch (e: Exception) {
            // Nothing else to try.
        }
    }

    /** Clears the clipboard when a pending deadline has passed; see the class rules. */
    fun clearIfDue() = clearPending(force = false)

    /**
     * Clears a pending KashPass clip now, by the same rules as at its deadline, for a lock. Without
     * a pending deadline nothing is touched.
     */
    fun clearForLock() = clearPending(force = true)

    // [force] clears before the deadline. The foreground, background and failure rules are the
    // class's.
    private fun clearPending(force: Boolean) {
        try {
            val deadline = deadlines.read() ?: return
            val copiedBeforeBoot = deadline.atMillis - TIMEOUT_MS < bootedAt()
            if (!copiedBeforeBoot) {
                if (!force && now() < deadline.atMillis) return
                val label = readableLabel()
                if (!isForeground() || label == null || label == deadline.label) clipboard.clearPrimaryClip()
            }
            forget()
        } catch (e: Exception) {
            // The deadline and the alarm stay for the next try.
        }
    }

    // The primary clip's label, or null when KashPass can't read it (the read is refused or
    // throws), which the class rules treat as a clip to clear.
    private fun readableLabel(): String? = try {
        clipboard.primaryClipDescription?.label?.toString()
    } catch (e: Exception) {
        null
    }

    private fun forget() {
        timer?.cancel()
        timer = null
        deadlines.clear()
        alarm.cancel()
    }

    private fun randomTag(): String = ByteArray(6).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }

    companion object {
        const val TIMEOUT_MS = 30_000L

        // The value of ClipDescription.EXTRA_IS_SENSITIVE (API 33), which keyboards on Android 12
        // also honour; the literal avoids an API 33 reference on minSdk 31
        // (developer.android.com/privacy-and-security/risks/secure-clipboard-handling).
        const val SENSITIVE_KEY = "android.content.extra.IS_SENSITIVE"
    }
}

