package org.onekash.kashpass.platform

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.checkAll
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.testing.RecordingAlarm
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Random sequences of copy, another app replacing the clip, foreground and background, the clip
 * becoming unreadable to KashPass, time passing, a frozen process, a process restart, a reboot,
 * a lock and the alarm firing, against [SensitiveClipboard] on Robolectric's clipboard. A model of
 * the clear rules predicts the clipboard, the stored deadline and the alarm after each event, and
 * every clip KashPass puts on the clipboard is marked sensitive under a random label.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(shadows = [UnreadableClipboardShadow::class])
class SensitiveClipboardProperties {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val clipboard = context.getSystemService(ClipboardManager::class.java)

    @Test
    fun `the clipboard is cleared exactly when the clear rules say`() = runBlocking<Unit> {
        val counts = sortedMapOf<String, Int>()
        checkAll(PropertyRuns.config(iterations = 1_000), EVENTS) { events ->
            Rig(counts).use { rig -> events.forEach { rig.apply(it) } }
        }
        val missing = COVERAGE.filter { (counts[it] ?: 0) == 0 }
        assertTrue("never reached: $missing (reached: $counts)", missing.isEmpty())
    }

    sealed interface Event {
        data class Copy(val text: String) : Event
        data class Replace(val text: String) : Event
        data object Foreground : Event
        data object Background : Event
        data object Unreadable : Event
        data object Readable : Event
        data class Time(val ms: Long) : Event
        data class Freeze(val ms: Long) : Event
        data object Restart : Event
        data object Reboot : Event
        data object Lock : Event
        data object AlarmFires : Event
    }

    private class Clip(val text: String, val label: String)

    private class Deadline(val at: Long, val label: String)

    private inner class Rig(private val counts: MutableMap<String, Int>) : AutoCloseable {
        private val scope = TestScope(StandardTestDispatcher())
        private val deadlines = ClipboardDeadlineStore(context)
        private val alarm = RecordingAlarm()
        private var skew = 0L
        private var foreground = true
        private var bootedAt = 0L
        private var process = Job()
        private var instance = newInstance()
        private val labels = mutableSetOf<String>()

        // The model.
        private var clip: Clip? = null
        private var deadline: Deadline? = null
        private var timerAt: Long? = null
        private var alarmAt: Long? = null
        private var unreadable = false

        init {
            UnreadableClipboardShadow.denyRead = false
            clipboard.clearPrimaryClip()
            deadlines.clear()
        }

        private fun now() = START + scope.testScheduler.currentTime + skew

        private fun newInstance() = SensitiveClipboard(
            clipboard,
            deadlines,
            alarm,
            CoroutineScope(scope.coroutineContext + process),
            now = ::now,
            bootedAt = { bootedAt },
            isForeground = { foreground },
        )

        fun apply(event: Event) {
            when (event) {
                is Event.Copy -> copy(event.text)
                is Event.Replace -> {
                    clipboard.setPrimaryClip(ClipData.newPlainText("other", event.text))
                    clip = Clip(event.text, "other")
                }
                Event.Foreground -> foreground = true
                Event.Background -> foreground = false
                Event.Unreadable -> {
                    UnreadableClipboardShadow.denyRead = true
                    unreadable = true
                }
                Event.Readable -> {
                    UnreadableClipboardShadow.denyRead = false
                    unreadable = false
                }
                is Event.Time -> time(event.ms)
                is Event.Freeze -> skew += event.ms
                Event.Restart -> restart("start")
                Event.Reboot -> {
                    bootedAt = now()
                    clipboard.clearPrimaryClip()
                    clip = null
                    alarm.pending = null
                    alarmAt = null
                    restart("start after reboot")
                }
                Event.Lock -> {
                    instance.clearForLock()
                    clear(force = true, "lock")
                }
                Event.AlarmFires -> {
                    val at = alarmAt
                    if (at != null && now() >= at) {
                        instance.clearIfDue()
                        clear(force = false, "alarm")
                    }
                }
            }
            scope.runCurrent()
            check()
        }

        private fun copy(text: String) {
            assertTrue(instance.copy(text))
            val description = withRead { clipboard.primaryClipDescription!! }
            val label = description.label.toString()
            assertTrue("random label: $label", LABEL.matches(label))
            assertNotEquals("the label is not the text", text, label)
            assertTrue("a new label for each copy", labels.add(label))
            assertTrue("marked sensitive", description.extras!!.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE))
            assertTrue("marked sensitive under the string key", description.extras!!.getBoolean(SensitiveClipboard.SENSITIVE_KEY))
            clip = Clip(text, label)
            deadline = Deadline(now() + SensitiveClipboard.TIMEOUT_MS, label)
            alarmAt = deadline!!.at
            timerAt = scope.testScheduler.currentTime + SensitiveClipboard.TIMEOUT_MS
            count("copy")
        }

        // A new process: the old one's timer is gone, and the start calls clearIfDue.
        private fun restart(cause: String) {
            process.cancel()
            process = Job()
            instance = newInstance()
            timerAt = null
            instance.clearIfDue()
            clear(force = false, cause)
        }

        private fun time(ms: Long) {
            val target = scope.testScheduler.currentTime + ms
            val timer = timerAt
            if (timer != null && timer <= target) {
                scope.advanceTimeBy(timer - scope.testScheduler.currentTime)
                scope.runCurrent()
                timerAt = null
                clear(force = false, "timer")
                check()
            }
            scope.advanceTimeBy(target - scope.testScheduler.currentTime)
        }

        // The model's clearPending: a deadline copied before this boot is dropped without
        // clearing; otherwise, when due or forced, the clip is cleared unless KashPass is in the
        // foreground and reads another label than its own.
        private fun clear(force: Boolean, cause: String) {
            val pending = deadline ?: return
            val copiedBeforeBoot = pending.at - SensitiveClipboard.TIMEOUT_MS < bootedAt
            if (copiedBeforeBoot) {
                count("dropped after reboot ($cause)")
            } else {
                if (!force && now() < pending.at) return
                val label = if (unreadable) null else clip?.label
                when {
                    clip == null -> count("nothing left to clear ($cause)")
                    !foreground -> count("cleared in the background${if (label != pending.label) ", replaced or unreadable" else ""} ($cause)")
                    label == null -> count("cleared because unreadable ($cause)")
                    label == pending.label -> count("cleared ($cause)")
                    else -> count("replaced clip left in the foreground ($cause)")
                }
                if (!foreground || label == null || label == pending.label) clip = null
            }
            deadline = null
            timerAt = null
            alarmAt = null
        }

        private fun check() {
            val actual = withRead { clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString() }
            assertEquals("clipboard", clip?.text, actual)
            val stored = deadlines.read()
            assertEquals("deadline", deadline?.at, stored?.atMillis)
            assertEquals("deadline label", deadline?.label, stored?.label)
            assertEquals("alarm", alarmAt, alarm.pending)
        }

        private fun <T> withRead(block: () -> T): T {
            val deny = UnreadableClipboardShadow.denyRead
            UnreadableClipboardShadow.denyRead = false
            try {
                return block()
            } finally {
                UnreadableClipboardShadow.denyRead = deny
            }
        }

        private fun count(name: String) {
            counts[name] = (counts[name] ?: 0) + 1
        }

        override fun close() {
            UnreadableClipboardShadow.denyRead = false
            scope.cancel()
        }
    }

    private companion object {
        const val START = 1_700_000_000_000L
        val LABEL = Regex("KashPass [0-9a-f]{12}")

        val TEXTS = listOf("b@nk-p4ss", "", "KashPass 000000000000", "x".repeat(2_000), "ünïcödé 漢字 😀", "other")
        val TIMES = listOf(1_000L, 29_999L, 30_000L, 30_001L, 60_000L, 120_000L)

        // Any text, with the edge cases above often.
        val TEXT: Arb<String> = Arb.choice(Arb.element(TEXTS), Generators.anyText)

        val EVENTS: Arb<List<Event>> = Arb.list(Arb.bind(Arb.int(0..89), Arb.int(0..1_000), TEXT) { k, p, text -> event(k, p, text) }, 1..25)

        fun event(k: Int, p: Int, text: String): Event = when {
            k < 14 -> Event.Copy(text)
            k < 22 -> Event.Replace(text)
            k < 30 -> Event.Foreground
            k < 38 -> Event.Background
            k < 43 -> Event.Unreadable
            k < 48 -> Event.Readable
            k < 62 -> Event.Time(TIMES[p % TIMES.size])
            k < 67 -> Event.Freeze(TIMES[p % TIMES.size])
            k < 72 -> Event.Restart
            k < 75 -> Event.Reboot
            k < 81 -> Event.Lock
            else -> Event.AlarmFires
        }

        val COVERAGE = listOf(
            "copy", "cleared (timer)", "cleared (alarm)", "cleared (start)", "cleared (lock)",
            "replaced clip left in the foreground (timer)", "replaced clip left in the foreground (lock)",
            "cleared in the background, replaced or unreadable (timer)", "cleared because unreadable (timer)",
            "cleared because unreadable (lock)", "dropped after reboot (start after reboot)",
        )
    }
}
