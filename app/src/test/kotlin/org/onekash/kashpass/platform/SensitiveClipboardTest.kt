package org.onekash.kashpass.platform

import android.app.AlarmManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.TransactionTooLargeException
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ClipboardClearReceiver
import org.onekash.kashpass.testing.RecordingAlarm
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.shadows.ShadowClipboardManager
import org.robolectric.shadows.ShadowSystemClock
import java.time.Duration

/** Throws on every set, as the system does for a clip over the binder transaction limit. */
@Implements(ClipboardManager::class)
class RefusingClipboardShadow : ShadowClipboardManager() {
    @Implementation
    override fun setPrimaryClip(clip: ClipData) = throw RuntimeException(TransactionTooLargeException("clip too large"))
}

/** Refuses clipboard reads while [denyRead] is set, as Android does for an unfocused window. */
@Implements(ClipboardManager::class)
class UnreadableClipboardShadow : ShadowClipboardManager() {
    @Implementation
    override fun getPrimaryClipDescription(): ClipDescription? = if (denyRead) null else super.getPrimaryClipDescription()

    @Implementation
    override fun getPrimaryClip(): ClipData? = if (denyRead) null else super.getPrimaryClip()

    companion object {
        @JvmStatic
        var denyRead = false
    }
}

/** Throws on clear while [failClear] is set and on reading the label while [failRead] is set. */
@Implements(ClipboardManager::class)
class ThrowingClipboardShadow : ShadowClipboardManager() {
    @Implementation
    override fun clearPrimaryClip() = if (failClear) throw SecurityException("clear") else super.clearPrimaryClip()

    @Implementation
    override fun getPrimaryClipDescription(): ClipDescription? = if (failRead) throw SecurityException("read") else super.getPrimaryClipDescription()

    companion object {
        @JvmStatic
        var failClear = false

        @JvmStatic
        var failRead = false
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class SensitiveClipboardTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val clipboard = context.getSystemService(ClipboardManager::class.java)
    private val scope = TestScope(StandardTestDispatcher())
    private var foreground = true
    private val start = 1_700_000_000_000L
    private val alarm = RecordingAlarm()
    private val deadlines = ClipboardDeadlineStore(context)

    private fun now() = start + scope.testScheduler.currentTime

    // The current boot started long before every copy in these tests unless a test says otherwise.
    private var bootedAt = 0L

    private fun newClipboard() = SensitiveClipboard(
        clipboard,
        deadlines,
        alarm,
        scope,
        now = ::now,
        bootedAt = { bootedAt },
        isForeground = { foreground },
    )

    private fun clipText(): String? = clipboard.primaryClip?.getItemAt(0)?.text?.toString()

    @Test
    fun `a copy is marked sensitive under the EXTRA_IS_SENSITIVE key`() {
        newClipboard().copy("b@nk-p4ss")
        val extras = clipboard.primaryClipDescription!!.extras!!
        assertEquals(ClipDescription.EXTRA_IS_SENSITIVE, SensitiveClipboard.SENSITIVE_KEY)
        assertTrue(extras.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE))
        assertEquals("b@nk-p4ss", clipText())
    }

    @Test
    fun `the clip is cleared 30 seconds after the copy`() {
        newClipboard().copy("b@nk-p4ss")
        scope.advanceTimeBy(29_999)
        scope.runCurrent()
        assertEquals("b@nk-p4ss", clipText())
        scope.advanceTimeBy(2)
        scope.runCurrent()
        assertNull(clipText())
        assertNull(deadlines.read())
    }

    @Test
    fun `in the foreground a clip someone replaced is left alone`() {
        newClipboard().copy("b@nk-p4ss")
        clipboard.setPrimaryClip(ClipData.newPlainText("other", "my note"))
        scope.advanceTimeBy(30_001)
        scope.runCurrent()
        assertEquals("my note", clipText())
    }

    @Test
    fun `in the background the clip is cleared at the deadline, replaced or not`() {
        newClipboard().copy("b@nk-p4ss")
        foreground = false
        clipboard.setPrimaryClip(ClipData.newPlainText("other", "my note"))
        scope.advanceTimeBy(30_001)
        scope.runCurrent()
        assertNull(clipText())
    }

    @Test
    fun `each copy schedules the backup alarm at the deadline and replaces the previous one`() {
        val clip = newClipboard()
        clip.copy("alice")
        scope.advanceTimeBy(5_000)
        clip.copy("b@nk-p4ss")
        assertEquals(listOf(start + 30_000, start + 35_000), alarm.scheduled)
        assertEquals(2, alarm.cancels)
    }

    @Test
    fun `after a restart an overdue deadline clears our clip when KashPass next runs`() {
        newClipboard().copy("b@nk-p4ss")
        val restarted = SensitiveClipboard(clipboard, ClipboardDeadlineStore(context), alarm, TestScope(), now = { start + 60_000 }, bootedAt = { 0L }, isForeground = { true })
        restarted.clearIfDue()
        assertNull(clipText())
    }

    @Test
    fun `a future deadline, or one for a clip that is not ours, clears nothing`() {
        newClipboard().copy("b@nk-p4ss")
        SensitiveClipboard(clipboard, deadlines, alarm, TestScope(), now = { start + 10_000 }, bootedAt = { 0L }, isForeground = { true }).clearIfDue()
        assertEquals("b@nk-p4ss", clipText())

        clipboard.setPrimaryClip(ClipData.newPlainText("other", "copied later"))
        SensitiveClipboard(clipboard, deadlines, alarm, TestScope(), now = { start + 60_000 }, bootedAt = { 0L }, isForeground = { true }).clearIfDue()
        assertEquals("copied later", clipText())
    }

    @Test
    fun `a deadline from before the current boot is dropped without clearing the newer clip`() {
        newClipboard().copy("b@nk-p4ss")
        // Android empties the clipboard on reboot, so a clip there now belongs to another app.
        bootedAt = start + 40_000
        scope.advanceTimeBy(60_000)
        clipboard.setPrimaryClip(ClipData.newPlainText("other", "copied after the reboot"))
        foreground = false
        SensitiveClipboard(clipboard, ClipboardDeadlineStore(context), alarm, TestScope(), now = { start + 70_000 }, bootedAt = { bootedAt }, isForeground = { false }).clearIfDue()
        assertEquals("copied after the reboot", clipText())
        assertNull(deadlines.read())
    }

    @Test
    @Config(shadows = [UnreadableClipboardShadow::class])
    fun `in the foreground a clip KashPass cannot read is cleared at the deadline`() {
        newClipboard().copy("b@nk-p4ss")
        // Android hides the clip while the window lacks focus, as under the notification shade.
        UnreadableClipboardShadow.denyRead = true
        try {
            scope.advanceTimeBy(30_001)
            scope.runCurrent()
        } finally {
            UnreadableClipboardShadow.denyRead = false
        }
        assertNull(clipText())
        assertNull(deadlines.read())
    }

    @Test
    @Config(shadows = [RefusingClipboardShadow::class])
    fun `a copy the system refuses reports failure and schedules nothing`() {
        // A value over the binder limit (a very long note) makes setPrimaryClip throw.
        assertFalse(newClipboard().copy("x".repeat(10)))
        assertNull(deadlines.read())
        assertEquals(emptyList<Long>(), alarm.scheduled)
    }

    @Test
    fun `a copy that reaches the clipboard reports success`() {
        assertTrue(newClipboard().copy("b@nk-p4ss"))
    }

    @Test
    fun `the clip label names no field and holds only a random tag`() {
        newClipboard().copy("b@nk-p4ss")
        val label = clipboard.primaryClipDescription!!.label.toString()
        assertTrue(label, Regex("KashPass [0-9a-f]{12}").matches(label))
    }

    @Test
    fun `the deadline file holds a timestamp and a random label, never the copied value`() {
        newClipboard().copy("b@nk-p4ss")
        val stored = context.getSharedPreferences(ClipboardDeadlineStore.FILE, Context.MODE_PRIVATE).all
        assertEquals(setOf(ClipboardDeadlineStore.KEY_DEADLINE, ClipboardDeadlineStore.KEY_LABEL), stored.keys)
        assertFalse(stored.values.any { it.toString().contains("b@nk-p4ss") })
        assertNotNull(deadlines.read())
    }

    @Test
    fun `the production alarm is an explicit immutable intent to the receiver with no extras`() {
        val am = context.getSystemService(AlarmManager::class.java)
        AlarmClearAlarm(context, ClipboardClearReceiver::class.java).schedule(start + 30_000)
        val next = shadowOf(am).scheduledAlarms.single()
        val intent: Intent = shadowOf(next.operation).savedIntent
        assertEquals(ClipboardClearReceiver::class.java.name, intent.component?.className)
        assertNull(intent.extras)
        assertTrue(shadowOf(next.operation).isImmutable)
        AlarmClearAlarm(context, ClipboardClearReceiver::class.java).cancel()
        assertTrue(shadowOf(am).scheduledAlarms.isEmpty())
    }

    @Test
    fun `the receiver clears an overdue clip`() {
        clipboard.setPrimaryClip(ClipData.newPlainText("x", "seed"))
        newClipboard().copy("b@nk-p4ss")
        // The receiver uses the app's clipboard and the real clocks: copied 40 s after boot.
        ShadowSystemClock.advanceBy(Duration.ofSeconds(70))
        deadlines.write(ClipboardDeadlineStore.Deadline(System.currentTimeMillis() - 1, deadlines.read()!!.label))
        ClipboardClearReceiver().onReceive(context, Intent(context, ClipboardClearReceiver::class.java))
        assertNull(clipText())
    }

    @Test
    fun `a lock clears our clip at once and cancels the timer and alarm`() {
        val clip = newClipboard()
        clip.copy("b@nk-p4ss")
        val cancelsBefore = alarm.cancels
        clip.clearForLock()
        assertNull(clipText())
        assertNull(deadlines.read())
        assertEquals(cancelsBefore + 1, alarm.cancels)
    }

    @Test
    fun `in the foreground a lock leaves a clip someone replaced`() {
        val clip = newClipboard()
        clip.copy("b@nk-p4ss")
        clipboard.setPrimaryClip(ClipData.newPlainText("other", "my note"))
        clip.clearForLock()
        assertEquals("my note", clipText())
        assertNull(deadlines.read())
    }

    @Test
    fun `in the background a lock clears the clip, replaced or not, as the timer does`() {
        val clip = newClipboard()
        clip.copy("b@nk-p4ss")
        foreground = false
        clipboard.setPrimaryClip(ClipData.newPlainText("other", "my note"))
        clip.clearForLock()
        assertNull(clipText())
    }

    @Test
    fun `a copy whose clear can't be scheduled reports failure and takes the clip back`() {
        alarm.failSchedule = true
        assertFalse(newClipboard().copy("b@nk-p4ss"))
        assertNull(clipText())
        assertNull(deadlines.read())
    }

    @Test
    @Config(shadows = [ThrowingClipboardShadow::class])
    fun `a clear that throws keeps the deadline, and the next start or lock clears the clip`() {
        val clip = newClipboard()
        clip.copy("b@nk-p4ss")
        val cancels = alarm.cancels
        ThrowingClipboardShadow.failClear = true
        try {
            scope.advanceTimeBy(30_001)
            scope.runCurrent()
            clip.clearForLock()
            assertEquals("b@nk-p4ss", clipText())
            assertNotNull("the deadline stays for the next try", deadlines.read())
            assertEquals("the alarm stays scheduled", cancels, alarm.cancels)
        } finally {
            ThrowingClipboardShadow.failClear = false
        }
        newClipboard().clearIfDue()
        assertNull(clipText())
        assertNull(deadlines.read())
    }

    @Test
    @Config(shadows = [ThrowingClipboardShadow::class])
    fun `a clip description that throws counts as unreadable, so the clip is cleared`() {
        val clip = newClipboard()
        clip.copy("b@nk-p4ss")
        ThrowingClipboardShadow.failRead = true
        try {
            clip.clearForLock()
        } finally {
            ThrowingClipboardShadow.failRead = false
        }
        assertNull(clipText())
        assertNull(deadlines.read())
    }

    @Test
    fun `with nothing copied a lock never touches the clipboard`() {
        clipboard.setPrimaryClip(ClipData.newPlainText("other", "my note"))
        foreground = false
        newClipboard().clearForLock()
        assertEquals("my note", clipText())
    }
}
