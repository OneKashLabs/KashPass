package org.onekash.kashpass

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Looper
import android.os.Parcel
import android.view.ViewGroup
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertIsNotFocused
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isHeading
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performImeAction
import androidx.compose.ui.test.performTextInput
import androidx.core.view.WindowCompat
import androidx.lifecycle.Lifecycle
import androidx.test.platform.app.InstrumentationRegistry
import java.time.Duration
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.time.Duration.Companion.seconds
import org.onekash.kashpass.lock.LockOnCrash
import org.onekash.kashpass.platform.ClipboardDeadlineStore
import org.onekash.kashpass.platform.FakeDocumentsProvider
import androidx.compose.ui.test.performScrollTo
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.testing.TouchModeRule
import org.onekash.kashpass.vault.open.VaultSession
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowSystemClock

// A phone-sized screen, so the sheet's fields are laid out.
@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class LockFlowTest {

    @get:Rule(order = -1)
    val overlay = org.onekash.kashpass.testing.OverlayPermissionRule()

    @get:Rule(order = 0)
    val touchMode = TouchModeRule()

    @get:Rule(order = 1)
    val rule = createAndroidComposeRule<MainActivity>()

    private val graph get() = rule.activity.graph

    private val field get() = rule.onNode(hasSetTextAction())

    private fun unlock(): VaultSession {
        val result = runBlocking { TestVaults.unlock(vault) }
        rule.runOnUiThread {
            graph.sessions.set(Unlocked(TestVaults.LOCATION, result.session, result.kdf, result.showWeakWarning))
        }
        rule.waitForIdle()
        rule.onNodeWithText("Example Mail").assertExists()
        return result.session
    }

    private fun idleFor(seconds: Long) = shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(seconds))

    private fun assertLockScreen() {
        rule.waitForIdle()
        assertNull(graph.sessions.current.value)
        rule.onNodeWithText("Example Mail").assertDoesNotExist()
    }

    private fun lightStatusIcons(): Boolean {
        var light = false
        rule.runOnUiThread {
            val controller = WindowCompat.getInsetsController(rule.activity.window, rule.activity.window.decorView)
            light = controller.isAppearanceLightStatusBars && controller.isAppearanceLightNavigationBars
        }
        return light
    }

    // Robolectric runs in light mode: the navy lock screen needs light icons (dark bars false),
    // the light browser needs dark icons.
    @Test
    fun `system bar icons suit the navy lock screen and the light browser`() {
        rule.waitForIdle()
        assertFalse("lock screen", lightStatusIcons())
        unlock()
        assertTrue("browser", lightStatusIcons())
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("Lock vault").performClick()
        rule.waitForIdle()
        assertFalse("lock screen after a lock", lightStatusIcons())
    }

    @Test
    fun `after unlock the search field has focus and Enter on a single result opens it`() {
        unlock()
        field.assertIsFocused()
        field.performTextInput("a-1234")
        field.performImeAction()
        rule.onNode(hasText("Example Mail") and isHeading()).assertExists()
    }

    @Test
    fun `rotation after unlock does not move focus back to the search field`() {
        unlock()
        field.assertIsFocused()
        rule.activityRule.scenario.recreate()
        rule.waitForIdle()
        field.assertIsNotFocused()
    }

    @Test
    fun `the lock button shows the unlock screen and releases the session`() {
        val session = unlock()
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("Lock vault").performClick()
        assertLockScreen()
        assertFalse(session.isOpen)
    }

    @Test
    fun `screen off locks immediately`() {
        val session = unlock()
        rule.activity.sendBroadcast(Intent(Intent.ACTION_SCREEN_OFF))
        idleFor(0)
        assertLockScreen()
        assertFalse(session.isOpen)
    }

    @Test
    fun `a lock while the app is stopped disposes the screen that showed the vault`() {
        unlock()
        rule.onNodeWithText("Example Mail").performClick()
        rule.onNodeWithContentDescription("Show Password").performClick()
        rule.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        // A stopped composition doesn't recompose, so it would keep the rows and the open entry.
        rule.runOnUiThread { graph.sessions.lock() }
        rule.waitForIdle()
        assertEquals(0, rule.activity.findViewById<ViewGroup>(android.R.id.content).childCount)
        rule.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        rule.onNodeWithText("Open your KeePass vault").assertExists()
        rule.onNodeWithText("mail-pass").assertDoesNotExist()
    }

    @Test
    fun `60 seconds after leaving the app the vault is locked on return`() {
        unlock()
        rule.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        assertFalse(graph.inForeground)
        idleFor(61)
        rule.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        assertTrue(graph.inForeground)
        assertLockScreen()
    }

    @Test
    fun `returning within 60 seconds keeps the vault unlocked and stops the timer`() {
        unlock()
        rule.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        idleFor(59)
        rule.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        idleFor(120)
        rule.waitForIdle()
        assertNotNull(graph.sessions.current.value)
        rule.onNodeWithText("Example Mail").assertExists()
    }

    // Split screen and desktop windows keep KashPass resumed while another window has focus; the
    // system reports only the change of the top resumed activity.
    private fun focus(has: Boolean) {
        rule.runOnUiThread { rule.activity.onTopResumedActivityChanged(has) }
    }

    @Test
    fun `61 seconds with another window focused lock the vault while it stays resumed`() {
        unlock()
        focus(false)
        idleFor(61)
        assertEquals(Lifecycle.State.RESUMED, rule.activity.lifecycle.currentState)
        assertLockScreen()
    }

    @Test
    fun `focus back within 60 seconds keeps the vault unlocked and stops the timer`() {
        unlock()
        focus(false)
        idleFor(30)
        focus(true)
        idleFor(120)
        rule.waitForIdle()
        assertNotNull(graph.sessions.current.value)
        rule.onNodeWithText("Example Mail").assertExists()
    }

    @Test
    fun `a stop after a focus loss measures the 60 seconds from the focus loss`() {
        unlock()
        focus(false)
        idleFor(30)
        rule.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        idleFor(31)
        rule.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        assertLockScreen()
    }

    @Test
    fun `focus lost to a KashPass picker allows 2 minutes`() {
        unlock()
        rule.runOnUiThread { graph.locker.onPickerOpened() }
        focus(false)
        idleFor(61)
        assertNotNull(graph.sessions.current.value)
        idleFor(60)
        assertLockScreen()
    }

    @Test
    fun `a focus loss before a rotation does not lock early`() {
        unlock()
        focus(false)
        rule.activityRule.scenario.recreate()
        idleFor(120)
        rule.waitForIdle()
        assertNotNull(graph.sessions.current.value)
        rule.onNodeWithText("Example Mail").assertExists()
    }

    @Test
    fun `a focus loss saves staged deletes at once`() {
        val session = unlock()
        val id = session.index.rows(Chip.All, "").first { it.title == "Example Mail" }.id
        rule.runOnUiThread { assertTrue(graph.saves.stageDelete(id, 30.seconds)) }
        focus(false)
        assertEquals(emptyList<String>(), graph.saves.pendingDeletes.value.staged)
    }

    // The lock 60 s after the focus loss clears a pending clip by the same rule as its deadline.
    // The deadline itself compares wall-clock time, which Robolectric doesn't advance.
    @Test
    fun `without focus a pending clip is cleared even when another app replaced it`() {
        unlock()
        val clipboard = rule.activity.getSystemService(ClipboardManager::class.java)
        rule.runOnUiThread { assertTrue(graph.clipboard.copy("b@nk-p4ss")) }
        focus(false)
        assertFalse(graph.inForeground)
        // On a device Android 10+ refuses the clip to a window without focus; Robolectric lets
        // KashPass read it, so the test shows the clear doesn't depend on reading it.
        clipboard.setPrimaryClip(ClipData.newPlainText("other app", "copied elsewhere"))
        idleFor(61)
        assertLockScreen()
        assertNull(clipboard.primaryClip?.getItemAt(0)?.text)
        focus(true)
        assertTrue(graph.inForeground)
    }

    @Test
    fun `rotation keeps the vault unlocked`() {
        unlock()
        rule.activityRule.scenario.recreate()
        assertTrue(graph.inForeground)
        idleFor(120)
        rule.waitForIdle()
        assertNotNull(graph.sessions.current.value)
        rule.onNodeWithText("Example Mail").assertExists()
    }

    @Test
    fun `saved instance state holds no vault content, query or revealed value`() {
        unlock()
        field.performTextInput("Example")
        rule.onNodeWithText("Example Mail").performClick()
        rule.onNodeWithContentDescription("Show Password").performClick()
        rule.onNodeWithText("mail-pass").assertExists()

        val bundle = Bundle()
        rule.runOnUiThread { InstrumentationRegistry.getInstrumentation().callActivityOnSaveInstanceState(rule.activity, bundle) }
        val parcel = Parcel.obtain()
        val bytes = try {
            bundle.writeToParcel(parcel, 0)
            parcel.marshall()
        } finally {
            parcel.recycle()
        }
        for (secret in listOf("mail-pass", "Example", "alice", "A-1234", "otpauth")) {
            val utf16 = secret.toByteArray(Charsets.UTF_16LE)
            val utf8 = secret.toByteArray(Charsets.UTF_8)
            assertFalse("saved state holds $secret", bytes.containsSlice(utf16) || bytes.containsSlice(utf8))
        }
    }

    @Test
    fun `a clip copied by an earlier process is cleared once overdue when the app starts`() {
        val clipboard = rule.activity.getSystemService(ClipboardManager::class.java)
        // The earlier process copied 40 s into this boot and froze before its timer or alarm ran:
        // only its clip and stored deadline are left.
        ShadowSystemClock.advanceBy(Duration.ofSeconds(70))
        clipboard.setPrimaryClip(ClipData.newPlainText("KashPass 0123456789ab", "b@nk-p4ss"))
        val deadlines = ClipboardDeadlineStore(rule.activity)
        deadlines.write(ClipboardDeadlineStore.Deadline(System.currentTimeMillis() - 1, "KashPass 0123456789ab"))
        rule.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        rule.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        assertNull(clipboard.primaryClip?.getItemAt(0)?.text)
        assertNull(deadlines.read())
    }

    @Test
    fun `an uncaught exception locks the vault`() {
        val session = unlock()
        val installed = Thread.getDefaultUncaughtExceptionHandler() as LockOnCrash
        // Run without the previous handler, which ends the process on a device.
        rule.runOnUiThread { LockOnCrash(null, installed.lock).uncaughtException(Thread.currentThread(), IllegalStateException("crash")) }
        assertLockScreen()
        assertFalse(session.isOpen)
    }

    @Test
    fun `a fresh process starts locked`() {
        rule.waitForIdle()
        assertNull(graph.sessions.current.value)
        assertEquals(Lifecycle.State.RESUMED, rule.activity.lifecycle.currentState)
    }

    @After
    fun resetProvider() = FakeDocumentsProvider.reset()

    // Serves [shared] as "Shared.kdbx" from a documents provider, as a cloud storage app does for
    // Open with.
    private fun serveShared(): Intent {
        val file = java.io.File.createTempFile("shared", ".kdbx").apply { writeBytes(shared) }
        org.robolectric.Robolectric.setupContentProvider(FakeDocumentsProvider::class.java, FakeDocumentsProvider.AUTHORITY)
        FakeDocumentsProvider.reset()
        FakeDocumentsProvider.file = file
        FakeDocumentsProvider.name = "Shared.kdbx"
        FakeDocumentsProvider.size = shared.size.toLong()
        return Intent(Intent.ACTION_VIEW).setDataAndType(FakeDocumentsProvider.URI, "application/octet-stream")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }

    private val openedLine = "Opened from another app, read-only. Make it your vault to edit and save."

    private fun waitForText(text: String) =
        rule.waitUntil(10_000) { runCatching { rule.onNodeWithText(text).assertExists() }.isSuccess }

    @Test
    fun `a file opened with KashPass unlocks read-only for the session and leaves nothing behind`() {
        val view = serveShared()
        rule.waitForIdle()
        rule.runOnUiThread { rule.activity.onNewIntent(view) }
        waitForText(openedLine)
        rule.onNodeWithText("Shared.kdbx").assertExists()
        // The header check that shows the password field finishes after the line appears.
        rule.waitUntil(10_000) { rule.onAllNodes(hasSetTextAction()).fetchSemanticsNodes().isNotEmpty() }
        field.performTextInput(TestVaults.PASSWORD)
        rule.onNodeWithText("Unlock").performScrollTo().performClick()
        rule.waitUntil(20_000) { graph.sessions.current.value != null }
        assertTrue(graph.sessions.current.value!!.sessionOnly)
        waitForText("Opened from another app, read-only.")
        rule.onNodeWithText("Save as new file").assertExists()
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("Shared.kdbx").assertExists()
        rule.onNodeWithText("Vault backups").assertDoesNotExist()
        rule.onNodeWithText("Lock vault").performClick()
        assertLockScreen()
        // The lock returns to the remembered vault: here none.
        rule.onNodeWithText("Open your KeePass vault").assertExists()
        rule.onNodeWithText(openedLine).assertDoesNotExist()
        val prefs = rule.activity.getSharedPreferences(org.onekash.kashpass.platform.PrefsVaultStateStore.FILE, Context.MODE_PRIVATE).all
        assertEquals(emptySet<String>(), prefs.keys)
        assertTrue(AppGraph.backupRoot(rule.activity).walkTopDown().none { it.isFile })
        assertTrue(rule.activity.contentResolver.persistedUriPermissions.isEmpty())
    }

    @Test
    fun `an Open with while unlocked leaves the vault open and is offered after the lock`() {
        val view = serveShared()
        val session = unlock()
        rule.runOnUiThread { rule.activity.onNewIntent(view) }
        rule.waitForIdle()
        assertTrue(session.isOpen)
        rule.onNodeWithText("Example Mail").assertExists()
        rule.onNodeWithText(openedLine).assertDoesNotExist()
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("Lock vault").performClick()
        assertLockScreen()
        waitForText(openedLine)
        rule.onNodeWithText("Shared.kdbx").assertExists()
    }

    @Test
    fun `an Open with is handled once, not again after a rotation`() {
        val view = serveShared()
        rule.waitForIdle()
        rule.runOnUiThread { rule.activity.onNewIntent(view) }
        waitForText(openedLine)
        rule.onNodeWithText("Cancel").performScrollTo().performClick()
        rule.waitForIdle()
        rule.onNodeWithText(openedLine).assertDoesNotExist()
        rule.activityRule.scenario.recreate()
        rule.waitForIdle()
        rule.onNodeWithText(openedLine).assertDoesNotExist()
        rule.onNodeWithText("Open your KeePass vault").assertExists()
    }

    @Test
    fun `an Open with replayed from Recents is ignored`() {
        val view = serveShared().addFlags(Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY)
        rule.waitForIdle()
        rule.runOnUiThread { rule.activity.onNewIntent(view) }
        rule.waitForIdle()
        rule.onNodeWithText(openedLine).assertDoesNotExist()
        rule.onNodeWithText("Open your KeePass vault").assertExists()
    }

    private fun ByteArray.containsSlice(needle: ByteArray): Boolean =
        (0..size - needle.size).any { start -> needle.indices.all { this[start + it] == needle[it] } }

    private companion object {
        val vault: ByteArray by lazy { TestVaults.browserVault() }
        val shared: ByteArray by lazy { TestVaults.bytes(aesRounds = 1_000UL) }
    }
}
