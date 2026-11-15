package org.onekash.kashpass.ui.save

import android.net.Uri
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.core.app.ActivityOptionsCompat
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.ui.format.SaveChoice
import org.onekash.kashpass.ui.format.SaveProblem
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.testing.TouchModeRule
import org.onekash.kashpass.testing.FakeVaultFiles
import org.onekash.kashpass.platform.RememberedVault
import org.onekash.kashpass.shownFileName
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.test.hasProgressBarRangeInfo
import androidx.compose.ui.test.assertIsNotEnabled

@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class SaveProblemHostTest {

    @get:Rule(order = 0)
    val touchMode = TouchModeRule()

    @get:Rule(order = 1)
    val rule = createComposeRule()

    private val sessions = SessionHolder()
    private val storage = FakeVaultStorage()
    private val saver = FakeVaultSaver()
    private val opener = FakeVaultOpener()
    private val coordinator = SaveCoordinator(sessions, saver, opener, CoroutineScope(SupervisorJob() + Dispatchers.IO), storage)
    private val messages = mutableListOf<String>()
    private var editorClosed = 0

    // Records the picker launch; the test delivers the result later, as the system does.
    private var pending: Int? = null
    private val registry = object : ActivityResultRegistry() {
        override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?) {
            pending = requestCode
        }
    }
    private val owner = object : ActivityResultRegistryOwner {
        override val activityResultRegistry = registry
    }

    private fun show(fileName: () -> String = { "Passwords.kdbx" }) = rule.setContent {
        CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner) {
            KashPassTheme {
                SaveProblemHost(coordinator, fileName(), onEditsDropped = { editorClosed++ }, onMessage = { messages += it })
            }
        }
    }

    private fun conflict() = runBlocking {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        val unlocked = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false).also(sessions::set)
        saver.result = { vault, prepared -> SaveResult.Conflict(vault, prepared) }
        coordinator.save(unlocked.session.opened.document).await()
    }

    @Test
    fun `the sheet names a session-only file by its own name, not the remembered vault's`() {
        val opened = runBlocking { TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL), access = FileAccess.SESSION_ONLY) }
        val unlocked = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, sessionName = "Shared.kdbx")
        sessions.set(unlocked)
        saver.result = { vault, prepared -> SaveResult.Conflict(vault, prepared) }
        runBlocking { coordinator.save(unlocked.session.opened.document).await() }
        val files = FakeVaultFiles().apply { vault = RememberedVault("content://drive/document/doc1", "Passwords.kdbx") }
        show { shownFileName(sessions.current.value, files) }
        rule.onNodeWithText("Shared.kdbx changed since you opened it. Your edits are not saved.").assertExists()
    }

    @Test
    fun `save as copy writes the copy, names it and closes the editor`() {
        conflict()
        show()
        rule.onNodeWithText("Save as copy").performClick()
        val copy = storage.createDocument("Passwords (phone).kdbx")
        rule.runOnIdle { registry.dispatchResult(pending!!, android.app.Activity.RESULT_OK, android.content.Intent().setData(Uri.parse(copy))) }
        rule.waitUntil(5_000) { messages.isNotEmpty() }
        assertEquals(listOf("Saved a copy as copy.kdbx"), messages)
        assertEquals(1, editorClosed)
        rule.onNodeWithText("Save as copy").assertDoesNotExist()
    }

    @Test
    fun `a picker result with nothing left to write offers to delete the empty file`() {
        conflict()
        show()
        rule.onNodeWithText("Save as copy").performClick()
        val copy = storage.createDocument("Passwords (phone).kdbx")
        // The vault locks (or the process restarts) before the picker returns.
        rule.runOnIdle {
            coordinator.cancelRunning()
            sessions.lock()
            registry.dispatchResult(pending!!, android.app.Activity.RESULT_OK, android.content.Intent().setData(Uri.parse(copy)))
        }
        rule.waitUntil(5_000) { runCatching { rule.onNodeWithText("The copy wasn't saved. Delete the file it left?").assertExists() }.isSuccess }
        rule.onNodeWithText("Delete it").performClick()
        rule.waitUntil(5_000) { runCatching { rule.onNodeWithText("File deleted.").assertExists() }.isSuccess }
        assertEquals(null, storage.bytes(copy))
    }

    @Test
    fun `a Reload of a file whose unlock settings became much slower says so and keeps the edit`() {
        conflict()
        opener.reopenResult = { org.onekash.kashpass.vault.open.OpenResult.TooSlow(org.onekash.kashpass.vault.policy.SlowKdf(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(100_000_000UL), 100, 166)) }
        show()
        rule.onNodeWithText("Reload and lose my edits").performClick()
        rule.waitUntil(5_000) { messages.isNotEmpty() }
        assertEquals(listOf("This file's unlock settings changed. Lock and unlock to review them."), messages)
        assertEquals("the edit is not dropped", 0, editorClosed)
    }

    @Test
    fun `a lock and a new unlock while Reload reads the file leave the new editor open`() {
        conflict()
        show()
        opener.hold()
        rule.onNodeWithText("Reload and lose my edits").performClick()
        rule.waitUntil(5_000) { "reopen" in opener.calls }
        // Screen off, then the user unlocks again and opens an editor, while the file is read.
        sessions.lock()
        val again = runBlocking { TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL)) }
        sessions.set(Unlocked(TestVaults.LOCATION, again.session, again.kdf, false))
        val closedBefore = editorClosed
        opener.release()
        rule.waitUntil(5_000) { !coordinator.working.value }
        rule.waitForIdle()
        assertEquals("the editor opened after the new unlock stays open", closedBefore, editorClosed)
    }

    @Test
    fun `while a Reload runs the sheet shows progress and its choices are disabled`() {
        conflict()
        opener.hold()
        show()
        rule.onNodeWithText("Reload and lose my edits").performClick()
        rule.waitUntil(5_000) { coordinator.working.value }
        rule.onNodeWithText("Save as copy").assertIsNotEnabled()
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
        opener.release()
    }
}
