package org.onekash.kashpass.ui.save

import android.content.ActivityNotFoundException
import android.net.Uri
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.core.app.ActivityOptionsCompat
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.testing.TouchModeRule
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.save.CopyResult
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Save as new file from the activity root: picker, write, switch, and the empty-file offer. */
@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class BackupSaveHostTest {

    @get:Rule(order = 0)
    val touchMode = TouchModeRule()

    @get:Rule(order = 1)
    val rule = createComposeRule()

    private val sessions = SessionHolder()
    private val storage = FakeVaultStorage()
    private val saver = FakeVaultSaver()
    private val backups = FakeBackupStore()
    private val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), CoroutineScope(SupervisorJob() + Dispatchers.IO), storage, backups)
    private val messages = mutableListOf<String>()
    private val saved = mutableListOf<String>()
    private var opened = 0
    private var closed = 0
    private lateinit var start: () -> Unit

    // Records the picker launch and its suggested name; the test answers it as the system does.
    private var pending: Int? = null
    private var suggested: Any? = null
    private var noPicker = false
    private val registry = object : ActivityResultRegistry() {
        override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?) {
            if (noPicker) throw ActivityNotFoundException()
            pending = requestCode
            suggested = input
        }
    }
    private val owner = object : ActivityResultRegistryOwner {
        override val activityResultRegistry = registry
    }

    private val createdAt = Instant.parse("2026-10-19T10:00:00Z")

    private fun openBackup(): BackupInfo = runBlocking {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL)
        val info = (backups.add(TestVaults.LOCATION, bytes, BackupKind.OPENED) as BackupResult.Added).info.copy(createdAt = createdAt)
        val opened = TestVaults.unlock(bytes)
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, info))
        info
    }

    private fun show() = rule.setContent {
        CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner) {
            KashPassTheme {
                start = rememberBackupSaver(
                    saves = coordinator,
                    fileName = { "Passwords.kdbx" },
                    backupTime = { sessions.current.value?.backup?.createdAt },
                    onSaved = { saved += it },
                    onMessage = { messages += it },
                    onPickerOpened = { opened++ },
                    onPickerClosed = { closed++ },
                )
            }
        }
    }

    private fun answer(location: String) = rule.runOnIdle {
        registry.dispatchResult(pending!!, android.app.Activity.RESULT_OK, android.content.Intent().setData(Uri.parse(location)))
    }

    private val dialog = "The copy wasn't saved. Delete the file it left?"

    @Test
    fun `the picker suggests the vault and backup time and brackets the lock's away timer`() {
        openBackup()
        show()
        rule.runOnIdle { start() }
        val time = LocalDateTime.ofInstant(createdAt, ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HHmm"))
        assertEquals("Passwords (backup $time).kdbx", suggested)
        assertEquals(1, opened)
        val copy = storage.createDocument("Passwords (backup).kdbx")
        answer(copy)
        rule.waitUntil(5_000) { saved.isNotEmpty() }
        assertEquals(1, closed)
        assertEquals(listOf(copy), saved)
    }

    @Test
    fun `a copy that fails offers to delete the empty file`() {
        openBackup()
        saver.copyResult = { CopyResult.Failed(it) }
        show()
        rule.runOnIdle { start() }
        val copy = storage.createDocument("Passwords (backup).kdbx")
        answer(copy)
        rule.waitUntil(5_000) { runCatching { rule.onNodeWithText(dialog).assertExists() }.isSuccess }
        rule.onNodeWithText("Delete it").performClick()
        rule.waitUntil(5_000) { runCatching { rule.onNodeWithText("File deleted.").assertExists() }.isSuccess }
        assertEquals(null, storage.bytes(copy))
        rule.onNodeWithText("OK").performClick()
        rule.onNodeWithText("File deleted.").assertDoesNotExist()
        assertEquals(emptyList<String>(), saved)
    }

    @Test
    fun `a result after the vault locked offers to delete the empty file`() {
        openBackup()
        show()
        rule.runOnIdle { start() }
        val copy = storage.createDocument("Passwords (backup).kdbx")
        rule.runOnIdle { sessions.lock() }
        answer(copy)
        rule.waitUntil(5_000) { runCatching { rule.onNodeWithText(dialog).assertExists() }.isSuccess }
        assertEquals(emptyList<String>(), saved)
    }

    @Test
    fun `a write cancelled by a lock offers to delete the file`() {
        openBackup()
        saver.hold()
        show()
        rule.runOnIdle { start() }
        val copy = storage.createDocument("Passwords (backup).kdbx")
        answer(copy)
        rule.waitUntil(5_000) { coordinator.busy.value }
        rule.runOnIdle { coordinator.cancelRunning() }
        rule.waitUntil(5_000) { runCatching { rule.onNodeWithText(dialog).assertExists() }.isSuccess }
        saver.release()
        assertEquals(emptyList<String>(), saved)
    }

    @Test
    fun `a corrupted backup says so and offers to delete the empty file`() {
        val info = openBackup()
        backups.corrupt(TestVaults.LOCATION, info.id)
        show()
        rule.runOnIdle { start() }
        val copy = storage.createDocument("Passwords (backup).kdbx")
        answer(copy)
        rule.waitUntil(5_000) { messages.isNotEmpty() }
        assertEquals(listOf("This backup is corrupted."), messages)
        rule.onNodeWithText(dialog).assertExists()
    }

    // Opens [bytes] at the test location as a file another app handed over, read-only.
    private fun openFromApp(bytes: ByteArray) = runBlocking {
        storage.put(TestVaults.LOCATION, bytes)
        val opener = VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO)
        val opened = opener.open(TestVaults.LOCATION, TestVaults.PASSWORD.toCharArray(), access = FileAccess.SESSION_ONLY) as OpenResult.Unlocked
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, sessionName = "Shared.kdbx"))
    }

    @Test
    fun `a read-only file is saved as a new file named as a copy`() {
        openFromApp(TestVaults.bytes(aesRounds = 1_000UL))
        show()
        rule.runOnIdle { start() }
        assertTrue(suggested.toString(), suggested.toString().startsWith("Passwords (copy "))
        val copy = storage.createDocument("Passwords (copy).kdbx")
        answer(copy)
        rule.waitUntil(5_000) { saved.isNotEmpty() }
        assertEquals(listOf("backupCopy" to copy), saver.calls)
        assertEquals(listOf(copy), saved)
    }

    @Test
    fun `a read-only file that changed since it opened says so, writes nothing and offers to delete the empty file`() {
        openFromApp(TestVaults.bytes(aesRounds = 1_000UL))
        storage.put(TestVaults.LOCATION, TestVaults.bytes(aesRounds = 1_000UL))
        show()
        rule.runOnIdle { start() }
        val copy = storage.createDocument("Passwords (copy).kdbx")
        answer(copy)
        rule.waitUntil(5_000) { messages.isNotEmpty() }
        assertEquals(listOf("Not saved: the file changed since you opened it. Lock and unlock to see the new version."), messages)
        rule.onNodeWithText(dialog).assertExists()
        assertEquals(emptyList<Pair<String, String>>(), saver.calls)
        assertEquals(emptyList<String>(), saved)
    }

    @Test
    fun `with no picker app it says so and ends the timer bracket`() {
        openBackup()
        noPicker = true
        show()
        rule.runOnIdle { start() }
        assertEquals(1, opened)
        assertEquals(1, closed)
        assertEquals(listOf("No app on this device can create the copy."), messages)
    }

    @Test
    fun `a file that isn't empty is refused, left as it was, and not offered for deletion`() {
        openBackup()
        saver.copyResult = { org.onekash.kashpass.vault.save.CopyResult.Refused(it) }
        show()
        rule.runOnIdle { start() }
        val copy = storage.createDocument("Passwords (backup).kdbx")
        answer(copy)
        rule.waitUntil(5_000) { messages.isNotEmpty() }
        assertEquals(listOf("Not saved: KashPass writes a copy only to a new, empty file."), messages)
        rule.onNodeWithText(dialog).assertDoesNotExist()
        assertEquals(emptyList<String>(), saved)
    }
}
