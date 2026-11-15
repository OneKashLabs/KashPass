package org.onekash.kashpass.session

import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import java.time.Instant
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.open.RefreshResult
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.KashPassApp
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SessionHolderTest {

    @Test
    fun `every lock runs the lock listener, whatever calls it`() {
        val sessions = SessionHolder()
        var locks = 0
        sessions.onLock = { locks++ }
        sessions.lock()
        val opened = runBlocking { TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL)) }
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        sessions.lock()
        assertEquals(2, locks)
    }

    @Test
    fun `an unlock of a session-only file is session-only without being told`() = runBlocking<Unit> {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL), access = FileAccess.SESSION_ONLY)
        val unlocked = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false)
        assertTrue(unlocked.sessionOnly)
        assertEquals(VaultTarget.SESSION_ONLY, unlocked.target)
        val file = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        assertFalse(Unlocked(TestVaults.LOCATION, file.session, file.kdf, false).sessionOnly)
    }

    @Test
    fun `a session-only target and its name survive every session swap`() = runBlocking<Unit> {
        val sessions = SessionHolder()
        val opener = FakeVaultOpener()
        val saver = FakeVaultSaver()
        val coordinator = SaveCoordinator(sessions, saver, opener, CoroutineScope(SupervisorJob() + Dispatchers.IO))
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL), access = FileAccess.SESSION_ONLY)
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, sessionName = "Shared.kdbx"))
        fun check(step: String) {
            val current = sessions.current.value!!
            assertEquals(step, VaultTarget.SESSION_ONLY, current.target)
            assertEquals(step, "Shared.kdbx", current.sessionName)
        }
        saver.result = { vault, _ -> SaveResult.ReadOnly(vault, Saveability.ReadOnly(ReadOnlyReason.OPENED_FROM_APP)) }
        coordinator.save(sessions.current.value!!.session.opened.document).await()
        check("after a refused save")
        saver.result = { vault, _ -> SaveResult.Saved(vault) }
        coordinator.save(sessions.current.value!!.session.opened.document).await()
        check("after a save")
        coordinator.reload()
        check("after a reload")
        // The real opener reloads a file with the access it was opened with.
        val changed = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL), access = FileAccess.SESSION_ONLY)
        opener.refreshResult = { RefreshResult.Reloaded(changed) }
        assertEquals(EditCheck.Updated, coordinator.refreshForAdd())
        check("after a refresh")
        val before = sessions.current.value!!
        assertNull(coordinator.openBackup(BACKUP))
        assertSame(before, sessions.current.value)
        assertFalse("openBackup" in opener.calls)
        sessions.replace(before, changed.session, backup = BACKUP)
        check("after a replace with a backup")
    }

    @Test
    fun `the remembered file's target follows the open backup`() = runBlocking<Unit> {
        val sessions = SessionHolder()
        val bytes = TestVaults.bytes(aesRounds = 1_000UL)
        val opened = TestVaults.unlock(bytes)
        val file = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false)
        sessions.set(file)
        assertEquals(VaultTarget.REMEMBERED, file.target)
        // Each swap takes a new session, as a save or reload does: a swap releases the old one.
        sessions.replace(file, TestVaults.unlock(bytes).session, backup = BACKUP)
        val backup = sessions.current.value!!
        assertEquals(VaultTarget.BACKUP, backup.target)
        sessions.replace(backup, TestVaults.unlock(bytes).session, backup = null)
        assertEquals(VaultTarget.REMEMBERED, sessions.current.value!!.target)
    }

    private companion object {
        val BACKUP = BackupInfo("b", Instant.parse("2026-10-19T10:00:00Z"), 1, BackupKind.OPENED, "0".repeat(64))
    }

    @Test
    fun `the app's lock listener clears a pending KashPass clip`() {
        val graph = ApplicationProvider.getApplicationContext<KashPassApp>().graph
        val clipboard = ApplicationProvider.getApplicationContext<android.content.Context>().getSystemService(android.content.ClipboardManager::class.java)
        graph.inForeground = true
        graph.clipboard.copy("b@nk-p4ss")
        graph.sessions.lock()
        assertEquals(null, clipboard.primaryClip?.getItemAt(0)?.text)
    }
}
