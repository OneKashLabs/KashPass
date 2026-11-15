package org.onekash.kashpass.session

import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.TestVaults

class BackupSettingsTest {

    private val loc = TestVaults.LOCATION
    private var clock = Instant.parse("2026-10-21T12:00:00Z")
    private val backups = FakeBackupStore { clock }.apply { keep = 30 }
    private val state = FakeVaultStateStore()
    private val sessions = SessionHolder()
    private var pending = false
    private val settings = BackupSettings(state, backups, sessions) { pending }

    private fun unlock(backup: org.onekash.kashpass.vault.backup.BackupInfo? = null) = runBlocking {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        sessions.set(Unlocked(loc, opened.session, opened.kdf, false, backup))
    }

    private fun copies(n: Int) = runBlocking {
        repeat(n) {
            backups.add(loc, byteArrayOf(it.toByte()), BackupKind.OPENED)
            clock += Duration.ofMinutes(1)
        }
    }

    @Test
    fun `the count defaults to 3 and lowering it trims the open file's copies`() = runBlocking<Unit> {
        unlock()
        copies(5)
        assertEquals(3, settings.keep())
        assertEquals(5, backups.list(loc).size)
        state.keep = 5
        assertEquals(BackupChange.Done(3, 3), settings.setKeep(3, confirmed = 2))
        assertEquals(3, state.keep)
        assertEquals(3, backups.list(loc).size)
    }

    @Test
    fun `raising the count deletes nothing, also with more copies than the count`() = runBlocking<Unit> {
        unlock()
        copies(5)
        state.keep = 3
        assertEquals(BackupChange.Done(4, 5), settings.setKeep(4, confirmed = 0))
        assertEquals(5, backups.list(loc).size)
        assertEquals(4, settings.keep())
    }

    @Test
    fun `nothing changes for an open backup or a locked app`() = runBlocking<Unit> {
        copies(4)
        assertNull(settings.setKeep(1, confirmed = 3))
        unlock(backup = backups.list(loc).first())
        assertNull(settings.setKeep(1, confirmed = 3))
        assertEquals(4, backups.list(loc).size)
        assertEquals(null, state.keep)
    }

    @Test
    fun `pinned reports a pending save marker for the open file`() {
        unlock()
        assertFalse(settings.pinned())
        pending = true
        assertTrue(settings.pinned())
    }

    @Test
    fun `a change that deletes more copies than confirmed recounts and changes nothing`() = runBlocking<Unit> {
        unlock()
        copies(4)
        state.keep = 3
        // The screen counted 3 copies and showed "Removes 1"; a save added a fourth since.
        assertEquals(BackupChange.Recount(4), settings.setKeep(2, confirmed = 1))
        assertEquals(4, backups.list(loc).size)
        assertEquals(3, settings.keep())
    }

    @Test
    fun `only the file itself offers its location for a delete`() = runBlocking<Unit> {
        assertNull("no session", settings.deletable())
        copies(2)
        unlock()
        assertEquals(loc, settings.deletable())
        unlock(backup = backups.list(loc).first())
        assertNull("an open backup", settings.deletable())
    }

    @Test
    fun `a delete with the location taken earlier runs after a lock`() = runBlocking<Unit> {
        unlock()
        copies(3)
        val location = settings.deletable()!!
        val older = backups.list(loc).last().id
        sessions.lock()
        assertEquals(org.onekash.kashpass.vault.backup.BackupDeletion.Deleted, settings.delete(location, older))
        assertEquals(2, backups.list(loc).size)
    }

    @Test
    fun `the store refuses the newest copy, a pinned location and a failed delete`() = runBlocking<Unit> {
        unlock()
        copies(3)
        val (newest, middle) = backups.list(loc).map { it.id }
        assertEquals(org.onekash.kashpass.vault.backup.BackupDeletion.Newest, settings.delete(loc, newest))
        backups.pinned = setOf(loc)
        assertEquals(org.onekash.kashpass.vault.backup.BackupDeletion.Pinned, settings.delete(loc, middle))
        backups.pinned = emptySet()
        backups.failDeletes = true
        assertEquals(org.onekash.kashpass.vault.backup.BackupDeletion.Failed, settings.delete(loc, middle))
        assertEquals(3, backups.list(loc).size)
    }
}
