package org.onekash.kashpass.vault.open

import java.security.MessageDigest
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.TestVaults

/** Pins the shared test fakes to the real contracts that app tests built on them rely on. */
class TestFixturesContractTest {

    @Test
    fun `a generated test vault passes every check and unlocks with its password`() = runBlocking {
        val storage = FakeVaultStorage().apply { put("v", TestVaults.bytes()) }
        val opener = VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.Unconfined)
        assertIs<OpenResult.Ready>(opener.check("v"))
        val unlocked = assertIs<OpenResult.Unlocked>(opener.open("v", TestVaults.PASSWORD.toCharArray()))
        assertEquals(listOf("Example Bank", "Example Mail"), unlocked.session.index.rows(Chip.All, "").map { it.title })
    }

    @Test
    fun `FakeVaultStorage enforces maxBytes and unknown locations`() = runBlocking {
        val storage = FakeVaultStorage().apply { put("v", ByteArray(11)) }
        assertEquals(StorageFailure.TOO_LARGE, (storage.read("v", 10) as org.onekash.kashpass.vault.storage.ReadResult.Failed).cause)
        assertEquals(StorageFailure.NOT_FOUND, (storage.read("other", 10) as org.onekash.kashpass.vault.storage.ReadResult.Failed).cause)
    }

    @Test
    fun `FakeVaultOpener unlocks with the test password, refuses others, and zero-fills arrays`() = runBlocking {
        val fake = FakeVaultOpener()
        assertIs<OpenResult.Unlocked>(fake.open("v", TestVaults.PASSWORD.toCharArray()))
        assertEquals(OpenResult.WrongPassword, fake.open("v", "nope".toCharArray()))
        fake.openResult = { OpenResult.NotEnoughMemory() }
        assertEquals(OpenResult.NotEnoughMemory(), fake.open("v", "x".toCharArray()))
        assertTrue(fake.passwordArrays.all { array -> array.all { it == '\u0000' } })
        assertEquals(3, fake.opens)
    }

    @Test
    fun `FakeVaultOpener sets each unlock origin and keeps it on reopen and backup`() = runBlocking {
        val fake = FakeVaultOpener()
        val hash = MessageDigest.getInstance("SHA-256").digest(TestVaults.PASSWORD.toByteArray())
        fun origin(result: OpenResult) = assertIs<OpenResult.Unlocked>(result).session.opened.origin
        assertEquals(UnlockOrigin.PASSWORD, origin(fake.open("v", TestVaults.PASSWORD.toCharArray())))
        val keyFile = TestVaults.KEY_FILE
        assertEquals(UnlockOrigin.PASSWORD_AND_KEY_FILE, origin(fake.open("v", TestVaults.PASSWORD.toCharArray(), keyFile = keyFile)))
        assertTrue(keyFile.all { it == 0.toByte() })
        assertEquals(UnlockOrigin.KEY_FILE_ONLY, origin(fake.open("v", CharArray(0), keyFile = TestVaults.KEY_FILE)))
        assertEquals(UnlockOrigin.STORED_KEY, origin(fake.openWithKey("v", hash.copyOf())))
        val stored = assertIs<OpenResult.Unlocked>(fake.openWithKey("v", hash.copyOf(), keyFile = TestVaults.KEY_FILE)).session
        assertEquals(UnlockOrigin.STORED_KEY_AND_KEY_FILE, stored.opened.origin)
        assertEquals(UnlockOrigin.STORED_KEY_AND_KEY_FILE, origin(fake.reopen("v", stored)))
        val backup = BackupInfo("b", java.time.Instant.EPOCH, 0, BackupKind.OPENED, "")
        assertEquals(UnlockOrigin.STORED_KEY_AND_KEY_FILE, origin(fake.openBackup("v", backup, stored)))
        assertEquals(OpenResult.WrongPassword, fake.openWithKey("v", ByteArray(32)))
    }
}
