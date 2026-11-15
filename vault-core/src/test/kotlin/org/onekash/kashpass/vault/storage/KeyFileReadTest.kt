package org.onekash.kashpass.vault.storage

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.header.KeePassSignature
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.TestVaults

class KeyFileReadTest {

    private val loc = "content://fake/key.keyx"
    private val fake = FakeVaultStorage()

    // Records how each read was requested, then reads from the shared fake.
    private val calls = mutableListOf<String>()
    private val storage = object : VaultStorage by fake {
        override suspend fun read(location: String, maxBytes: Int): ReadResult {
            calls += "read $maxBytes"
            return fake.read(location, maxBytes)
        }

        override suspend fun readFresh(location: String, maxBytes: Int): ReadResult {
            calls += "readFresh $maxBytes"
            return fake.read(location, maxBytes)
        }
    }

    @Test
    fun `a key file is read fresh with the vault's heap-derived cap and returned whole`() = runBlocking {
        fake.put(loc, TestVaults.KEY_FILE)
        val read = assertIs<KeyFileRead.Bytes>(storage.readKeyFile(loc))
        assertContentEquals(TestVaults.KEY_FILE, read.bytes)
        assertEquals(listOf("readFresh ${maxVaultBytes(Runtime.getRuntime().maxMemory())}"), calls)
    }

    @Test
    fun `a key file over the cap is too large`() = runBlocking {
        fake.put(loc, ByteArray(101))
        assertEquals(KeyFileRead.Failed(StorageFailure.TOO_LARGE), storage.readKeyFile(loc, maxBytes = 100))
        assertIs<KeyFileRead.Bytes>(storage.readKeyFile(loc, maxBytes = 101))
        Unit
    }

    @Test
    fun `each storage failure is passed on`() = runBlocking {
        for (cause in StorageFailure.entries) {
            fake.fail(loc, cause)
            assertEquals(KeyFileRead.Failed(cause), storage.readKeyFile(loc))
        }
    }

    @Test
    fun `a KeePass vault is refused as a key file and its bytes are zero-filled`() = runBlocking {
        val vault = TestVaults.bytes(aesRounds = 1_000UL)
        fake.put(loc, vault)
        assertEquals(KeyFileRead.KeePassVault, storage.readKeyFile(loc))
        assertEquals(true, fake.lastReturned!!.all { it == 0.toByte() })
    }

    @Test
    fun `the signature check reads 8 bytes and zero-fills them`() = runBlocking {
        fake.put(loc, TestVaults.bytes(aesRounds = 1_000UL))
        assertEquals(true, storage.startsWithKeePassSignature(loc))
        assertEquals(true, fake.lastReturned!!.all { it == 0.toByte() })
        fake.put(loc, TestVaults.KEY_FILE)
        assertEquals(false, storage.startsWithKeePassSignature(loc))
        assertEquals(8, fake.lastReturned!!.size)
        assertEquals(true, fake.lastReturned!!.all { it == 0.toByte() })
        assertEquals(listOf(KeePassSignature.BYTES, KeePassSignature.BYTES), fake.prefixReads)
        assertEquals(0, fake.reads)
    }

    @Test
    fun `a short or unreadable file has no KeePass signature`() = runBlocking {
        fake.put(loc, TestVaults.bytes(aesRounds = 1_000UL).copyOf(7))
        assertEquals(false, storage.startsWithKeePassSignature(loc))
        for (cause in StorageFailure.entries) {
            fake.fail(loc, cause)
            assertEquals(false, storage.startsWithKeePassSignature(loc))
        }
    }

    @Test
    fun `the result never shows the key file's bytes`() {
        assertEquals("Bytes(3 bytes)", KeyFileRead.Bytes(byteArrayOf(65, 66, 67)).toString())
    }
}
