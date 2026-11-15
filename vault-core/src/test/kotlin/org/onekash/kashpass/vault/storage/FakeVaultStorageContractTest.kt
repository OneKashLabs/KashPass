package org.onekash.kashpass.vault.storage

import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.testing.FakeVaultStorage

/** Pins the shared fake's behavior, so tests built on it model what SAF providers do. */
class FakeVaultStorageContractTest {

    private val loc = "content://fake/vault.kdbx"
    private val storage = FakeVaultStorage().apply { put(loc, ByteArray(100) { 7 }) }

    private fun stored() = storage.bytes(loc)!!

    @Test
    fun `a write truncates, like mode rwt`() = runBlocking {
        assertEquals(WriteResult.Written, storage.write(loc, byteArrayOf(1, 2, 3)))
        assertContentEquals(byteArrayOf(1, 2, 3), stored())
        assertEquals(1, storage.writes)
    }

    @Test
    fun `writability defaults follow the location`() = runBlocking {
        assertEquals(Writability.WRITABLE, storage.writability(loc))
        assertEquals(Writability.NOT_CONTENT, storage.writability("file:///sdcard/vault.kdbx"))
        assertEquals(Writability.UNAVAILABLE, storage.writability("content://fake/missing"))
        for (value in Writability.entries) {
            storage.setWritability(loc, value)
            assertEquals(value, storage.writability(loc))
        }
    }

    @Test
    fun `a failure before open leaves the file untouched, after open leaves a partial write`() = runBlocking {
        storage.failWrites(loc, StorageFailure.PERMISSION_REVOKED, afterOpen = false)
        assertEquals(WriteResult.Failed(StorageFailure.PERMISSION_REVOKED, afterOpen = false), storage.write(loc, ByteArray(10)))
        assertContentEquals(ByteArray(100) { 7 }, stored())
        assertEquals(0, storage.writes)

        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = true)
        assertEquals(WriteResult.Failed(StorageFailure.IO_FAILURE, afterOpen = true), storage.write(loc, ByteArray(10) { 1 }))
        assertContentEquals(ByteArray(5) { 1 }, stored())
    }

    @Test
    fun `a provider that ignores truncation keeps the old tail`() = runBlocking {
        storage.ignoreTruncation(loc)
        storage.write(loc, byteArrayOf(1, 2))
        assertEquals(100, stored().size)
        assertContentEquals(byteArrayOf(1, 2, 7), stored().copyOf(3))
    }

    @Test
    fun `a scripted provider reads back different bytes`() = runBlocking {
        storage.readBackDifferent(loc)
        val written = ByteArray(10) { it.toByte() }
        assertEquals(WriteResult.Written, storage.write(loc, written))
        assertFalse(written.contentEquals(stored()))
    }

    @Test
    fun `a blocked write blocks its thread until released`() {
        storage.blockWrites()
        var result: WriteResult? = null
        val writer = thread { result = runBlocking { storage.write(loc, byteArrayOf(9)) } }
        assertTrue(storage.writeStarted.await(5, TimeUnit.SECONDS))
        writer.join(200)
        assertTrue(writer.isAlive)
        assertNull(result)
        storage.releaseWrites()
        writer.join(5_000)
        assertEquals(WriteResult.Written, result)
        assertContentEquals(byteArrayOf(9), stored())
    }

    @Test
    fun `a created document is empty and renamed on a clash, and deletes when allowed`() = runBlocking {
        val first = storage.createDocument("Vault (phone).kdbx")
        val second = storage.createDocument("Vault (phone).kdbx")
        val kept = storage.createDocument("Other.kdbx", deletable = false)
        assertEquals("Vault (phone).kdbx", storage.metadata(first).displayName)
        assertEquals("Vault (phone) (1).kdbx", storage.metadata(second).displayName)
        assertEquals(0L, storage.metadata(second).size)
        assertEquals(DeleteResult.DELETED, storage.delete(second))
        assertEquals(DeleteResult.UNSUPPORTED, storage.delete(kept))
        assertEquals(ReadResult.Failed(StorageFailure.NOT_FOUND), storage.read(second, 10))
    }

    @Test
    fun `a prefix read returns at most the requested bytes and records the count`() = runBlocking {
        val long = storage.readPrefix(loc, 8) as ReadResult.Bytes
        assertContentEquals(ByteArray(8) { 7 }, long.bytes)
        val short = storage.readPrefix(loc, 1_000) as ReadResult.Bytes
        assertContentEquals(ByteArray(100) { 7 }, short.bytes)
        assertEquals(listOf(8, 1_000), storage.prefixReads)
        assertEquals(0, storage.reads)
    }

    @Test
    fun `a prefix read honours scripted failures except TOO_LARGE, which it never reports`() = runBlocking {
        for (cause in StorageFailure.entries - StorageFailure.TOO_LARGE) {
            storage.fail(loc, cause)
            assertEquals(ReadResult.Failed(cause), storage.readPrefix(loc, 8))
        }
        storage.fail(loc, StorageFailure.TOO_LARGE)
        assertContentEquals(ByteArray(8) { 7 }, (storage.readPrefix(loc, 8) as ReadResult.Bytes).bytes)
        assertEquals(ReadResult.Failed(StorageFailure.NOT_FOUND), storage.readPrefix("content://fake/missing", 8))
    }

    @Test
    fun `metadata reports only what was described`() = runBlocking {
        assertEquals(FileMetadata(null, 100, null), storage.metadata(loc))
        storage.describe(loc, "Vault.kdbx", 1_000L)
        assertEquals(FileMetadata("Vault.kdbx", 100, 1_000L), storage.metadata(loc))
    }
}
