package org.onekash.kashpass.vault.storage

import java.io.IOException
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.testing.FakeVaultStorage

// Real time on real threads: the fake blocks a thread as a stuck provider call does, which
// virtual time can't model.
class DeadlineStorageTest {

    private val loc = "content://fake/vault.kdbx"
    private val bytes = byteArrayOf(1, 2, 3)
    private val fake = FakeVaultStorage().apply { put(loc, bytes) }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val deadline = Duration.ofMillis(200)
    private val storage = DeadlineStorage(fake, scope, deadline)

    @AfterEach
    fun tearDown() {
        fake.releaseReads()
        scope.cancel()
    }

    private fun <T> real(block: suspend () -> T): T = runBlocking { withContext(Dispatchers.Default) { block() } }

    @Test
    fun `an answered call returns its own result`() = real {
        assertContentEquals(bytes, assertIs<ReadResult.Bytes>(storage.read(loc, 100)).bytes)
        assertEquals(ReadResult.Failed(StorageFailure.TOO_LARGE), storage.read(loc, 2))
        assertEquals(Writability.WRITABLE, storage.writability(loc))
        assertEquals(WriteResult.Written, storage.write(loc, byteArrayOf(9)))
        assertContentEquals(byteArrayOf(9), fake.bytes(loc))
        assertEquals(1L, storage.metadata(loc).size)
        assertEquals(DeleteResult.UNSUPPORTED, storage.delete(loc))
    }

    @Test
    fun `an exception from the provider reaches the caller unchanged`() {
        val error = IOException("binder died")
        fake.throwOnRead(error)
        val thrown = assertThrows<IOException> { real { storage.read(loc, 100) } }
        assertEquals("binder died", thrown.message)
    }

    @Test
    fun `a read the provider doesn't answer stops at the deadline`() = real {
        fake.blockReads()
        val started = System.nanoTime()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(loc, 100))
        val millis = (System.nanoTime() - started) / 1_000_000
        assertTrue(millis in 150..2_000, "returned after $millis ms")
    }

    @Test
    fun `a writability check the provider doesn't answer reports TIMED_OUT`() = real {
        fake.blockReads()
        assertEquals(Writability.TIMED_OUT, storage.writability(loc))
    }

    @Test
    fun `stalled metadata and delete calls report nothing known and a failed delete`() = real {
        val gate = CountDownLatch(1)
        val stalling = object : VaultStorage by fake {
            override suspend fun metadata(location: String): FileMetadata {
                gate.await(60, TimeUnit.SECONDS)
                return fake.metadata(location)
            }

            override suspend fun delete(location: String): DeleteResult {
                gate.await(60, TimeUnit.SECONDS)
                return DeleteResult.DELETED
            }
        }
        val wrapped = DeadlineStorage(stalling, scope, deadline)
        try {
            assertEquals(FileMetadata(null, null, null), wrapped.metadata(loc))
            assertEquals(DeleteResult.FAILED, wrapped.delete(loc))
        } finally {
            gate.countDown()
        }
    }

    @Test
    fun `a second read joins the stalled one instead of starting another`() = real {
        fake.blockReads()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(loc, 100))
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(loc, 100))
        assertEquals(1, fake.reads)
    }

    @Test
    fun `a read that joins a stalled one gets its bytes when it finishes in time`() = real {
        fake.blockReads()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(loc, 100))
        val second = scope.async { storage.read(loc, 100) }
        delay(50)
        fake.releaseReads()
        assertContentEquals(bytes, assertIs<ReadResult.Bytes>(second.await()).bytes)
        assertEquals(1, fake.reads)
    }

    @Test
    fun `a read after a write never joins a read that started before it`() = real {
        fake.blockReads()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(loc, 100))
        storage.write(loc, byteArrayOf(7))
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(loc, 100))
        assertEquals(2, fake.reads)
    }

    @Test
    fun `reads of other locations are not held back by a stalled one`() = real {
        val other = "content://fake/other.kdbx"
        fake.put(other, bytes)
        fake.blockReads()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(loc, 100))
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(other, 100))
        assertEquals(2, fake.reads)
    }

    @Test
    fun `a fresh read never joins a stalled one`() = real {
        fake.blockReads()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(loc, 100))
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.readFresh(loc, 100))
        assertEquals(2, fake.reads)
    }

    @Test
    fun `a prefix read returns the delegate's prefix`() = real {
        assertContentEquals(byteArrayOf(1, 2), assertIs<ReadResult.Bytes>(storage.readPrefix(loc, 2)).bytes)
        assertContentEquals(bytes, assertIs<ReadResult.Bytes>(storage.readPrefix(loc, 100)).bytes)
        assertEquals(listOf(2, 100), fake.prefixReads)
    }

    @Test
    fun `a prefix read the provider doesn't answer stops at the deadline`() = real {
        fake.blockReads()
        val started = System.nanoTime()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.readPrefix(loc, 8))
        val millis = (System.nanoTime() - started) / 1_000_000
        assertTrue(millis in 150..2_000, "returned after $millis ms")
    }

    @Test
    fun `a prefix that arrives after the deadline is zero-filled`() = real {
        fake.blockReads()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.readPrefix(loc, 8))
        fake.releaseReads()
        val until = System.nanoTime() + 5_000_000_000L
        while (System.nanoTime() < until && fake.lastReturned?.all { it == 0.toByte() } != true) delay(10)
        val late = fake.lastReturned
        assertEquals(3, late?.size)
        assertTrue(late!!.all { it == 0.toByte() }, "the late prefix kept its bytes")
    }

    // Waits until the provider's late result is zero-filled, then checks it.
    private suspend fun assertLateResultZeroFilled() {
        val until = System.nanoTime() + 5_000_000_000L
        while (System.nanoTime() < until && fake.lastReturned?.all { it == 0.toByte() } != true) delay(10)
        val late = fake.lastReturned
        assertEquals(3, late?.size)
        assertTrue(late!!.all { it == 0.toByte() }, "the late result kept its bytes")
    }

    @Test
    fun `a fresh read that arrives after the deadline is zero-filled`() = real {
        fake.blockReads()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.readFresh(loc, 100))
        fake.releaseReads()
        assertLateResultZeroFilled()
    }

    @Test
    fun `a fresh read whose caller was cancelled is zero-filled when it arrives`() = real {
        fake.blockReads()
        val caller = scope.launch { storage.readFresh(loc, 100) }
        while (fake.reads == 0) delay(5)
        caller.cancelAndJoin()
        fake.releaseReads()
        assertLateResultZeroFilled()
    }

    @Test
    fun `a prefix whose caller was cancelled is zero-filled when it arrives`() = real {
        fake.blockReads()
        val caller = scope.launch { storage.readPrefix(loc, 8) }
        while (fake.prefixReads.isEmpty()) delay(5)
        caller.cancelAndJoin()
        fake.releaseReads()
        assertLateResultZeroFilled()
    }

    @Test
    fun `a prefix read never joins a stalled read`() = real {
        fake.blockReads()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.read(loc, 100))
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), storage.readPrefix(loc, 8))
        assertEquals(1, fake.reads)
        assertEquals(listOf(8), fake.prefixReads)
    }

    @Test
    fun `a read that started while a write ran is not joined after the write ends`() = real {
        val writing = CountDownLatch(1)
        val finish = CountDownLatch(1)
        val slowWrite = object : VaultStorage by fake {
            override suspend fun write(location: String, bytes: ByteArray): WriteResult {
                writing.countDown()
                finish.await(60, TimeUnit.SECONDS)
                return fake.write(location, bytes)
            }
        }
        val wrapped = DeadlineStorage(slowWrite, scope, deadline)
        val write = scope.async { wrapped.write(loc, byteArrayOf(7)) }
        writing.await(5, TimeUnit.SECONDS)
        fake.blockReads()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), wrapped.read(loc, 100))
        finish.countDown()
        write.await()
        assertEquals(ReadResult.Failed(StorageFailure.TIMED_OUT), wrapped.read(loc, 100))
        assertEquals(2, fake.reads)
    }
}
