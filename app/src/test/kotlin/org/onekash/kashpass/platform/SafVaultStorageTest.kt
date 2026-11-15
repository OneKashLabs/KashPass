package org.onekash.kashpass.platform

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import androidx.test.core.app.ApplicationProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.Executors
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.storage.DeleteResult
import org.onekash.kashpass.vault.storage.FileMetadata
import org.onekash.kashpass.vault.storage.ReadResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.WriteResult
import org.onekash.kashpass.vault.storage.Writability
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class SafVaultStorageTest {

    private val ioThreads = Executors.newSingleThreadExecutor { Thread(it, "storage-io") }
    private val io = ioThreads.asCoroutineDispatcher()

    private fun storage(size: (Uri) -> Long? = { null }, open: (Uri) -> InputStream?) = SafVaultStorage(io, open, size)

    @After
    fun tearDown() {
        FakeDocumentsProvider.reset()
        ioThreads.shutdown()
    }

    @Test
    fun `the read runs on the injected dispatcher, not the caller's thread`() {
        var thread = ""
        read(storage { thread = Thread.currentThread().name; ByteArrayInputStream(ByteArray(1)) })
        // Coroutine debug mode appends " @coroutine#n" to the thread name.
        assertEquals("storage-io", thread.substringBefore(" @"))
    }

    @Test
    fun `an exception a documents provider throws on open is a read failure, for a read and a prefix read`() {
        // The binder carries these from a provider's openFile to the caller.
        for (thrown in listOf(IllegalArgumentException("p"), IllegalStateException("p"), NullPointerException("p"), UnsupportedOperationException("p"))) {
            val storage = storage { throw thrown }
            assertEquals(thrown.toString(), ReadResult.Failed(StorageFailure.IO_FAILURE), read(storage))
            assertEquals(thrown.toString(), ReadResult.Failed(StorageFailure.IO_FAILURE), runBlocking { storage.readPrefix("content://drive/doc/1", 8) })
        }
    }

    @Test
    fun `a cancellation during the provider call is rethrown, not a read failure`() {
        val storage = storage { throw kotlinx.coroutines.CancellationException("cancelled") }
        val thrown = runCatching { read(storage) }.exceptionOrNull()
        assertTrue("got $thrown", thrown is kotlinx.coroutines.CancellationException)
    }

    private fun read(storage: SafVaultStorage, max: Int = 1_000): ReadResult =
        runBlocking { storage.read("content://drive/doc/1", max) }

    @Test
    fun `reads the whole file into one array`() {
        val bytes = ByteArray(5_000) { it.toByte() }
        val result = read(storage { ByteArrayInputStream(bytes) }, max = 10_000) as ReadResult.Bytes
        assertArrayEquals(bytes, result.bytes)
    }

    @Test
    fun `a file larger than maxBytes is TooLarge after reading at most maxBytes plus one`() {
        val counting = CountingStream(ByteArray(10_000))
        val result = read(storage { counting }, max = 1_000)
        assertEquals(ReadResult.Failed(StorageFailure.TOO_LARGE), result)
        assertTrue("read ${counting.count} bytes", counting.count <= 1_001)
        assertTrue(counting.closed)
    }

    @Test
    fun `a file the provider reports as larger than maxBytes is TooLarge without being opened`() {
        var opened = 0
        val result = read(storage(size = { 1_001 }) { opened++; ByteArrayInputStream(ByteArray(10)) }, max = 1_000)
        assertEquals(ReadResult.Failed(StorageFailure.TOO_LARGE), result)
        assertEquals(0, opened)
    }

    @Test
    fun `a wrong or missing size report changes nothing about what is read`() {
        val bytes = ByteArray(5_000) { it.toByte() }
        for (size in listOf<Long?>(null, 0, 10, 4_999, 5_001, 10_000)) {
            val result = read(storage(size = { size }) { ByteArrayInputStream(bytes) }, max = 10_000)
            assertArrayEquals("reported $size", bytes, (result as ReadResult.Bytes).bytes)
        }
        val tooLong = read(storage(size = { 10 }) { ByteArrayInputStream(ByteArray(1_500)) }, max = 1_000)
        assertEquals(ReadResult.Failed(StorageFailure.TOO_LARGE), tooLong)
    }

    @Test
    fun `the production size lookup reads OpenableColumns SIZE and survives a failing provider`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        Robolectric.setupContentProvider(FakeDocumentsProvider::class.java, FakeDocumentsProvider.AUTHORITY)
        val size = SafVaultStorage.sizeFrom(context.contentResolver)
        assertEquals(1_975L, size(FakeDocumentsProvider.URI))
        FakeDocumentsProvider.size = null
        assertNull(size(FakeDocumentsProvider.URI))
        FakeDocumentsProvider.failure = IllegalArgumentException("unknown document")
        assertNull(size(FakeDocumentsProvider.URI))
        assertNull(size(Uri.parse("content://no.such.authority/doc")))
    }

    @Test
    fun `provider failures map to storage failures`() {
        val cases = listOf<Pair<(Uri) -> InputStream?, StorageFailure>>(
            { _: Uri -> throw FileNotFoundException() } to StorageFailure.NOT_FOUND,
            { _: Uri -> throw SecurityException() } to StorageFailure.PERMISSION_REVOKED,
            { _: Uri -> throw IOException("offline") } to StorageFailure.IO_FAILURE,
            { _: Uri -> null } to StorageFailure.IO_FAILURE,
            { _: Uri -> FailingStream() } to StorageFailure.IO_FAILURE,
        )
        for ((open, expected) in cases) assertEquals(ReadResult.Failed(expected), read(storage(open = open)))
    }

    @Test
    fun `the production storage reads through the content resolver`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val uri = Uri.parse("content://drive/doc/1")
        shadowOf(context.contentResolver).registerInputStream(uri, ByteArrayInputStream(byteArrayOf(1, 2, 3)))
        val result = runBlocking { SafVaultStorage.forResolver(context, io).read(uri.toString(), 10) }
        assertArrayEquals(byteArrayOf(1, 2, 3), (result as ReadResult.Bytes).bytes)
    }

    private fun readPrefix(storage: SafVaultStorage, count: Int = 8): ReadResult =
        runBlocking { storage.readPrefix("content://drive/doc/1", count) }

    @Test
    fun `a prefix read returns the first bytes, reads no further and closes the stream`() {
        val bytes = ByteArray(10_000) { it.toByte() }
        val counting = CountingStream(bytes)
        val result = readPrefix(storage { counting }) as ReadResult.Bytes
        assertArrayEquals(bytes.copyOf(8), result.bytes)
        assertEquals(8, counting.count)
        assertTrue(counting.closed)
    }

    @Test
    fun `a prefix read of a shorter file returns the whole file`() {
        val result = readPrefix(storage { ByteArrayInputStream(byteArrayOf(1, 2, 3)) }) as ReadResult.Bytes
        assertArrayEquals(byteArrayOf(1, 2, 3), result.bytes)
        val empty = readPrefix(storage { ByteArrayInputStream(ByteArray(0)) }) as ReadResult.Bytes
        assertEquals(0, empty.bytes.size)
    }

    @Test
    fun `a prefix read keeps reading a stream that returns one byte per read`() {
        val bytes = ByteArray(100) { it.toByte() }
        val trickle = object : ByteArrayInputStream(bytes) {
            override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, minOf(len, 1))
        }
        val result = readPrefix(storage { trickle }) as ReadResult.Bytes
        assertArrayEquals(bytes.copyOf(8), result.bytes)
    }

    @Test
    fun `a prefix read ignores the reported size and is never TooLarge`() {
        var asked = 0
        val result = readPrefix(storage(size = { asked++; Long.MAX_VALUE }) { ByteArrayInputStream(ByteArray(100)) }, count = 8)
        assertEquals(8, (result as ReadResult.Bytes).bytes.size)
        assertEquals(0, asked)
    }

    @Test
    fun `prefix read failures map to storage failures`() {
        val cases = listOf<Pair<(Uri) -> InputStream?, StorageFailure>>(
            { _: Uri -> throw FileNotFoundException() } to StorageFailure.NOT_FOUND,
            { _: Uri -> throw SecurityException() } to StorageFailure.PERMISSION_REVOKED,
            { _: Uri -> throw IOException("offline") } to StorageFailure.IO_FAILURE,
            { _: Uri -> null } to StorageFailure.IO_FAILURE,
            { _: Uri -> FailingStream() } to StorageFailure.IO_FAILURE,
        )
        for ((open, expected) in cases) assertEquals(ReadResult.Failed(expected), readPrefix(storage(open = open)))
    }

    @Test
    fun `the prefix read runs on the injected dispatcher`() {
        var thread = ""
        readPrefix(storage { thread = Thread.currentThread().name; ByteArrayInputStream(ByteArray(1)) })
        assertEquals("storage-io", thread.substringBefore(" @"))
    }

    private val loc = "content://drive/doc/1"

    private fun writer(
        flags: Int? = DocumentsContract.Document.FLAG_SUPPORTS_WRITE,
        grant: Boolean = true,
        openWrite: (Uri) -> OutputStream? = { ByteArrayOutputStream() },
    ) = SafVaultStorage(io, { null }, openWrite = openWrite, flags = { flags }, hasWriteGrant = { grant })

    @Test
    fun `writability checks scheme, grant, then virtual documents`() = runBlocking<Unit> {
        val supports = DocumentsContract.Document.FLAG_SUPPORTS_WRITE
        val virtual = DocumentsContract.Document.FLAG_VIRTUAL_DOCUMENT
        assertEquals(Writability.WRITABLE, writer().writability(loc))
        assertEquals(Writability.NOT_CONTENT, writer().writability("file:///sdcard/vault.kdbx"))
        assertEquals(Writability.NOT_CONTENT, writer().writability("vault.kdbx"))
        assertEquals(Writability.NO_WRITE_GRANT, writer(grant = false).writability(loc))
        // Dropbox and OneDrive leave FLAG_SUPPORTS_WRITE unset on files they write; the write
        // and its read-back settle it.
        assertEquals(Writability.WRITABLE, writer(flags = 0).writability(loc))
        assertEquals(Writability.WRITABLE, writer(flags = DocumentsContract.Document.FLAG_SUPPORTS_DELETE).writability(loc))
        assertEquals(Writability.NOT_WRITABLE, writer(flags = virtual).writability(loc))
        assertEquals(Writability.NOT_WRITABLE, writer(flags = supports or virtual).writability(loc))
        assertEquals(Writability.UNAVAILABLE, writer(flags = null).writability(loc))
    }

    @Test
    fun `a write closes the stream and only then counts as written`() = runBlocking<Unit> {
        var closed = false
        val sink = object : ByteArrayOutputStream() {
            override fun close() {
                closed = true
            }
        }
        assertEquals(WriteResult.Written, writer(openWrite = { sink }).write(loc, byteArrayOf(1, 2, 3)))
        assertArrayEquals(byteArrayOf(1, 2, 3), sink.toByteArray())
        assertTrue(closed)
    }

    @Test
    fun `write failures say whether the file was opened`() = runBlocking<Unit> {
        val before = listOf<Pair<(Uri) -> OutputStream?, StorageFailure>>(
            { _: Uri -> throw FileNotFoundException() } to StorageFailure.NOT_FOUND,
            { _: Uri -> throw SecurityException() } to StorageFailure.PERMISSION_REVOKED,
            { _: Uri -> throw IllegalArgumentException("mode rwt unsupported") } to StorageFailure.IO_FAILURE,
            { _: Uri -> null } to StorageFailure.IO_FAILURE,
        )
        for ((open, cause) in before) assertEquals(WriteResult.Failed(cause, afterOpen = false), writer(openWrite = open).write(loc, ByteArray(4)))
        val failsWriting = object : OutputStream() {
            override fun write(b: Int) = throw IOException("connection lost")
        }
        val failsClosing = object : ByteArrayOutputStream() {
            override fun close() = throw IOException("provider reported an error")
        }
        for (stream in listOf(failsWriting, failsClosing)) {
            assertEquals(WriteResult.Failed(StorageFailure.IO_FAILURE, afterOpen = true), writer(openWrite = { stream }).write(loc, ByteArray(4)))
        }
    }

    @Test
    fun `the production write opens the document in mode rwt and truncates`() = runBlocking<Unit> {
        val context = ApplicationProvider.getApplicationContext<Context>()
        Robolectric.setupContentProvider(FakeDocumentsProvider::class.java, FakeDocumentsProvider.AUTHORITY)
        val file = File.createTempFile("vault", ".kdbx").apply { writeBytes(ByteArray(100) { 7 }) }
        FakeDocumentsProvider.file = file
        val open = SafVaultStorage.openWriteFrom(context.contentResolver)
        val storage = SafVaultStorage(io, { null }, openWrite = open)
        assertEquals(WriteResult.Written, storage.write(FakeDocumentsProvider.URI.toString(), byteArrayOf(1, 2, 3)))
        assertEquals(listOf("rwt"), FakeDocumentsProvider.modes)
        assertArrayEquals(byteArrayOf(1, 2, 3), file.readBytes())
        file.delete()
    }

    @Test
    fun `the production flags and metadata lookups read the document columns and survive a failing provider`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        Robolectric.setupContentProvider(FakeDocumentsProvider::class.java, FakeDocumentsProvider.AUTHORITY)
        val flags = SafVaultStorage.flagsFrom(context.contentResolver)
        val metadata = SafVaultStorage.metadataFrom(context.contentResolver)
        assertEquals(DocumentsContract.Document.FLAG_SUPPORTS_WRITE, flags(FakeDocumentsProvider.URI))
        assertEquals(FileMetadata("Passwords.kdbx", 1_975L, 1_700_000_000_000), metadata(FakeDocumentsProvider.URI))
        FakeDocumentsProvider.size = null
        FakeDocumentsProvider.lastModified = null
        FakeDocumentsProvider.flags = null
        assertEquals(FileMetadata("Passwords.kdbx", null, null), metadata(FakeDocumentsProvider.URI))
        assertNull(flags(FakeDocumentsProvider.URI))
        FakeDocumentsProvider.failure = IllegalArgumentException("unknown document")
        assertNull(flags(FakeDocumentsProvider.URI))
        assertEquals(FileMetadata(null, null, null), metadata(FakeDocumentsProvider.URI))
    }

    @Test
    fun `delete calls the provider only when it reports delete support`() = runBlocking<Unit> {
        val context = ApplicationProvider.getApplicationContext<Context>()
        Robolectric.setupContentProvider(FakeDocumentsProvider::class.java, FakeDocumentsProvider.AUTHORITY)
        val storage = SafVaultStorage.forResolver(context, io)
        val location = FakeDocumentsProvider.URI.toString()
        assertEquals(DeleteResult.UNSUPPORTED, storage.delete(location))
        assertFalse(FakeDocumentsProvider.deleted)
        FakeDocumentsProvider.flags = DocumentsContract.Document.FLAG_SUPPORTS_DELETE
        assertEquals(DeleteResult.DELETED, storage.delete(location))
        assertTrue(FakeDocumentsProvider.deleted)
        val failing = SafVaultStorage(io, { null }, flags = { DocumentsContract.Document.FLAG_SUPPORTS_DELETE }, deleteDocument = { throw IllegalStateException() })
        assertEquals(DeleteResult.FAILED, failing.delete(location))
    }

    @Test
    fun `the production storage wires the grant check and the provider's flags`() = runBlocking<Unit> {
        // Robolectric grants every URI permission, so the refused-grant path is covered by the
        // injected check above; this checks that the real lookups reach the provider's flags.
        val context = ApplicationProvider.getApplicationContext<Context>()
        Robolectric.setupContentProvider(FakeDocumentsProvider::class.java, FakeDocumentsProvider.AUTHORITY)
        val storage = SafVaultStorage.forResolver(context, io)
        val location = FakeDocumentsProvider.URI.toString()
        assertEquals(Writability.WRITABLE, storage.writability(location))
        FakeDocumentsProvider.flags = DocumentsContract.Document.FLAG_SUPPORTS_WRITE or DocumentsContract.Document.FLAG_VIRTUAL_DOCUMENT
        assertEquals(Writability.NOT_WRITABLE, storage.writability(location))
    }

    private class CountingStream(bytes: ByteArray) : ByteArrayInputStream(bytes) {
        var count = 0
        var closed = false
        override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, len).also { if (it > 0) count += it }
        override fun read(): Int = super.read().also { if (it >= 0) count++ }
        override fun close() {
            closed = true
        }
    }

    private class FailingStream : InputStream() {
        override fun read(): Int = throw IOException("connection lost")
    }

    // Serves [bytes] and records every array the storage reads into; at the end it throws when
    // [failAtEnd], else reports the end of the stream.
    private class RecordingStream(bytes: ByteArray, private val failAtEnd: Boolean) : ByteArrayInputStream(bytes) {
        val buffers = mutableListOf<ByteArray>()
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (buffers.none { it === b }) buffers += b
            if (available() == 0 && failAtEnd) throw IOException("connection lost")
            return super.read(b, off, len)
        }
    }

    private fun content(size: Int) = ByteArray(size) { (it % 250 + 1).toByte() }

    private fun assertZeroed(stream: RecordingStream) {
        assertTrue(stream.buffers.isNotEmpty())
        for (buffer in stream.buffers) assertTrue("a ${buffer.size}-byte buffer kept bytes", buffer.all { it == 0.toByte() })
    }

    @Test
    fun `a prefix read that fails after some bytes leaves its buffer zeroed`() {
        val stream = RecordingStream(content(3), failAtEnd = true)
        assertEquals(ReadResult.Failed(StorageFailure.IO_FAILURE), readPrefix(storage { stream }))
        assertZeroed(stream)
    }

    @Test
    fun `a short prefix read zero-fills the buffer it doesn't return`() {
        val stream = RecordingStream(content(3), failAtEnd = false)
        val result = readPrefix(storage { stream }) as ReadResult.Bytes
        assertArrayEquals(content(3), result.bytes)
        assertZeroed(stream)
    }

    @Test
    fun `a read zero-fills every chunk it reads into, whether it returns, refuses or fails`() {
        val whole = RecordingStream(content(70_000), failAtEnd = false)
        assertArrayEquals(content(70_000), (read(storage { whole }, max = 100_000) as ReadResult.Bytes).bytes)
        assertEquals(2, whole.buffers.size)
        assertZeroed(whole)
        val tooLarge = RecordingStream(content(70_000), failAtEnd = false)
        assertEquals(ReadResult.Failed(StorageFailure.TOO_LARGE), read(storage { tooLarge }, max = 66_000))
        assertZeroed(tooLarge)
        val failing = RecordingStream(content(70_000), failAtEnd = true)
        assertEquals(ReadResult.Failed(StorageFailure.IO_FAILURE), read(storage { failing }, max = 100_000))
        assertZeroed(failing)
    }
}
