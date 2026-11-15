package org.onekash.kashpass.platform

import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import androidx.core.net.toUri
import android.os.ParcelFileDescriptor
import android.os.Process
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.SyncFailedException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import org.onekash.kashpass.vault.storage.DeleteResult
import org.onekash.kashpass.vault.storage.FileMetadata
import org.onekash.kashpass.vault.storage.ReadResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.VaultStorage
import org.onekash.kashpass.vault.storage.WriteResult
import org.onekash.kashpass.vault.storage.Writability

/**
 * Reads and writes vault and key files through the Storage Access Framework, on [io]
 * (main-safe). Locations are content URI strings from the system file pickers. Each provider call
 * is a function, so tests can script any provider behavior; [forResolver] wires the real ones.
 *
 * [read] refuses a file the provider reports as larger than the limit without opening it. The
 * reported size is a hint: the read stops after maxBytes + 1 bytes whatever the provider reports.
 *
 * Writes open the document in mode "rwt" through [openWrite], never `openOutputStream` without
 * a mode, whose default "w" is not guaranteed to truncate (ContentResolver.openFileDescriptor).
 * A cloud storage provider has refused "wt" with "Unsupported mode"; "rwt" truncates the same way.
 */
class SafVaultStorage(
    private val io: CoroutineDispatcher,
    private val open: (Uri) -> InputStream?,
    private val size: (Uri) -> Long? = { null },
    /** Opens the document for writing in mode "rwt"; closing the stream must report every error. */
    private val openWrite: (Uri) -> OutputStream? = { null },
    /** The document's COLUMN_FLAGS, or null when the provider can't answer. */
    private val flags: (Uri) -> Int? = { null },
    private val hasWriteGrant: (Uri) -> Boolean = { false },
    private val describe: (Uri) -> FileMetadata = { FileMetadata(null, null, null) },
    /** Deletes the document; true when the provider reports success. */
    private val deleteDocument: (Uri) -> Boolean = { false },
) : VaultStorage {

    override suspend fun read(location: String, maxBytes: Int): ReadResult = withContext(io) { readNow(location, maxBytes) }

    private fun readNow(location: String, maxBytes: Int): ReadResult = mapReadFailures {
        val uri = location.toUri()
        val reported = size(uri)
        if (reported != null && reported > maxBytes) {
            ReadResult.Failed(StorageFailure.TOO_LARGE)
        } else {
            val stream = open(uri) ?: return ReadResult.Failed(StorageFailure.IO_FAILURE)
            stream.use { readCapped(it, maxBytes) }
        }
    }

    /**
     * Opens the file without asking its size and reads until [count] bytes or the end. The buffer
     * is zero-filled on every path that doesn't return it, as [VaultStorage.readPrefix] requires.
     */
    override suspend fun readPrefix(location: String, count: Int): ReadResult = withContext(io) {
        mapReadFailures {
            val stream = open(location.toUri()) ?: return@mapReadFailures ReadResult.Failed(StorageFailure.IO_FAILURE)
            val prefix = ByteArray(count)
            var returned = false
            try {
                val n = stream.use { fill(it, prefix) }
                if (n == count) {
                    returned = true
                    ReadResult.Bytes(prefix)
                } else {
                    ReadResult.Bytes(prefix.copyOf(n))
                }
            } finally {
                if (!returned) prefix.fill(0)
            }
        }
    }

    // A documents provider's exception crosses the binder to the caller (IllegalArgumentException,
    // IllegalStateException, NullPointerException, UnsupportedOperationException), so any
    // RuntimeException is a failed read, never a crash; a cancellation, itself an
    // IllegalStateException, is rethrown. SafVaultStorageTest pins it.
    private inline fun mapReadFailures(read: () -> ReadResult): ReadResult = try {
        read()
    } catch (e: FileNotFoundException) {
        ReadResult.Failed(StorageFailure.NOT_FOUND)
    } catch (e: SecurityException) {
        ReadResult.Failed(StorageFailure.PERMISSION_REVOKED)
    } catch (e: IOException) {
        ReadResult.Failed(StorageFailure.IO_FAILURE)
    } catch (e: CancellationException) {
        throw e
    } catch (e: RuntimeException) {
        ReadResult.Failed(StorageFailure.IO_FAILURE)
    }

    /**
     * Checks in order: a content URI, a write grant held by KashPass, and the provider's flags
     * (FLAG_VIRTUAL_DOCUMENT clear). FLAG_SUPPORTS_WRITE is not required: Dropbox and OneDrive
     * leave it unset on files they write. A provider that refuses fails the write before any byte
     * is written, and the read-back catches one that accepts bytes it doesn't keep.
     */
    override suspend fun writability(location: String): Writability = withContext(io) {
        val uri = location.toUri()
        when {
            uri.scheme != ContentResolver.SCHEME_CONTENT -> Writability.NOT_CONTENT
            !hasWriteGrant(uri) -> Writability.NO_WRITE_GRANT
            else -> {
                val flags = flags(uri)
                when {
                    flags == null -> Writability.UNAVAILABLE
                    flags and DocumentsContract.Document.FLAG_VIRTUAL_DOCUMENT != 0 -> Writability.NOT_WRITABLE
                    else -> Writability.WRITABLE
                }
            }
        }
    }

    override suspend fun write(location: String, bytes: ByteArray): WriteResult = withContext(io) {
        val uri = location.toUri()
        val stream = try {
            openWrite(uri) ?: return@withContext WriteResult.Failed(StorageFailure.IO_FAILURE, afterOpen = false)
        } catch (e: Exception) {
            return@withContext WriteResult.Failed(failureOf(e), afterOpen = false)
        }
        try {
            stream.use { it.write(bytes) }
            WriteResult.Written
        } catch (e: Exception) {
            WriteResult.Failed(failureOf(e), afterOpen = true)
        }
    }

    override suspend fun metadata(location: String): FileMetadata = withContext(io) { describe(location.toUri()) }

    override suspend fun delete(location: String): DeleteResult = withContext(io) {
        val uri = location.toUri()
        val flags = flags(uri)
        when {
            flags == null || flags and DocumentsContract.Document.FLAG_SUPPORTS_DELETE == 0 -> DeleteResult.UNSUPPORTED
            else -> try {
                if (deleteDocument(uri)) DeleteResult.DELETED else DeleteResult.FAILED
            } catch (e: Exception) {
                DeleteResult.FAILED
            }
        }
    }

    // A provider can throw anything across the binder; these are the ones with a distinct fix.
    private fun failureOf(e: Exception) = when (e) {
        is FileNotFoundException -> StorageFailure.NOT_FOUND
        is SecurityException -> StorageFailure.PERMISSION_REVOKED
        else -> StorageFailure.IO_FAILURE
    }

    // Reads into fixed chunks and copies them once into the result, so memory peaks at twice the
    // file size; a growing buffer would reach three times while it doubles. Every chunk is
    // zero-filled before this returns or throws: a key file is read this way.
    private fun readCapped(stream: InputStream, maxBytes: Int): ReadResult {
        val chunks = ArrayList<ByteArray>()
        try {
            var total = 0L
            while (true) {
                val wanted = minOf(CHUNK.toLong(), maxBytes + 1L - total).toInt()
                if (wanted <= 0) return ReadResult.Failed(StorageFailure.TOO_LARGE)
                val chunk = ByteArray(wanted)
                chunks += chunk
                val n = fill(stream, chunk)
                total += n
                if (n < wanted) break
            }
            val out = ByteArray(total.toInt())
            var offset = 0
            for (chunk in chunks) {
                val n = minOf(chunk.size, out.size - offset)
                chunk.copyInto(out, offset, 0, n)
                offset += n
            }
            return ReadResult.Bytes(out)
        } finally {
            for (chunk in chunks) chunk.fill(0)
        }
    }

    // Reads until [chunk] is full or the stream ends; InputStream.readNBytes needs API 33.
    private fun fill(stream: InputStream, chunk: ByteArray): Int {
        var n = 0
        while (n < chunk.size) {
            val read = stream.read(chunk, n, chunk.size - n)
            if (read < 0) break
            n += read
        }
        return n
    }

    companion object {
        private const val CHUNK = 64 * 1024

        /** Returns storage over the app's content resolver that checks grants for this process. */
        fun forResolver(context: Context, io: CoroutineDispatcher): SafVaultStorage {
            val resolver = context.contentResolver
            return SafVaultStorage(
                io = io,
                open = { resolver.openInputStream(it) },
                size = sizeFrom(resolver),
                openWrite = openWriteFrom(resolver),
                flags = flagsFrom(resolver),
                hasWriteGrant = { uri ->
                    context.checkUriPermission(uri, Process.myPid(), Process.myUid(), Intent.FLAG_GRANT_WRITE_URI_PERMISSION) ==
                        PackageManager.PERMISSION_GRANTED
                },
                describe = metadataFrom(resolver),
                deleteDocument = { DocumentsContract.deleteDocument(resolver, it) },
            )
        }

        /**
         * Opens the document in mode "rwt" (read-write, truncate). Closing the returned stream
         * flushes, syncs where the descriptor is a file (a pipe can't sync), checks the descriptor
         * for an error the provider reported, and closes it; any of these failing throws.
         */
        fun openWriteFrom(resolver: ContentResolver): (Uri) -> OutputStream? = { uri ->
            resolver.openFileDescriptor(uri, "rwt")?.let(::CheckedOutput)
        }

        /** Reads the provider's COLUMN_FLAGS for a URI; null when unknown or failing. */
        fun flagsFrom(resolver: ContentResolver): (Uri) -> Int? = { uri ->
            try {
                resolver.query(uri, arrayOf(DocumentsContract.Document.COLUMN_FLAGS), null, null, null)?.use {
                    if (it.moveToFirst() && !it.isNull(0)) it.getInt(0) else null
                }
            } catch (e: RuntimeException) {
                null
            }
        }

        /** Reads the display name, size and last-modified time; an omitted value is null. */
        fun metadataFrom(resolver: ContentResolver): (Uri) -> FileMetadata = { uri ->
            val columns = arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE, DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            try {
                resolver.query(uri, columns, null, null, null)?.use { c ->
                    if (!c.moveToFirst()) return@use null
                    fun index(name: String) = c.getColumnIndex(name).takeIf { it >= 0 && !c.isNull(it) }
                    FileMetadata(
                        displayName = index(OpenableColumns.DISPLAY_NAME)?.let(c::getString),
                        size = index(OpenableColumns.SIZE)?.let(c::getLong),
                        lastModifiedMillis = index(DocumentsContract.Document.COLUMN_LAST_MODIFIED)?.let(c::getLong),
                    )
                }
            } catch (e: RuntimeException) {
                null
            } ?: FileMetadata(null, null, null)
        }

        /** Reads the provider's [OpenableColumns.SIZE] for a URI; null when unknown or failing. */
        fun sizeFrom(resolver: ContentResolver): (Uri) -> Long? = { uri ->
            try {
                resolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use {
                    if (it.moveToFirst() && !it.isNull(0)) it.getLong(0) else null
                }
            } catch (e: RuntimeException) {
                // A provider can throw any exception; the read enforces the limit on its own.
                null
            }
        }
    }
}

/** The write side of a "rwt" descriptor; [close] reports every failure the descriptor can see. */
private class CheckedOutput(private val pfd: ParcelFileDescriptor) : OutputStream() {
    private val out = FileOutputStream(pfd.fileDescriptor)

    override fun write(b: Int) = out.write(b)
    override fun write(b: ByteArray, off: Int, len: Int) = out.write(b, off, len)

    override fun close() {
        try {
            out.flush()
            try {
                out.fd.sync()
            } catch (e: SyncFailedException) {
                // Pipes and sockets can't sync; the provider owns durability for those.
            }
            pfd.checkError()
        } finally {
            pfd.close()
        }
    }
}
