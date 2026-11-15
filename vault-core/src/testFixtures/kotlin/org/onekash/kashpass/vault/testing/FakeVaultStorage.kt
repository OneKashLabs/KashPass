package org.onekash.kashpass.vault.testing

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.onekash.kashpass.vault.storage.DeleteResult
import org.onekash.kashpass.vault.storage.FileMetadata
import org.onekash.kashpass.vault.storage.ReadResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.VaultStorage
import org.onekash.kashpass.vault.storage.WriteResult
import org.onekash.kashpass.vault.storage.Writability

/**
 * Shared fake of [VaultStorage]. It serves bytes or a scripted failure per location, enforces the
 * maxBytes contract, truncates on write like mode "rwt", and can script what real providers do:
 * a revoked grant, a document that isn't writable, a failure before or after the file was opened
 * (leaving a partial write), a provider that ignores truncation, one that reads back different
 * bytes, and a read, writability check or write that blocks its thread until released. It records
 * every read, prefix read and write.
 */
class FakeVaultStorage : VaultStorage {

    // Concurrent: a blocked write finishes on its own thread while tests read on another.
    private val files = ConcurrentHashMap<String, ByteArray>()
    private val failures = mutableMapOf<String, StorageFailure>()
    private val writability = mutableMapOf<String, Writability>()
    private val writeFailures = mutableMapOf<String, WriteResult.Failed>()
    private val ignoresTruncation = mutableSetOf<String>()
    private val failsAfterFullWrite = mutableSetOf<String>()
    private val readsBackDifferent = mutableSetOf<String>()
    private val readsBackDifferentOnce = mutableSetOf<String>()
    private val names = mutableMapOf<String, String>()
    private val modified = mutableMapOf<String, Long>()
    private val deletable = mutableSetOf<String>()
    private var created = 0

    private var readError: Throwable? = null

    @Volatile
    private var gate: CountDownLatch? = null

    /** Number of [read] calls so far. */
    var reads = 0
        private set

    private val prefixCounts = mutableListOf<Int>()

    /** The count of each [readPrefix] call so far, in order. */
    val prefixReads: List<Int>
        get() = synchronized(this) { prefixCounts.toList() }

    /** Number of [write] calls that reached the file (not refused before opening). */
    var writes = 0
        private set

    /** Thread name of the last [read]. */
    var lastReadThread: String? = null
        private set

    /** The array the last successful [read] or [readPrefix] returned. */
    var lastReturned: ByteArray? = null
        private set

    @Volatile
    private var readGate: CountDownLatch? = null

    /** Runs inside every [read] after its gate and before it returns: a lock during a read. */
    @Volatile
    var onRead: (() -> Unit)? = null

    /** Makes the next reads, prefix reads and writability checks block until [releaseReads]. */
    fun blockReads() {
        readGate = CountDownLatch(1)
    }

    /** Lets blocked reads, prefix reads and writability checks continue. */
    fun releaseReads() {
        readGate?.countDown()
        readGate = null
    }

    // Blocks the thread, not the coroutine, as a provider call stuck in the binder does.
    private fun waitForReadGate() {
        readGate?.await(60, TimeUnit.SECONDS)
    }

    /** Signalled when a blocked write has started and is blocked until [releaseWrites]. */
    val writeStarted = CountDownLatch(1)

    /** Serves [bytes] at [location] from now on. */
    fun put(location: String, bytes: ByteArray) {
        failures.remove(location)
        files[location] = bytes.copyOf()
    }

    /** The bytes stored at [location], or null. */
    fun bytes(location: String): ByteArray? = files[location]?.copyOf()

    /**
     * Makes reads and prefix reads of [location] fail with [cause] from now on. Prefix reads
     * ignore [StorageFailure.TOO_LARGE] ([VaultStorage.readPrefix] never reports it).
     */
    fun fail(location: String, cause: StorageFailure) {
        failures[location] = cause
    }

    /** Makes every read and prefix read throw [error], as a buggy provider or full heap does. */
    fun throwOnRead(error: Throwable) {
        readError = error
    }

    /** Makes reads of [location] succeed again. */
    fun recover(location: String) {
        failures.remove(location)
    }

    /** Reports [value] for [location] instead of the default (WRITABLE for content: locations). */
    fun setWritability(location: String, value: Writability) {
        writability[location] = value
    }

    /**
     * Makes writes to [location] fail with [cause]. With [afterOpen], the file is truncated and
     * the first half of the new bytes is written before the failure, as a dropped connection does.
     */
    fun failWrites(location: String, cause: StorageFailure, afterOpen: Boolean) {
        writeFailures[location] = WriteResult.Failed(cause, afterOpen)
    }

    /**
     * Makes writes to [location] store every byte and then fail, as a provider that reports an
     * error on close after the data landed does.
     */
    fun failAfterFullWrite(location: String) {
        failsAfterFullWrite += location
    }

    /** Makes writes to [location] succeed again. */
    fun allowWrites(location: String) {
        writeFailures.remove(location)
        failsAfterFullWrite.remove(location)
    }

    /** Makes [location] behave like a provider that opens "rwt" without truncating. */
    fun ignoreTruncation(location: String) {
        ignoresTruncation += location
    }

    /** Makes [location] store something other than what was written (a byte flipped). */
    fun readBackDifferent(location: String) {
        readsBackDifferent += location
    }

    /** Makes the next full write to [location] flip one byte, as [readBackDifferent] does. */
    fun readBackDifferentOnce(location: String) {
        readsBackDifferentOnce += location
    }

    /** Makes the next writes block their thread until [releaseWrites]. */
    fun blockWrites() {
        gate = CountDownLatch(1)
    }

    /** Lets blocked writes continue. */
    fun releaseWrites() {
        gate?.countDown()
        gate = null
    }

    /**
     * Creates an empty document the way the create-document picker does: the provider renames on
     * a clash ("name (1).kdbx"). Returns the new location.
     */
    fun createDocument(requestedName: String, deletable: Boolean = true): String {
        val base = requestedName.substringBeforeLast('.')
        val ext = requestedName.substringAfterLast('.', "")
        var name = requestedName
        var n = 1
        while (name in names.values) {
            name = if (ext.isEmpty()) "$base ($n)" else "$base ($n).$ext"
            n++
        }
        val location = "content://fake/created/${++created}"
        files[location] = ByteArray(0)
        names[location] = name
        if (deletable) this.deletable += location
        return location
    }

    /** Sets what [metadata] reports for [location]. */
    fun describe(location: String, name: String?, lastModifiedMillis: Long?) {
        if (name != null) names[location] = name else names.remove(location)
        if (lastModifiedMillis != null) modified[location] = lastModifiedMillis else modified.remove(location)
    }

    override suspend fun read(location: String, maxBytes: Int): ReadResult {
        synchronized(this) { reads++ }
        waitForReadGate()
        onRead?.invoke()
        lastReadThread = Thread.currentThread().name
        readError?.let { throw it }
        failures[location]?.let { return ReadResult.Failed(it) }
        val bytes = files[location] ?: return ReadResult.Failed(StorageFailure.NOT_FOUND)
        if (bytes.size > maxBytes) return ReadResult.Failed(StorageFailure.TOO_LARGE)
        return ReadResult.Bytes(bytes.copyOf()).also { lastReturned = it.bytes }
    }

    override suspend fun readPrefix(location: String, count: Int): ReadResult {
        synchronized(this) { prefixCounts += count }
        waitForReadGate()
        readError?.let { throw it }
        // A prefix read stops at [count] bytes, so a file too large to read whole returns a prefix.
        failures[location]?.takeIf { it != StorageFailure.TOO_LARGE }?.let { return ReadResult.Failed(it) }
        val bytes = files[location] ?: return ReadResult.Failed(StorageFailure.NOT_FOUND)
        return ReadResult.Bytes(bytes.copyOf(minOf(count, bytes.size))).also { lastReturned = it.bytes }
    }

    override suspend fun writability(location: String): Writability {
        waitForReadGate()
        return writability[location] ?: when {
            !location.startsWith("content://") -> Writability.NOT_CONTENT
            !files.containsKey(location) -> Writability.UNAVAILABLE
            else -> Writability.WRITABLE
        }
    }

    override suspend fun write(location: String, bytes: ByteArray): WriteResult {
        val refused = writeFailures[location]
        if (refused != null && !refused.afterOpen) return refused
        if (!files.containsKey(location)) return WriteResult.Failed(StorageFailure.NOT_FOUND, afterOpen = false)
        writes++
        gate?.let {
            writeStarted.countDown()
            // Blocks the thread, not the coroutine, as a provider call stuck in the binder does.
            it.await(60, TimeUnit.SECONDS)
        }
        val old = files.getValue(location)
        if (refused != null) {
            files[location] = bytes.copyOf(bytes.size / 2)
            return refused
        }
        var stored = if (location in ignoresTruncation && old.size > bytes.size) bytes + old.copyOfRange(bytes.size, old.size) else bytes.copyOf()
        val flip = location in readsBackDifferent || readsBackDifferentOnce.remove(location)
        if (flip && stored.isNotEmpty()) stored = stored.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }
        files[location] = stored
        if (location in failsAfterFullWrite) return WriteResult.Failed(StorageFailure.IO_FAILURE, afterOpen = true)
        return WriteResult.Written
    }

    override suspend fun metadata(location: String): FileMetadata =
        FileMetadata(names[location], files[location]?.size?.toLong(), modified[location])

    override suspend fun delete(location: String): DeleteResult = when {
        location !in deletable -> DeleteResult.UNSUPPORTED
        files.remove(location) == null -> DeleteResult.FAILED
        else -> {
            names.remove(location)
            deletable.remove(location)
            DeleteResult.DELETED
        }
    }
}
