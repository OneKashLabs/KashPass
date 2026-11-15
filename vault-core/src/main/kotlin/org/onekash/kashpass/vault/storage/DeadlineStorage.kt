package org.onekash.kashpass.vault.storage

import java.time.Duration
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Gives every call to [delegate] except [write] at most [timeout] (30 s, the same as a save's
 * write). A call the provider doesn't answer in time reports
 * [StorageFailure.TIMED_OUT], [Writability.TIMED_OUT], nothing known, or a failed delete. A
 * provider call blocked in the binder can't be cancelled, so each runs in [scope] and finishes
 * there; its late result is dropped. [write] passes through: the saver keeps its own deadline and
 * classifies a write that ran past it.
 *
 * One provider read runs per location at a time for [read]. A read that arrives while an earlier
 * one runs takes that one's result (within its own deadline) instead of starting another, unless
 * a write to the location began or ended after the earlier read started: then the earlier bytes
 * can be stale and a new read starts. [readFresh] and [readPrefix] never join.
 * [DeadlineStorageTest] pins each rule.
 */
class DeadlineStorage(
    private val delegate: VaultStorage,
    /** Outlives every caller, so an abandoned provider call has somewhere to finish. */
    private val scope: CoroutineScope,
    private val timeout: Duration = Duration.ofSeconds(30),
) : VaultStorage {

    private class Running(val job: Deferred<ReadResult>, val writes: Long, val maxBytes: Int)

    private val lock = Any()
    private val running = HashMap<String, Running>()
    private val writeEvents = HashMap<String, Long>()

    override suspend fun read(location: String, maxBytes: Int): ReadResult {
        var joined = false
        val job = synchronized(lock) {
            val writes = writeEvents[location] ?: 0L
            val earlier = running[location]?.takeIf { it.job.isActive && it.writes == writes && it.maxBytes == maxBytes }
            if (earlier != null) {
                joined = true
                earlier.job
            } else {
                scope.async { delegate.read(location, maxBytes) }.also { job ->
                    running[location] = Running(job, writes, maxBytes)
                    job.invokeOnCompletion { synchronized(lock) { if (running[location]?.job === job) running.remove(location) } }
                }
            }
        }
        val result = withTimeoutOrNull(timeout.toMillis()) { job.await() } ?: return ReadResult.Failed(StorageFailure.TIMED_OUT)
        // Each caller owns its array: the first caller can be using or clearing it.
        return if (joined && result is ReadResult.Bytes) ReadResult.Bytes(result.bytes.copyOf()) else result
    }

    /** Reads like [VaultStorage.readFresh] within the deadline, through [owned]. */
    override suspend fun readFresh(location: String, maxBytes: Int): ReadResult = owned { delegate.read(location, maxBytes) }

    /** Reads like [VaultStorage.readPrefix] within the deadline, through [owned]. */
    override suspend fun readPrefix(location: String, count: Int): ReadResult = owned { delegate.readPrefix(location, count) }

    // Runs [read] within the deadline for one caller. Bytes that arrive after the deadline, or
    // after the caller was cancelled (a lock, Back), have no caller and are zero-filled: they can
    // be key-file material. [claimed] is set by whichever side finishes first, the provider call
    // with its result or the caller giving up at the deadline. A provider call that finds it set
    // zero-fills its result; a caller that finds it set takes the result, or zero-fills it when
    // cancelled. DeadlineStorageTest pins it.
    private suspend fun owned(read: suspend () -> ReadResult): ReadResult {
        val claimed = AtomicBoolean(false)
        val job = scope.async {
            read().also { result ->
                if (!claimed.compareAndSet(false, true) && result is ReadResult.Bytes) result.bytes.fill(0)
            }
        }
        try {
            withTimeoutOrNull(timeout.toMillis()) { job.await() }?.let { return it }
            if (claimed.compareAndSet(false, true)) return ReadResult.Failed(StorageFailure.TIMED_OUT)
            // The result arrived between the deadline and the claim: the caller takes it.
            return job.await()
        } catch (e: CancellationException) {
            if (!claimed.compareAndSet(false, true)) scope.launch { (job.await() as? ReadResult.Bytes)?.bytes?.fill(0) }
            throw e
        }
    }

    override suspend fun writability(location: String): Writability = within(Writability.TIMED_OUT) { delegate.writability(location) }

    override suspend fun write(location: String, bytes: ByteArray): WriteResult {
        bumpWrites(location)
        try {
            return delegate.write(location, bytes)
        } finally {
            bumpWrites(location)
        }
    }

    // Counts write starts and ends, so a read that began during a write is never joined after it.
    private fun bumpWrites(location: String) {
        synchronized(lock) { writeEvents[location] = (writeEvents[location] ?: 0L) + 1 }
    }

    override suspend fun metadata(location: String): FileMetadata = within(FileMetadata(null, null, null)) { delegate.metadata(location) }

    override suspend fun delete(location: String): DeleteResult = within(DeleteResult.FAILED) { delegate.delete(location) }

    private suspend fun <T> within(fallback: T, call: suspend () -> T): T {
        val job = scope.async { call() }
        return withTimeoutOrNull(timeout.toMillis()) { job.await() } ?: fallback
    }
}
