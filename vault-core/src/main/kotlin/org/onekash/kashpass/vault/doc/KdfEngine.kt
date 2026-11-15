package org.onekash.kashpass.vault.doc

import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import org.onekash.kashpass.vault.header.Argon2Variant
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.kdbx.Argon2Type
import org.onekash.kashpass.vault.kdbx.Bytes
import org.onekash.kashpass.vault.kdbx.Digests
import org.onekash.kashpass.vault.kdbx.KdbxException
import org.onekash.kashpass.vault.kdbx.KdfParameters as KdbxKdfParameters
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.policy.KdfPolicy
import org.onekash.kashpass.vault.policy.KdfRejection

/** A key-derivation setting [KdfEngine] refuses to derive with; no key was derived. */
internal class KdfOutOfBoundsException(val rejection: KdfRejection.OutOfBounds) : Exception()

/**
 * An Argon2 salt shorter than 8 bytes or longer than [KdbxHeaderReader.MAX_SALT]; no key was
 * derived.
 */
internal class KdfSaltException : Exception()

/**
 * Argon2's memory ([KdfPolicy.argon2MemoryUsedBytes]) is larger than one array can hold; nothing
 * was allocated. The opener reports that the vault needs more memory than this device has.
 */
internal class KdfTooLargeException : Exception()

/** How a [KdfEngine] exception ended a derivation, for the open and the save to report. */
internal sealed interface KdfFailure {
    /** [KdfOutOfBoundsException]: the policy refused the settings. */
    class OutOfBounds(val rejection: KdfRejection.OutOfBounds) : KdfFailure

    /** [KdfSaltException]. */
    data object Salt : KdfFailure

    /** [KdfTooLargeException]. */
    data object TooLarge : KdfFailure

    /** [KdbxException.AlgorithmUnavailable]: the platform lacks an algorithm the KDF uses. */
    data object Unavailable : KdfFailure

    companion object {
        /**
         * Returns what [e] from [KdfEngine.derive] means, or null for an exception that is none
         * of these. [ContainerDecode] and [VaultXmlCodec.encode] both translate through it.
         */
        fun of(e: Exception): KdfFailure? = when (e) {
            is KdfOutOfBoundsException -> OutOfBounds(e.rejection)
            is KdfSaltException -> Salt
            is KdfTooLargeException -> TooLarge
            is KdbxException.AlgorithmUnavailable -> Unavailable
            else -> null
        }
    }
}

/**
 * Derives the KDBX 4 transformed key for KDF parameters as
 * [org.onekash.kashpass.vault.kdbx.KdbxHeaderReader] builds them.
 */
internal fun interface KeyDerivation {
    /**
     * Returns the 32-byte transformed key for [compositeKey] with [parameters]; the caller owns
     * the result and zero-fills it. [compositeKey] stays the caller's.
     */
    fun derive(parameters: KdbxKdfParameters, compositeKey: ByteArray): ByteArray
}

/** Maps the container's KDF parameters to the [KdfSettings] that [KdfPolicy] checks. */
internal fun KdbxKdfParameters.toSettings(): KdfSettings = when (this) {
    is KdbxKdfParameters.Aes -> KdfSettings.AesKdf(rounds)
    is KdbxKdfParameters.Argon2 -> KdfSettings.Argon2(
        variant = when (type) {
            Argon2Type.ARGON2D -> Argon2Variant.ARGON2D
            Argon2Type.ARGON2ID -> Argon2Variant.ARGON2ID
        },
        iterations = iterations,
        memoryBytes = memoryBytes,
        parallelism = parallelism,
        version = version,
    )
}

/**
 * Derives the KDBX 4 transformed key for KashPass's own container, on open and on save:
 * AES-KDF, and Argon2d or Argon2id at version 0x10 or 0x13 with the optional secret key and
 * associated data.
 *
 * Argon2 follows RFC 9106 section 3 and fills the lanes of each slice at the same time: a block
 * reads only blocks of its own lane or of other lanes' finished segments (section 3.4.1.2), so the
 * lanes of one slice never touch the same block. The lanes run on min(parallelism, [processors])
 * workers; the calling thread is one of them, each worker has its own scratch blocks, and a slice
 * ends when every worker finished it. The memory is one array of m' blocks, allocated once by
 * [allocate] and shared. Memory in KiB is the header's byte count / 1024, rounded down; H0 hashes
 * that value, and the memory and the address generator's input use m' (that value raised to
 * 8 x parallelism and rounded down to a multiple of 4 x parallelism,
 * [KdfPolicy.argon2MemoryUsedBytes]). Version 0x10 overwrites blocks in later passes, 0x13 XORs
 * into them.
 *
 * AES-KDF encrypts each 16-byte half of the key with AES-ECB under the seed, one half per thread
 * on two threads, then hashes the result with SHA-256.
 *
 * [KdfEngineTest] checks RFC 9106 vectors, 820 cases from the phc-winner-argon2 reference library
 * and recorded keys for memory below 8 KiB per lane; the gated KeePass 2 tests open vaults
 * derived with each KDF. A failure on any worker (OutOfMemoryError,
 * [KdbxException.AlgorithmUnavailable] when the platform lacks a cipher or digest) is rethrown as
 * it was thrown, once every worker stopped; no worker thread is alive after [derive] returns or
 * throws. [beforeWork] runs on the worker before each Argon2 segment (with the lane) and each
 * AES-KDF half (with the half); tests use it to observe threads and inject failures.
 *
 * A derivation given a cancellation check calls it before each Argon2 slice, on the calling
 * thread, and in each AES-KDF half every [CANCEL_CHECK_ROUNDS] rounds; once it returns true the
 * derivation stops after the slice or chunk in progress, zero-fills its memory and throws
 * CancellationException. [KdfEngineTest] pins both.
 */
internal class KdfEngine(
    private val processors: () -> Int = { Runtime.getRuntime().availableProcessors() },
    private val allocate: (Int) -> LongArray = ::LongArray,
    private val beforeWork: (Int) -> Unit = {},
) : KeyDerivation {

    /** Derives with no cancellation check. */
    override fun derive(parameters: KdbxKdfParameters, compositeKey: ByteArray): ByteArray = derive(parameters, compositeKey, NEVER)

    /**
     * Returns the 32-byte transformed key for [compositeKey]; throws CancellationException once
     * [cancelled], called from the calling thread and from worker threads, returns true. Throws
     * [KdfOutOfBoundsException] before any allocation for a setting outside
     * [KdfPolicy.checkBounds], so a caller that skips the policy check derives nothing out of
     * bounds. An AES-KDF seed that is not 32 bytes is hashed with SHA-256 first; an Argon2 salt
     * under 8 bytes or over [KdbxHeaderReader.MAX_SALT] throws [KdfSaltException]; Argon2 memory
     * below 8 KiB per lane derives with [KdfPolicy.argon2MemoryUsedBytes] blocks while H0 keeps the
     * stated memory, and a block count past one array throws [KdfTooLargeException], both before
     * any allocation.
     */
    fun derive(parameters: KdbxKdfParameters, compositeKey: ByteArray, cancelled: () -> Boolean): ByteArray {
        val settings = parameters.toSettings()
        KdfPolicy.checkBounds(settings)?.let { throw KdfOutOfBoundsException(it) }
        return when (parameters) {
            is KdbxKdfParameters.Aes -> {
                val seed = if (parameters.seed.size == 32) parameters.seed else Digests.provider { MessageDigest.getInstance("SHA-256").digest(parameters.seed) }
                aesKdf(compositeKey, seed, parameters.rounds.toInt(), cancelled)
            }
            is KdbxKdfParameters.Argon2 -> {
                if (parameters.salt.size !in MIN_SALT_BYTES..KdbxHeaderReader.MAX_SALT) throw KdfSaltException()
                val blocks = KdfPolicy.argon2MemoryUsedBytes(settings as KdfSettings.Argon2) / 1024UL
                if (blocks * QWORDS.toULong() > Int.MAX_VALUE.toULong()) throw KdfTooLargeException()
                Argon2(
                    type = if (parameters.type == Argon2Type.ARGON2D) ARGON2D else ARGON2ID,
                    version = parameters.version.toInt(),
                    iterations = parameters.iterations.toInt(),
                    lanes = parameters.parallelism.toInt(),
                    memoryKib = (parameters.memoryBytes / 1024UL).toInt(),
                    blockCount = blocks.toInt(),
                    cancelled = cancelled,
                ).derive(
                    password = compositeKey,
                    salt = parameters.salt,
                    secret = parameters.secretKey,
                    associated = parameters.associatedData,
                )
            }
        }
    }

    private fun aesKdf(key: ByteArray, seed: ByteArray, rounds: Int, cancelled: () -> Boolean): ByteArray {
        // One array per half: Conscrypt, the Android default provider, copies the whole Java
        // array in and back out around each native call, so two threads updating halves of one
        // array overwrite each other's results (the app's Robolectric tests run on Conscrypt).
        val halves = Array(2) { key.copyOfRange(it * 16, it * 16 + 16) }
        val data = ByteArray(32)
        try {
            Workers(minOf(2, processors().coerceAtLeast(1))).use { workers ->
                workers.runEach(2) { half ->
                    beforeWork(half)
                    val block = halves[half]
                    // The seed is 32 bytes here (hashed first otherwise), so any refusal is the
                    // provider's.
                    val cipher = Digests.provider { Cipher.getInstance("AES/ECB/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(seed, "AES")) } }
                    var left = rounds
                    while (left > 0) {
                        if (cancelled()) throw CancellationException(CANCELLED)
                        val chunk = minOf(left, CANCEL_CHECK_ROUNDS)
                        repeat(chunk) { cipher.update(block, 0, 16, block, 0) }
                        left -= chunk
                    }
                }
            }
            halves[0].copyInto(data, 0)
            halves[1].copyInto(data, 16)
            return MessageDigest.getInstance("SHA-256").digest(data)
        } finally {
            halves.forEach { it.fill(0) }
            data.fill(0)
        }
    }

    private inner class Argon2(
        private val type: Int,
        private val version: Int,
        private val iterations: Int,
        private val lanes: Int,
        private val memoryKib: Int,
        private val blockCount: Int,
        private val cancelled: () -> Boolean,
    ) {
        private val segmentLength = blockCount / (lanes * SYNC_POINTS)
        private val laneLength = segmentLength * SYNC_POINTS

        fun derive(password: ByteArray, salt: ByteArray, secret: ByteArray?, associated: ByteArray?): ByteArray {
            val memory = allocate(blockCount * QWORDS)
            val workers = minOf(lanes, processors().coerceAtLeast(1))
            val scratch = Array(workers) { Scratch() }
            val h0 = ByteArray(PREHASH_SEED_BYTES)
            val block = ByteArray(BLOCK_BYTES)
            try {
                preHash(h0, password, salt, secret, associated)
                for (lane in 0 until lanes) {
                    for (column in 0..1) {
                        Bytes.writeLe32(h0, PREHASH_BYTES, column)
                        Bytes.writeLe32(h0, PREHASH_BYTES + 4, lane)
                        variableHash(h0, block, BLOCK_BYTES)
                        val base = (lane * laneLength + column) * QWORDS
                        for (i in 0 until QWORDS) memory[base + i] = Bytes.readLe64(block, i * 8)
                    }
                }
                Workers(workers).use { pool ->
                    for (pass in 0 until iterations) {
                        for (slice in 0 until SYNC_POINTS) {
                            if (cancelled()) throw CancellationException(CANCELLED)
                            pool.runEach(workers) { worker ->
                                for (lane in worker until lanes step workers) {
                                    beforeWork(lane)
                                    fillSegment(memory, scratch[worker], pass, slice, lane)
                                }
                            }
                        }
                    }
                }
                val last = (laneLength - 1) * QWORDS
                for (lane in 1 until lanes) {
                    val other = (lane * laneLength + laneLength - 1) * QWORDS
                    for (i in 0 until QWORDS) memory[last + i] = memory[last + i] xor memory[other + i]
                }
                for (i in 0 until QWORDS) Bytes.writeLe64(block, i * 8, memory[last + i])
                val tag = ByteArray(TAG_BYTES)
                variableHash(block, tag, TAG_BYTES)
                return tag
            } finally {
                memory.fill(0)
                scratch.forEach(Scratch::clear)
                h0.fill(0)
                block.fill(0)
            }
        }

        // H0 (RFC 9106 section 3.2), written into the first 64 bytes of [out].
        private fun preHash(out: ByteArray, password: ByteArray, salt: ByteArray, secret: ByteArray?, associated: ByteArray?) {
            val hash = Blake2b(PREHASH_BYTES)
            for (value in intArrayOf(lanes, TAG_BYTES, memoryKib, iterations, version, type)) hash.updateInt(value)
            for (part in arrayOf(password, salt, secret ?: EMPTY, associated ?: EMPTY)) {
                hash.updateInt(part.size)
                hash.update(part)
            }
            hash.digest(out)
        }

        // H' (RFC 9106 section 3.3): [length] bytes of [out] from [input].
        private fun variableHash(input: ByteArray, out: ByteArray, length: Int) {
            if (length <= 64) {
                Blake2b(length).apply { updateInt(length); update(input) }.digest(out)
                return
            }
            val hash = Blake2b(64)
            val v = ByteArray(64)
            hash.updateInt(length)
            hash.update(input)
            hash.digest(v)
            val r = (length + 31) / 32 - 2
            System.arraycopy(v, 0, out, 0, 32)
            for (i in 1 until r) {
                hash.update(v)
                hash.digest(v)
                System.arraycopy(v, 0, out, i * 32, 32)
            }
            Blake2b(length - 32 * r).apply { update(v) }.digest(out, 32 * r)
            v.fill(0)
        }

        private fun fillSegment(memory: LongArray, scratch: Scratch, pass: Int, slice: Int, lane: Int) {
            val independent = type == ARGON2ID && pass == 0 && slice < SYNC_POINTS / 2
            val first = if (pass == 0 && slice == 0) 2 else 0
            val withXor = pass != 0 && version == VERSION_13.toInt()
            if (independent) {
                scratch.input.fill(0)
                scratch.input[0] = pass.toLong()
                scratch.input[1] = lane.toLong()
                scratch.input[2] = slice.toLong()
                scratch.input[3] = blockCount.toLong()
                scratch.input[4] = iterations.toLong()
                scratch.input[5] = type.toLong()
                if (first != 0) nextAddresses(scratch)
            }
            var current = lane * laneLength + slice * segmentLength + first
            var previous = if (current % laneLength == 0) current + laneLength - 1 else current - 1
            for (index in first until segmentLength) {
                val pseudoRandom = if (independent) {
                    if (index % QWORDS == 0) nextAddresses(scratch)
                    scratch.address[index % QWORDS]
                } else {
                    memory[previous * QWORDS]
                }
                val refLane = if (pass == 0 && slice == 0) lane else ((pseudoRandom ushr 32) % lanes).toInt()
                val reference = refLane * laneLength + refIndex(pass, slice, index, pseudoRandom, refLane == lane)
                compress(memory, previous * QWORDS, memory, reference * QWORDS, current * QWORDS, withXor, scratch)
                previous = current
                current++
            }
        }

        // RFC 9106 section 3.4.1.2: the reference block's index within its lane.
        private fun refIndex(pass: Int, slice: Int, index: Int, pseudoRandom: Long, sameLane: Boolean): Int {
            // The reference set W: the finished segments (the earlier slices in pass 0, the other
            // three segments later); in the same lane also this segment's blocks before the
            // previous one; in another lane without its last block when this block starts the
            // segment.
            val start = if (pass == 0) 0 else (slice + 1) * segmentLength % laneLength
            val finished = if (pass == 0) slice * segmentLength else laneLength - segmentLength
            val area = finished + if (sameLane) index - 1 else if (index == 0) -1 else 0
            var x = pseudoRandom and 0xFFFF_FFFFL
            x = x * x ushr 32
            val relative = area - 1 - (area * x ushr 32)
            return ((start + relative) % laneLength).toInt()
        }

        private fun nextAddresses(scratch: Scratch) {
            scratch.input[6]++
            compress(ZERO_BLOCK, 0, scratch.input, 0, 0, withXor = false, scratch, out = scratch.address)
            compress(ZERO_BLOCK, 0, scratch.address, 0, 0, withXor = false, scratch, out = scratch.address)
        }
    }

    /** Per-worker blocks of RFC 9106 section 3.5 and the address generator of section 3.4.1.2. */
    private class Scratch {
        val r = LongArray(QWORDS)
        val z = LongArray(QWORDS)
        val input = LongArray(QWORDS)
        val address = LongArray(QWORDS)

        fun clear() = listOf(r, z, input, address).forEach { it.fill(0) }
    }

    /**
     * Runs tasks with the calling thread and up to `size - 1` daemon threads that exist only for
     * one derivation; [close] stops and joins every thread it started.
     */
    private class Workers(size: Int) : AutoCloseable {
        private val started: MutableList<Thread> = Collections.synchronizedList(ArrayList())
        private val pool: ExecutorService? = if (size <= 1) {
            null
        } else {
            val number = AtomicInteger()
            Executors.newFixedThreadPool(size - 1) { task ->
                Thread(task, "$THREAD_NAME ${number.incrementAndGet()}").apply { isDaemon = true }.also { started += it }
            }
        }

        /**
         * Runs [task] for 0 until [count]: 0 on the calling thread, the rest on the pool, or all
         * on the calling thread without one. Returns once every task ended; rethrows the first
         * failure as it was thrown.
         */
        fun runEach(count: Int, task: (Int) -> Unit) {
            if (pool == null) {
                for (i in 0 until count) task(i)
                return
            }
            val futures = ArrayList<Future<*>>(count)
            var failure: Throwable? = null
            try {
                for (i in 1 until count) futures += pool.submit(Runnable { task(i) })
                task(0)
            } catch (t: Throwable) {
                failure = t
            }
            for (future in futures) {
                val error = try {
                    awaitUninterruptibly { future.get() }
                    null
                } catch (e: ExecutionException) {
                    e.cause ?: e
                }
                if (error != null && failure == null) failure = error
            }
            failure?.let { throw it }
        }

        override fun close() {
            val executor = pool ?: return
            executor.shutdownNow()
            for (thread in started.toList()) awaitUninterruptibly { thread.join() }
        }

        // An interrupt doesn't end the wait, because the derivation must not return while a
        // worker uses its memory; the interrupt flag is set again afterwards.
        private fun awaitUninterruptibly(wait: () -> Unit) {
            var interrupted = false
            while (true) {
                try {
                    wait()
                    break
                } catch (e: InterruptedException) {
                    interrupted = true
                }
            }
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    companion object {
        /** Name prefix of the worker threads. */
        const val THREAD_NAME = "KashPass KDF"

        /** AES-KDF rounds between two cancellation checks in each half. */
        const val CANCEL_CHECK_ROUNDS = 4_096

        private const val CANCELLED = "Key derivation cancelled"
        private val NEVER: () -> Boolean = { false }

        private const val VERSION_13 = 0x13U
        private const val ARGON2D = 0
        private const val ARGON2ID = 2
        private const val SYNC_POINTS = 4
        private const val BLOCK_BYTES = 1024
        private const val QWORDS = BLOCK_BYTES / 8
        private const val PREHASH_BYTES = 64
        private const val PREHASH_SEED_BYTES = 72
        private const val TAG_BYTES = 32
        private const val MIN_SALT_BYTES = 8
        private val EMPTY = ByteArray(0)
        private val ZERO_BLOCK = LongArray(QWORDS)
        private const val M32 = 0xFFFF_FFFFL

        /**
         * Writes G(X, Y) (RFC 9106 section 3.5) for the blocks at [xOff] in [x] and [yOff] in
         * [y] to [outOff] in [out], XORed into the old block when [withXor].
         */
        private fun compress(
            x: LongArray,
            xOff: Int,
            y: LongArray,
            yOff: Int,
            outOff: Int,
            withXor: Boolean,
            scratch: Scratch,
            out: LongArray = x,
        ) {
            val r = scratch.r
            val z = scratch.z
            for (i in 0 until QWORDS) r[i] = x[xOff + i] xor y[yOff + i]
            r.copyInto(z)
            for (i in 0 until 8) {
                val b = 16 * i
                permute(z, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7, b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15)
            }
            for (i in 0 until 8) {
                val b = 2 * i
                permute(z, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49, b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113)
            }
            if (withXor) {
                for (i in 0 until QWORDS) out[outOff + i] = out[outOff + i] xor r[i] xor z[i]
            } else {
                for (i in 0 until QWORDS) out[outOff + i] = r[i] xor z[i]
            }
        }

        // Permutation P (RFC 9106 section 3.6) on the 16 words at the given indices of [v].
        private fun permute(
            v: LongArray, i0: Int, i1: Int, i2: Int, i3: Int, i4: Int, i5: Int, i6: Int, i7: Int,
            i8: Int, i9: Int, i10: Int, i11: Int, i12: Int, i13: Int, i14: Int, i15: Int,
        ) {
            mix(v, i0, i4, i8, i12)
            mix(v, i1, i5, i9, i13)
            mix(v, i2, i6, i10, i14)
            mix(v, i3, i7, i11, i15)
            mix(v, i0, i5, i10, i15)
            mix(v, i1, i6, i11, i12)
            mix(v, i2, i7, i8, i13)
            mix(v, i3, i4, i9, i14)
        }

        // GB (RFC 9106 section 3.6): BLAKE2b's G with each addition a + b replaced by
        // a + b + 2 * trunc(a) * trunc(b).
        private fun mix(v: LongArray, ia: Int, ib: Int, ic: Int, id: Int) {
            var a = v[ia]
            var b = v[ib]
            var c = v[ic]
            var d = v[id]
            a += b + 2 * (a and M32) * (b and M32)
            d = (d xor a).rotateRight(32)
            c += d + 2 * (c and M32) * (d and M32)
            b = (b xor c).rotateRight(24)
            a += b + 2 * (a and M32) * (b and M32)
            d = (d xor a).rotateRight(16)
            c += d + 2 * (c and M32) * (d and M32)
            b = (b xor c).rotateRight(63)
            v[ia] = a
            v[ib] = b
            v[ic] = c
            v[id] = d
        }
    }
}

/**
 * Derives through [delegate] and keeps the first transformed key until [close]; a save uses one
 * so its read-back reuses the encode's derivation. A later call with KDF parameters equal in
 * content ([same]: rounds and seed, or every Argon2 value with the salt, secret key and
 * associated data) and an equal composite key, compared in constant time, gets the kept key; any
 * other call derives through [delegate]. The cache keeps its own copies of the parameters and the
 * composite key, and every call returns its own array, so a caller that zero-fills its arrays
 * leaves the kept ones intact. [close] zero-fills the kept composite and transformed keys; after
 * it every call derives. [KdfEngineTest] pins each case.
 */
internal class SaveKeyCache(private val delegate: KeyDerivation) : KeyDerivation, AutoCloseable {

    private var parameters: KdbxKdfParameters? = null
    private var compositeKey: ByteArray? = null
    private var transformedKey: ByteArray? = null
    private var closed = false

    @Synchronized
    override fun derive(parameters: KdbxKdfParameters, compositeKey: ByteArray): ByteArray {
        val kept = transformedKey
        val keptParameters = this.parameters
        if (kept != null && keptParameters != null && same(parameters, keptParameters) && MessageDigest.isEqual(compositeKey, this.compositeKey)) {
            return kept.copyOf()
        }
        val derived = delegate.derive(parameters, compositeKey)
        if (closed || kept != null) return derived
        this.parameters = copied(parameters)
        this.compositeKey = compositeKey.copyOf()
        transformedKey = derived
        return derived.copyOf()
    }

    @Synchronized
    override fun close() {
        closed = true
        compositeKey?.fill(0)
        transformedKey?.fill(0)
        compositeKey = null
        transformedKey = null
        parameters = null
    }

    companion object {
        /** Returns true when [a] and [b] hold the same KDF, values and byte arrays included. */
        fun same(a: KdbxKdfParameters, b: KdbxKdfParameters): Boolean = when {
            a is KdbxKdfParameters.Aes && b is KdbxKdfParameters.Aes -> a.rounds == b.rounds && a.seed.contentEquals(b.seed)
            a is KdbxKdfParameters.Argon2 && b is KdbxKdfParameters.Argon2 ->
                a.type == b.type && a.parallelism == b.parallelism && a.memoryBytes == b.memoryBytes && a.iterations == b.iterations &&
                    a.version == b.version && a.salt.contentEquals(b.salt) && a.secretKey.contentEquals(b.secretKey) &&
                    a.associatedData.contentEquals(b.associatedData)
            else -> false
        }

        private fun copied(p: KdbxKdfParameters): KdbxKdfParameters = when (p) {
            is KdbxKdfParameters.Aes -> KdbxKdfParameters.Aes(p.rounds, p.seed.copyOf())
            is KdbxKdfParameters.Argon2 -> KdbxKdfParameters.Argon2(
                p.type, p.salt.copyOf(), p.parallelism, p.memoryBytes, p.iterations, p.version, p.secretKey?.copyOf(), p.associatedData?.copyOf(),
            )
        }
    }
}
