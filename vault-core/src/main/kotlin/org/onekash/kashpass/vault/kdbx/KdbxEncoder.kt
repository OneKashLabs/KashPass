package org.onekash.kashpass.vault.kdbx

import java.security.SecureRandom
import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.CancellationException

/**
 * Encodes a KDBX 4 file.
 * The steps run in this order, each only after the one before it returned ([Step]):
 * 1. the outer header ([KdbxHeaderWriter]), which draws the master seed, the IV and the KDF salt
 *    or seed, and the KDF parameters [KdbxHeaderReader] reads back from those bytes;
 * 2. the caller's KDF check on those parameters; a refusal ends the encode before any
 *    derivation;
 * 3. the transformed key from the caller's KDF, with the same parameters, then [KeySchedule];
 * 4. the header's SHA-256 and HMAC, written after the header;
 * 5. the payload: the inner header ([InnerHeaderWriter], ChaCha20 with a 64-byte key drawn from
 *    the same random source after the header's values), then the
 *    XML the caller writes through a [PayloadSink];
 * 6. gzip, when the settings say so ([GzipWriter]);
 * 7. encryption in place: AES-256-CBC with PKCS#7 ([AesCbc]) or ChaCha20 with the header IV and
 *    [ChaCha20.Counter.RFC8439];
 * 8. the HMAC block stream ([BlockStreamWriter]), ending with the end block and nothing after it.
 *
 * Every key, keystream and plaintext array the encoder holds comes from [Buffers]: the inner
 * stream key, the inner header's stream fields, the payload, the compressed payload, the key
 * schedule's keys and every array a [PayloadSink] hands out. The inner header goes into the
 * payload in pieces ([PayloadSink.writeInnerHeader]) and is never built in an array of its own.
 * An array a step is done with before the encode ends (the stream fields once copied, each array
 * the caller's payload buffer outgrows ([PayloadSink.release]), the payload once compressed or
 * moved for the padding, each buffer [GzipWriter] outgrows) is zero-filled and released
 * ([Buffers.release]) at once, so the encoder holds no reference to it while the later steps
 * allocate. When [encode] returns or throws, every array not released and the transformed key
 * are zero-filled, the key schedule, the inner stream and the outer ChaCha20 are closed, and only
 * [EncodeResult.Encoded.bytes] holds data. [KdbxEncoderTest] and [KdbxEncoderZeroingTest] pin
 * this.
 */
internal object KdbxEncoder {

    /** The encoder's steps, in order, for tests that check the order. */
    enum class Step { HEADER, KDF_ALLOWED, DERIVE, HEADER_MAC, PAYLOAD, COMPRESS, ENCRYPT, BLOCKS }

    private const val STREAM_KEY_BYTES = 64
    private const val AES_BLOCK = 16

    // Ends the encode with [result]. Stackless and without a message.
    private class Stop(val result: EncodeResult) : Exception(null, null, false, false)

    /**
     * Encodes a file with [settings] as KDBX 4.[minorVersion], with [attachments] in the inner
     * header in the order given, and returns one of [EncodeResult]; nothing but a
     * CancellationException escapes. Every random value comes from [random].
     *
     * [kdfAllowed] sees the KDF parameters read back from the written header; false returns
     * [EncodeResult.Refused] and nothing is derived. [derive] returns the 32-byte transformed key
     * for [compositeKey] with those parameters; [compositeKey] stays the caller's to zero-fill,
     * and the returned array becomes the encoder's, which zero-fills it. An exception from
     * [derive] is [EncodeResult.DeriveFailed], an OutOfMemoryError
     * [EncodeResult.NotEnoughMemory], and a CancellationException is rethrown.
     *
     * [writeXml] writes the XML through the [PayloadSink] it is given and hands the bytes over
     * before it returns; the sink and its [PayloadSink.keystream] are closed after it returns.
     * [step] sees each step as it starts.
     */
    fun encode(
        settings: SaveSettings,
        minorVersion: Int,
        compositeKey: ByteArray,
        kdfAllowed: (KdfParameters) -> Boolean,
        derive: (KdfParameters, ByteArray) -> ByteArray,
        attachments: List<Attachment>,
        writeXml: (PayloadSink) -> Unit,
        random: SecureRandom,
        buffers: Buffers = Buffers.Default,
        step: (Step) -> Unit = {},
    ): EncodeResult {
        val tracking = TrackingBuffers(buffers)
        val owned = tracking.owned
        try {
            return run(settings, minorVersion, compositeKey, kdfAllowed, derive, attachments, writeXml, random, tracking, step)
        } catch (e: Stop) {
            return e.result
        } catch (e: KdbxException) {
            return map(e)
        } catch (e: OutOfMemoryError) {
            return EncodeResult.NotEnoughMemory
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            return EncodeResult.Failed(FailureCause.INTERNAL)
        } finally {
            for (a in owned) a.fill(0)
        }
    }

    private fun run(
        settings: SaveSettings,
        minorVersion: Int,
        compositeKey: ByteArray,
        kdfAllowed: (KdfParameters) -> Boolean,
        derive: (KdfParameters, ByteArray) -> ByteArray,
        attachments: List<Attachment>,
        writeXml: (PayloadSink) -> Unit,
        random: SecureRandom,
        buffers: Buffers,
        step: (Step) -> Unit,
    ): EncodeResult {
        step(Step.HEADER)
        val written = when (val w = KdbxHeaderWriter.write(settings, minorVersion, random)) {
            is KdbxHeaderWriter.Write.Written -> w
            is KdbxHeaderWriter.Write.Invalid ->
                return if (w.result is KdbxResult.NotEnoughMemory) EncodeResult.NotEnoughMemory else EncodeResult.Failed(FailureCause.INTERNAL)
        }
        val header = written.header

        step(Step.KDF_ALLOWED)
        if (!kdfAllowed(written.kdf)) return EncodeResult.Refused

        step(Step.DERIVE)
        val transformed = try {
            derive(written.kdf, compositeKey)
        } catch (e: CancellationException) {
            throw e
        } catch (e: OutOfMemoryError) {
            return EncodeResult.NotEnoughMemory
        } catch (e: Exception) {
            return EncodeResult.DeriveFailed(e)
        }
        val keys = try {
            KeySchedule(header.masterSeed, transformed, buffers)
        } finally {
            transformed.fill(0)
        }
        keys.use {
            step(Step.HEADER_MAC)
            val headerBytes = written.bytes
            val hash = Digests.sha256(headerBytes)
            val mac = keys.headerMac(headerBytes, 0, headerBytes.size)

            step(Step.PAYLOAD)
            val spare = if (header.cipher == OuterCipher.AES_256) AES_BLOCK else 0
            var plain = payload(attachments, writeXml, random, buffers)

            if (header.compression == Compression.GZIP) {
                step(Step.COMPRESS)
                val deflated = sized { GzipWriter.compress(plain.bytes, 0, plain.size, spare, buffers) }
                plain.bytes.fill(0)
                buffers.release(plain.bytes)
                plain = Sized(deflated.bytes, deflated.size)
            } else if (plain.bytes.size - plain.size < spare) {
                // AES pads in place; a payload without room for the padding moves once.
                val padded = sized { AesCbc.paddedLength(plain.size) }
                val room = buffers.bytes(padded)
                plain.bytes.copyInto(room, 0, 0, plain.size)
                plain.bytes.fill(0)
                buffers.release(plain.bytes)
                plain = Sized(room, plain.size)
            }

            step(Step.ENCRYPT)
            val cipherLength = when (header.cipher) {
                OuterCipher.AES_256 -> AesCbc.encrypt(keys.cipherKey(), header.iv, plain.bytes, 0, plain.size)
                OuterCipher.CHACHA20 -> {
                    ChaCha20(keys.cipherKey(), header.iv, ChaCha20.Counter.RFC8439, buffers).use { it.xor(plain.bytes, 0, plain.size) }
                    plain.size
                }
            }

            step(Step.BLOCKS)
            val blocksSize = sized { BlockStreamWriter.size(cipherLength) }
            val total = headerBytes.size.toLong() + 2 * Digests.SHA256_BYTES + blocksSize
            if (total > Int.MAX_VALUE) return EncodeResult.NotEnoughMemory
            val out = ByteArray(total.toInt())
            headerBytes.copyInto(out)
            hash.copyInto(out, headerBytes.size)
            mac.copyInto(out, headerBytes.size + Digests.SHA256_BYTES)
            BlockStreamWriter.write(plain.bytes, 0, cipherLength, keys, out, headerBytes.size + 2 * Digests.SHA256_BYTES)
            return EncodeResult.Encoded(out)
        }
    }

    private class Sized(val bytes: ByteArray, val size: Int)

    // The inner header followed by the caller's XML, in one array from [buffers].
    private fun payload(attachments: List<Attachment>, writeXml: (PayloadSink) -> Unit, random: SecureRandom, buffers: Buffers): Sized {
        val streamKey = buffers.bytes(STREAM_KEY_BYTES)
        random.nextBytes(streamKey)
        val innerHeaderSize = sized { InnerHeaderWriter.size(streamKey, attachments) }
        val sink = InnerStream.open(InnerStream.CHACHA20, streamKey, buffers).use { keystream ->
            PayloadSink(streamKey, attachments, innerHeaderSize, keystream, buffers).also { sink ->
                try {
                    writeXml(sink)
                } finally {
                    sink.close()
                }
            }
        }
        val handed = sink.handed ?: throw IllegalStateException()
        return Sized(handed, sink.handedSize)
    }

    // Runs [block], turning an output larger than an array can hold into NotEnoughMemory.
    private inline fun <T> sized(block: () -> T): T = try {
        block()
    } catch (e: KdbxException.InvalidLength) {
        if (e.field == KdbxException.Field.RANGE) throw Stop(EncodeResult.NotEnoughMemory) else throw e
    }

    // Primitive exceptions the steps above do not map themselves.
    private fun map(e: KdbxException): EncodeResult = when (e) {
        is KdbxException.AlgorithmUnavailable -> EncodeResult.Failed(FailureCause.PLATFORM)
        is KdbxException.DictionaryTooLarge -> EncodeResult.NotEnoughMemory
        is KdbxException.InvalidLength, is KdbxException.KeystreamExhausted, is KdbxException.Closed,
        is KdbxException.CiphertextNotBlockMultiple, is KdbxException.BadPadding, is KdbxException.CompressedData,
        is KdbxException.InflatedTooLarge, is KdbxException.KdfParametersInvalid, is KdbxException.DerivationTooLarge,
        -> EncodeResult.Failed(FailureCause.INTERNAL)
    }
}

/**
 * Takes the XML of a save in an array that starts with the inner header, so the encoder
 * compresses or encrypts it where it lies. The caller allocates its growable buffer through
 * [allocate], gives back each array it outgrows through [release], writes the pieces
 * [writeInnerHeader] passes it, then the XML with protected values XORed with [keystream] in
 * document order and Base64-encoded, and gives the array to [handOver]. Every array [allocate]
 * returns is the encoder's to zero-fill, so a buffer that grows and the one handed over need no
 * copy. Each call after the encode's XML step throws [KdbxException.Closed].
 */
internal class PayloadSink internal constructor(
    private val streamKey: ByteArray,
    private val attachments: List<Attachment>,
    /** The size of the inner header [writeInnerHeader] writes ([InnerHeaderWriter.size]). */
    val innerHeaderSize: Int,
    /** The inner random stream (ChaCha20, id 3) of the inner header's key. */
    val keystream: Keystream,
    private val buffers: Buffers,
) {
    private val allocated: MutableSet<ByteArray> = Collections.newSetFromMap(IdentityHashMap())
    private var closed = false

    internal var handed: ByteArray? = null
        private set
    internal var handedSize = 0
        private set

    /** Returns a zero-filled array of [size] bytes that the encoder zero-fills after the save. */
    fun allocate(size: Int): ByteArray {
        if (closed) throw KdbxException.Closed()
        return buffers.bytes(size).also { allocated += it }
    }

    /**
     * Zero-fills [array], which came from [allocate] and is never used again, and drops it from
     * the encoder's arrays ([Buffers.release]), so it is garbage before the encode ends. Throws
     * [IllegalStateException] for an array from elsewhere.
     */
    fun release(array: ByteArray) {
        if (closed) throw KdbxException.Closed()
        check(allocated.remove(array))
        array.fill(0)
        buffers.release(array)
    }

    /**
     * Passes the inner header to [write] in pieces, each an array, an offset and a length
     * ([InnerHeaderWriter.write]). The pieces hold the inner stream key and the attachments;
     * [write] copies the bytes and keeps no reference to them.
     */
    fun writeInnerHeader(write: (ByteArray, Int, Int) -> Unit) {
        if (closed) throw KdbxException.Closed()
        InnerHeaderWriter.write(streamKey, attachments, buffers, write)
    }

    /**
     * Takes the first [size] bytes of [buffer] as the payload: the inner header, then the XML.
     * Throws [IllegalStateException] for a second hand-over, a [size] outside [buffer], bytes
     * that do not start with the inner header or an array from elsewhere than [allocate], which
     * ends the encode as an internal failure.
     */
    fun handOver(buffer: ByteArray, size: Int) {
        if (closed) throw KdbxException.Closed()
        check(handed == null && buffer in allocated && size in innerHeaderSize..buffer.size)
        var p = 0
        InnerHeaderWriter.write(streamKey, attachments, buffers) { bytes, from, length ->
            for (i in 0 until length) check(buffer[p + i] == bytes[from + i])
            p += length
        }
        handed = buffer
        handedSize = size
    }

    internal fun close() {
        closed = true
    }
}
