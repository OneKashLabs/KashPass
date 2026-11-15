package org.onekash.kashpass.vault.kdbx

import java.util.Collections
import java.util.IdentityHashMap
import java.util.concurrent.CancellationException

/**
 * Decodes a KDBX 4 file whose outer header [KdbxHeaderReader] read, up to the XML. The steps run
 * in this order, each only after the one before it passed ([Step]):
 * 1. the header's SHA-256 against the 32 bytes after it (unkeyed, so before the slow
 *    derivation);
 * 2. the transformed key from the caller's KDF;
 * 3. the header HMAC against the next 32 bytes; a mismatch is a wrong key, and nothing after it
 *    is read;
 * 4. every block HMAC, before any block is decrypted ([BlockStream]);
 * 5. the IV's size for the cipher (16 for AES-256, 12 for ChaCha20), then decryption in place:
 *    AES-256-CBC ([AesCbc]) or ChaCha20 with the IV as nonce and the KDBX outer counter
 *    ([ChaCha20.Counter.RFC8439]);
 * 6. gzip, when the header says so ([GzipReader], capped at the caller's limit);
 * 7. the inner header ([InnerHeaderReader]).
 * No header field except the KDF parameters, the master seed and the cipher id is used before the
 * header HMAC passes, and no failure after it is a wrong key: damage there names its layer.
 *
 * Every key, ciphertext and plaintext array the decoder allocates comes from [Buffers]. The
 * transformed key from the KDF is zero-filled once the key schedule holds it; the key schedule is
 * closed after the last decryption, never during it. An array a step is done with before the
 * decode ends (each gzip buffer [GzipReader] outgrows, the ciphertext once inflated) is
 * zero-filled and released ([Buffers.release]) at once, so the decoder holds no reference to it
 * while later steps allocate. When [decode] returns [KdbxResult.Opened],
 * the caller owns the plaintext and the container's stream key and attachments; on any other
 * result every array the decoder took from [Buffers] is zero-filled. [KdbxDecoderTest] and
 * [KdbxDecoderZeroingTest] pin this.
 */
internal object KdbxDecoder {

    /** The decoder's steps, in order, for tests that check the order. */
    enum class Step { HEADER_HASH, DERIVE, HEADER_MAC, BLOCKS, DECRYPT, INFLATE, INNER_HEADER }


    /**
     * Decodes [bytes], the whole file, whose outer header is [header]. [derive] returns the
     * 32-byte transformed key for [compositeKey], which stays the caller's to zero-fill. The
     * result is one of [KdbxResult]; nothing but a CancellationException escapes. [step] sees each
     * step as it starts.
     */
    fun decode(
        bytes: ByteArray,
        header: OuterHeader,
        compositeKey: ByteArray,
        derive: (KdfParameters, ByteArray) -> ByteArray,
        inflateLimit: Int,
        buffers: Buffers = Buffers.Default,
        step: (Step) -> Unit = {},
    ): KdbxResult {
        val tracking = TrackingBuffers(buffers)
        val owned = tracking.owned
        val kept: MutableSet<ByteArray> = Collections.newSetFromMap(IdentityHashMap())
        try {
            val result = run(bytes, header, compositeKey, derive, inflateLimit, tracking, step)
            if (result is KdbxResult.Opened) {
                kept += result.plaintext.buffer
                kept += result.container.inner.streamKey
                result.container.inner.attachments.forEach { kept += it.data }
            }
            return result
        } catch (e: KdbxFailure) {
            return e.result
        } catch (e: KdbxException) {
            return map(e)
        } catch (e: OutOfMemoryError) {
            return KdbxResult.NotEnoughMemory(MemoryCause.OUT_OF_MEMORY)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            return KdbxResult.Failed(FailureCause.INTERNAL)
        } finally {
            for (a in owned) if (a !in kept) a.fill(0)
        }
    }

    private fun run(
        bytes: ByteArray,
        header: OuterHeader,
        compositeKey: ByteArray,
        derive: (KdfParameters, ByteArray) -> ByteArray,
        inflateLimit: Int,
        buffers: Buffers,
        step: (Step) -> Unit,
    ): KdbxResult {
        val length = header.length
        if (length < 0 || bytes.size - length < 2 * Digests.SHA256_BYTES) damaged(KdbxDamage.TRUNCATED)
        step(Step.HEADER_HASH)
        val hash = buffers.bytes(Digests.SHA256_BYTES)
        Digests.provider {
            val digest = Digests.sha256Digest()
            digest.update(bytes, 0, length)
            digest.digest(hash, 0, hash.size)
        }
        if (!Bytes.constantTimeEquals(hash, bytes.copyOfRange(length, length + Digests.SHA256_BYTES))) damaged(KdbxDamage.HEADER_HASH)

        step(Step.DERIVE)
        val transformed = derive(header.kdf, compositeKey)
        val keys = try {
            KeySchedule(header.masterSeed, transformed, buffers)
        } finally {
            transformed.fill(0)
        }
        val payload = keys.use { payload(bytes, header, keys, inflateLimit, buffers, step) }

        step(Step.INNER_HEADER)
        val inner = InnerHeaderReader.read(payload.bytes, payload.length, header, buffers)
        val plaintext = Plaintext(payload.bytes, inner.xmlOffset, payload.length - inner.xmlOffset)
        return KdbxResult.Opened(KdbxContainer(header, inner.header, payload.bytesAfterEnd), plaintext)
    }

    // The first [length] bytes of [bytes] are the decrypted, decompressed payload.
    private class Payload(val bytes: ByteArray, val length: Int, val bytesAfterEnd: Boolean)

    // Steps 3 to 6. The ciphertext copy lives only in this frame: with gzip it is zero-filled and
    // released once inflated, so the file, the ciphertext and the payload are held together only
    // while gzip reads; without it the decrypted ciphertext is the payload.
    private fun payload(bytes: ByteArray, header: OuterHeader, keys: KeySchedule, inflateLimit: Int, buffers: Buffers, step: (Step) -> Unit): Payload {
        val length = header.length
        step(Step.HEADER_MAC)
        val mac = keys.headerMac(bytes, 0, length)
        if (!Bytes.constantTimeEquals(mac, bytes.copyOfRange(length + Digests.SHA256_BYTES, length + 2 * Digests.SHA256_BYTES))) throw KdbxFailure(KdbxResult.WrongKey)
        step(Step.BLOCKS)
        val blocks = BlockStream.read(bytes, length + 2 * Digests.SHA256_BYTES, keys, buffers)
        step(Step.DECRYPT)
        val plainLength = decrypt(header, keys.cipherKey(), blocks, buffers)
        if (header.compression != Compression.GZIP) return Payload(blocks.ciphertext, plainLength, blocks.bytesAfterEnd)
        step(Step.INFLATE)
        val inflated = try {
            GzipReader.inflate(blocks.ciphertext, 0, plainLength, inflateLimit, buffers)
        } catch (e: KdbxException.CompressedData) {
            damaged(KdbxDamage.COMPRESSED_DATA)
        }
        blocks.ciphertext.fill(0)
        buffers.release(blocks.ciphertext)
        return Payload(inflated.bytes, inflated.size, blocks.bytesAfterEnd)
    }

    // Decrypts the blocks in place and returns the plaintext length.
    private fun decrypt(header: OuterHeader, key: ByteArray, blocks: BlockStream.Blocks, buffers: Buffers): Int = when (header.cipher) {
        OuterCipher.AES_256 -> {
            if (header.iv.size != OuterCipher.AES_256.ivSize) damaged(KdbxDamage.HEADER_FIELD)
            try {
                AesCbc.decrypt(key, header.iv, blocks.ciphertext, 0, blocks.length)
            } catch (e: KdbxException.CiphertextNotBlockMultiple) {
                damaged(KdbxDamage.CIPHERTEXT_LENGTH)
            } catch (e: KdbxException.BadPadding) {
                damaged(KdbxDamage.PADDING)
            }
        }
        OuterCipher.CHACHA20 -> {
            if (header.iv.size != OuterCipher.CHACHA20.ivSize) damaged(KdbxDamage.HEADER_FIELD)
            try {
                ChaCha20(key, header.iv, ChaCha20.Counter.RFC8439, buffers).use { it.xor(blocks.ciphertext, 0, blocks.length) }
            } catch (e: KdbxException.KeystreamExhausted) {
                damaged(KdbxDamage.CIPHERTEXT_LENGTH)
            }
            blocks.length
        }
    }

    // Primitive exceptions the steps above do not map themselves. A wrong length reaching a
    // primitive means a check is missing here, so it is internal, not damage.
    private fun map(e: KdbxException): KdbxResult = when (e) {
        is KdbxException.InflatedTooLarge -> KdbxResult.NotEnoughMemory(MemoryCause.LIMIT)
        is KdbxException.DerivationTooLarge -> KdbxResult.NotEnoughMemory(MemoryCause.LIMIT)
        is KdbxException.KdfParametersInvalid -> KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS)
        is KdbxException.AlgorithmUnavailable -> KdbxResult.Failed(FailureCause.PLATFORM)
        is KdbxException.CompressedData -> KdbxResult.Damaged(KdbxDamage.COMPRESSED_DATA)
        is KdbxException.CiphertextNotBlockMultiple -> KdbxResult.Damaged(KdbxDamage.CIPHERTEXT_LENGTH)
        is KdbxException.BadPadding -> KdbxResult.Damaged(KdbxDamage.PADDING)
        is KdbxException.InvalidLength, is KdbxException.KeystreamExhausted, is KdbxException.Closed,
        is KdbxException.DictionaryTooLarge -> KdbxResult.Failed(FailureCause.INTERNAL)
    }
}
