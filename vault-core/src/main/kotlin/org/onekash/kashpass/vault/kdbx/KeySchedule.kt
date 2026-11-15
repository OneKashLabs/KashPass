package org.onekash.kashpass.vault.kdbx

/**
 * The KDBX 4 keys derived from the master seed and the transformed key:
 * - cipher key = SHA-256(seed || transformed key), the outer cipher's 32-byte key;
 * - HMAC base key = SHA-512(seed || transformed key || 0x01);
 * - the key of block i = SHA-512(i as 8 bytes little-endian || HMAC base key), with i = 2^64-1
 *   (-1 as a Long) for the header.
 *
 * The transformed key comes from the KDF outside this package; [masterSeed] and [transformedKey]
 * must be 32 bytes each, else [KdbxException.InvalidLength], and stay the caller's to zero-fill.
 * The cipher key and the HMAC base key live in [buffers] arrays until [close] zero-fills them;
 * each block key exists only inside one [blockMac] or [headerMac] call and is zero-filled before
 * it returns or throws. [close] runs after the last call returns, never alongside one; a call
 * after it throws [KdbxException.Closed].
 */
internal class KeySchedule(
    masterSeed: ByteArray,
    transformedKey: ByteArray,
    private val buffers: Buffers = Buffers.Default,
) : AutoCloseable {

    private val cipherKey: ByteArray = buffers.bytes(Digests.SHA256_BYTES)
    private val hmacBase: ByteArray = buffers.bytes(Digests.SHA512_BYTES)

    @Volatile
    private var closed = false

    init {
        if (masterSeed.size != 32) throw KdbxException.InvalidLength(KdbxException.Field.MASTER_SEED)
        if (transformedKey.size != 32) throw KdbxException.InvalidLength(KdbxException.Field.TRANSFORMED_KEY)
        try {
            Digests.sha256Into(cipherKey, 0, masterSeed, transformedKey)
            Digests.sha512Into(hmacBase, 0, masterSeed, transformedKey, ONE)
        } catch (e: Throwable) {
            // No object is returned, so nothing could close it.
            close()
            throw e
        }
    }

    /**
     * Returns the outer cipher key itself, not a copy: valid until [close] zero-fills it, so a
     * caller keeps no reference past [close].
     */
    fun cipherKey(): ByteArray {
        if (closed) throw KdbxException.Closed()
        return cipherKey
    }

    /** Returns the header HMAC: HMAC-SHA-256 of the header bytes under the key of block 2^64-1. */
    fun headerMac(header: ByteArray, offset: Int, length: Int): ByteArray {
        Bytes.checkRange(header.size, offset, length)
        return mac(HEADER_INDEX) { it.update(header, offset, length) }
    }

    /**
     * Returns the HMAC of block [index] holding [length] bytes of [data] from [offset]:
     * HMAC-SHA-256 under the block's key over the index (8 bytes little-endian), the length (4
     * bytes little-endian) and the data, the HMAC stored before each block.
     */
    fun blockMac(index: Long, data: ByteArray, offset: Int, length: Int): ByteArray {
        Bytes.checkRange(data.size, offset, length)
        val prefix = ByteArray(12)
        Bytes.writeLe64(prefix, 0, index)
        Bytes.writeLe32(prefix, 8, length)
        return mac(index) {
            it.update(prefix, 0, prefix.size)
            it.update(data, offset, length)
        }
    }

    private fun mac(index: Long, feed: (HmacSha256) -> Unit): ByteArray {
        if (closed) throw KdbxException.Closed()
        val indexBytes = ByteArray(8).also { Bytes.writeLe64(it, 0, index) }
        val blockKey = buffers.bytes(Digests.SHA512_BYTES)
        try {
            Digests.sha512Into(blockKey, 0, indexBytes, hmacBase)
            return HmacSha256(blockKey, buffers).use { h ->
                feed(h)
                ByteArray(Digests.SHA256_BYTES).also { h.finish(it, 0) }
            }
        } finally {
            blockKey.fill(0)
        }
    }

    /** Zero-fills the cipher key and the HMAC base key. */
    override fun close() {
        closed = true
        cipherKey.fill(0)
        hmacBase.fill(0)
    }

    private companion object {
        val ONE = byteArrayOf(1)
        const val HEADER_INDEX = -1L
    }
}
