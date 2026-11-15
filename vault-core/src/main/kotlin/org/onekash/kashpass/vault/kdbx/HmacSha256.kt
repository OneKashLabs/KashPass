package org.onekash.kashpass.vault.kdbx

/**
 * HMAC-SHA-256 (RFC 2104) over the default provider's SHA-256. KashPass computes it itself
 * instead of using javax.crypto.Mac because Mac keeps the key in a SecretKeySpec and in provider
 * state that neither the JDK nor Android's provider can clear; here the padded keys and the inner
 * hash are arrays from [buffers], zero-filled on [close].
 *
 * A key longer than the 64-byte SHA-256 block is hashed first, as RFC 2104 says; the caller
 * zero-fills its own key array. One instance computes any number of MACs under its key: [update]
 * feeds the message and [finish] writes the MAC and starts the next message. [close] runs after
 * the last call returns, never alongside one.
 */
internal class HmacSha256(key: ByteArray, buffers: Buffers = Buffers.Default) : AutoCloseable {

    private val digest = Digests.sha256Digest()
    private val ipad = buffers.bytes(BLOCK)
    private val opad = buffers.bytes(BLOCK)
    private val inner = buffers.bytes(Digests.SHA256_BYTES)

    @Volatile
    private var closed = false

    init {
        var hashed: ByteArray? = null
        try {
            if (key.size > BLOCK) hashed = buffers.bytes(Digests.SHA256_BYTES).also { Digests.sha256Into(it, 0, key) }
            val k = hashed ?: key
            for (i in 0 until BLOCK) {
                val b = if (i < k.size) k[i].toInt() else 0
                ipad[i] = (b xor 0x36).toByte()
                opad[i] = (b xor 0x5c).toByte()
            }
            Digests.provider { digest.update(ipad) }
        } catch (e: Throwable) {
            // No object is returned, so nothing could close it.
            close()
            throw e
        } finally {
            hashed?.fill(0)
        }
    }

    /** Feeds [length] bytes of [data] from [offset] to the current message. */
    fun update(data: ByteArray, offset: Int, length: Int) {
        if (closed) throw KdbxException.Closed()
        Bytes.checkRange(data.size, offset, length)
        Digests.provider { digest.update(data, offset, length) }
    }

    /** Writes the 32-byte MAC of the current message into [out] from [outOffset]. */
    fun finish(out: ByteArray, outOffset: Int) {
        if (closed) throw KdbxException.Closed()
        Bytes.checkRange(out.size, outOffset, Digests.SHA256_BYTES)
        try {
            Digests.provider {
                digest.digest(inner, 0, inner.size)
                digest.update(opad)
                digest.update(inner)
                digest.digest(out, outOffset, Digests.SHA256_BYTES)
            }
        } finally {
            inner.fill(0)
            digest.reset()
            Digests.provider { digest.update(ipad) }
        }
    }

    /** Returns the MAC of [length] bytes of [data] from [offset] as a new array. */
    fun mac(data: ByteArray, offset: Int = 0, length: Int = data.size): ByteArray {
        update(data, offset, length)
        return ByteArray(Digests.SHA256_BYTES).also { finish(it, 0) }
    }

    override fun close() {
        closed = true
        ipad.fill(0)
        opad.fill(0)
        inner.fill(0)
        digest.reset()
    }

    private companion object {
        const val BLOCK = 64
    }
}
