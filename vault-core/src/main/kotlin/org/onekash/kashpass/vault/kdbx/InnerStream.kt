package org.onekash.kashpass.vault.kdbx

/**
 * Sets up the inner random stream that protected values are XORed with:
 * - ChaCha20 (3): key and nonce are bytes 0-31 and 32-43 of SHA-512 of the stream key, with
 *   the 64-bit block counter ([ChaCha20.Counter.LARGE]);
 * - Salsa20 (2): the key is SHA-256 of the stream key, the nonce the KDBX constant
 *   E8 30 09 4B 97 20 5D 2A;
 * - ArcFour variant (1): the stream key itself.
 * The hashed key material lives in [Buffers] arrays and is zero-filled before [open] returns; the
 * stream key stays the caller's. [InnerStreamTest] checks each against the test toolkit.
 */
internal object InnerStream {

    const val ARCFOUR_VARIANT = 1
    const val SALSA20 = 2
    const val CHACHA20 = 3

    /** Stream ids are below this; 0 is "no stream", which KashPass refuses. */
    const val COUNT = 4

    private val SALSA20_NONCE = byteArrayOf(0xE8.toByte(), 0x30, 0x09, 0x4B, 0x97.toByte(), 0x20, 0x5D, 0x2A)

    /**
     * Returns the keystream for stream [id] keyed by [key] (at least 1 byte); the caller closes it.
     * Throws [KdbxException.InvalidLength] for an empty key and for an id other than 1, 2 or 3,
     * which the inner header reader refuses first.
     */
    fun open(id: Int, key: ByteArray, buffers: Buffers = Buffers.Default): Keystream {
        if (key.isEmpty()) throw KdbxException.InvalidLength(KdbxException.Field.KEY)
        return when (id) {
            CHACHA20 -> {
                val hash = buffers.bytes(Digests.SHA512_BYTES)
                val k = buffers.bytes(32)
                val nonce = buffers.bytes(12)
                try {
                    Digests.sha512Into(hash, 0, key)
                    hash.copyInto(k, 0, 0, 32)
                    hash.copyInto(nonce, 0, 32, 44)
                    ChaCha20(k, nonce, ChaCha20.Counter.LARGE, buffers)
                } finally {
                    Bytes.zeroFill(hash, k, nonce)
                }
            }
            SALSA20 -> {
                val k = buffers.bytes(Digests.SHA256_BYTES)
                try {
                    Digests.sha256Into(k, 0, key)
                    Salsa20(k, SALSA20_NONCE, buffers)
                } finally {
                    k.fill(0)
                }
            }
            ARCFOUR_VARIANT -> ArcFourVariant(key, buffers)
            else -> throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        }
    }
}
