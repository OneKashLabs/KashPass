package org.onekash.kashpass.vault.doc

import org.onekash.kashpass.vault.kdbx.Bytes

/**
 * Computes unkeyed BLAKE2b (RFC 7693) with a digest of 1 to 64 bytes, the hash Argon2 builds on
 * (RFC 9106 section 3.2). [Blake2bTest] checks it against RFC 7693 Appendix A and Python's
 * hashlib.
 */
internal class Blake2b(private val digestLength: Int) {

    private val h = LongArray(8)
    private val buffer = ByteArray(BLOCK_BYTES)
    private val m = LongArray(16)
    private val v = LongArray(16)
    private var buffered = 0
    private var counter = 0L

    init {
        require(digestLength in 1..64) { "BLAKE2b digest length must be 1 to 64 bytes" }
        reset()
    }

    /** Adds [len] bytes of [input] from [off]. */
    fun update(input: ByteArray, off: Int = 0, len: Int = input.size) {
        var pos = off
        val end = off + len
        while (pos < end) {
            // The last block is compressed only in [digest], with the final-block flag set.
            if (buffered == BLOCK_BYTES) {
                counter += BLOCK_BYTES
                compress(last = false)
                buffered = 0
            }
            val n = minOf(BLOCK_BYTES - buffered, end - pos)
            System.arraycopy(input, pos, buffer, buffered, n)
            buffered += n
            pos += n
        }
    }

    /** Adds [value] as 4 little-endian bytes. */
    fun updateInt(value: Int) {
        val bytes = ByteArray(4)
        Bytes.writeLe32(bytes, 0, value)
        update(bytes)
    }

    /** Writes the digest to [out] at [off], then starts a new hash with the same length. */
    fun digest(out: ByteArray, off: Int = 0) {
        counter += buffered
        buffer.fill(0, buffered, BLOCK_BYTES)
        compress(last = true)
        for (i in 0 until digestLength) out[off + i] = (h[i / 8] ushr (8 * (i % 8))).toByte()
        reset()
    }

    private fun reset() {
        IV.copyInto(h)
        // Parameter block word 0: digest length, key length 0, fanout 1, depth 1.
        h[0] = h[0] xor (0x0101_0000L or digestLength.toLong())
        buffer.fill(0)
        m.fill(0)
        v.fill(0)
        buffered = 0
        counter = 0L
    }

    private fun compress(last: Boolean) {
        for (i in 0 until 16) m[i] = Bytes.readLe64(buffer, i * 8)
        h.copyInto(v, 0)
        IV.copyInto(v, 8)
        // Messages stay far below 2^64 bytes, so the high counter word is always 0.
        v[12] = v[12] xor counter
        if (last) v[14] = v[14].inv()
        for (round in 0 until 12) {
            val s = SIGMA[round % 10]
            mix(0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
    }

    // RFC 7693 section 3.1, function G.
    private fun mix(a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] += v[b] + x
        v[d] = (v[d] xor v[a]).rotateRight(32)
        v[c] += v[d]
        v[b] = (v[b] xor v[c]).rotateRight(24)
        v[a] += v[b] + y
        v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] += v[d]
        v[b] = (v[b] xor v[c]).rotateRight(63)
    }

    companion object {
        const val BLOCK_BYTES = 128

        private val IV = longArrayOf(
            0x6a09e667f3bcc908L, -0x4498517a7b3558c5L, 0x3c6ef372fe94f82bL, -0x5ab00ac5a0e2c90fL,
            0x510e527fade682d1L, -0x64fa9773d4c193e1L, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
        )

        private val SIGMA = arrayOf(
            intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
            intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
            intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
            intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
            intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
            intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
            intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
            intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
            intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
            intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
        )
    }
}
