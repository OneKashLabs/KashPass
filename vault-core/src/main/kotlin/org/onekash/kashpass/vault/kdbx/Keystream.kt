package org.onekash.kashpass.vault.kdbx

/**
 * A stream cipher's keystream, consumed in order. [xor] XORs the next keystream bytes into a
 * range of an array in place, so encryption and decryption are the same call and a stream split
 * across calls at any boundary gives the bytes one call gives.
 */
internal interface Keystream : AutoCloseable {

    /**
     * XORs the next [length] keystream bytes into [data] from [offset]. Throws
     * [KdbxException.InvalidLength] for a range outside [data] (leaving [data] unchanged),
     * [KdbxException.KeystreamExhausted] when the cipher's counter runs out and
     * [KdbxException.Closed] after [close]. [close] runs after the last call returns, never
     * alongside one.
     */
    fun xor(data: ByteArray, offset: Int, length: Int)

    /** Zero-fills the key, the state and the buffered keystream. */
    override fun close()
}

/**
 * A keystream made of 64-byte blocks, each from a 16-word state: the base of [ChaCha20] and
 * [Salsa20]. The state, the working copy and the current block come from [buffers] and are
 * zero-filled on [close].
 */
internal abstract class BlockKeystream(buffers: Buffers) : Keystream {

    protected val state: IntArray = buffers.ints(16)
    protected val working: IntArray = buffers.ints(16)
    private val block: ByteArray = buffers.bytes(64)
    private var used = 64

    @Volatile
    private var closed = false
    private var exhausted = false

    /**
     * Fills [working] with the next block's words (rounds plus the state added back) and
     * advances the counter in [state]; throws [KdbxException.KeystreamExhausted] when the counter
     * cannot advance, after the block is computed and before it is used.
     */
    protected abstract fun nextBlock()

    final override fun xor(data: ByteArray, offset: Int, length: Int) {
        if (closed) throw KdbxException.Closed()
        Bytes.checkRange(data.size, offset, length)
        var i = offset
        val end = offset + length
        while (i < end) {
            if (used == 64) refill()
            val n = minOf(64 - used, end - i)
            for (k in 0 until n) data[i + k] = (data[i + k].toInt() xor block[used + k].toInt()).toByte()
            used += n
            i += n
        }
    }

    private fun refill() {
        if (exhausted) throw KdbxException.KeystreamExhausted()
        try {
            nextBlock()
        } catch (e: KdbxException.KeystreamExhausted) {
            exhausted = true
            working.fill(0)
            throw e
        }
        for (w in 0 until 16) {
            val v = working[w]
            block[4 * w] = v.toByte()
            block[4 * w + 1] = (v ushr 8).toByte()
            block[4 * w + 2] = (v ushr 16).toByte()
            block[4 * w + 3] = (v ushr 24).toByte()
        }
        working.fill(0)
        used = 0
    }

    final override fun close() {
        closed = true
        state.fill(0)
        working.fill(0)
        block.fill(0)
    }

    protected companion object {
        /** Loads [words] little-endian words of [bytes] from byte [from] into [state] from [at]. */
        fun loadWords(state: IntArray, at: Int, bytes: ByteArray, from: Int, words: Int) {
            for (w in 0 until words) state[at + w] = Bytes.readLe32(bytes, from + 4 * w)
        }

        // The words "expand 32-byte k" for a 256-bit key, shared by ChaCha20 and Salsa20.
        const val SIGMA0 = 0x61707865
        const val SIGMA1 = 0x3320646e
        const val SIGMA2 = 0x79622d32
        const val SIGMA3 = 0x6b206574
    }
}
