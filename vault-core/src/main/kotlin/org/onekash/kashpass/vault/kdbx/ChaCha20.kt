package org.onekash.kashpass.vault.kdbx

/**
 * ChaCha20 as RFC 8439 section 2.4 defines it (20 rounds, 256-bit key, 96-bit nonce, no
 * Poly1305), with one of two block counter endings ([Counter]). The outer cipher of a KDBX 4
 * file uses the header's 12-byte IV as the nonce and [Counter.RFC8439]; the inner random stream
 * uses [Counter.LARGE]. Pure Kotlin: the desktop JDK's raw ChaCha20 takes only a
 * ChaCha20ParameterSpec, which Android has only from API 35, and Android's default provider takes
 * only an IvParameterSpec, so no one JCA call serves both.
 *
 * [key] must be 32 bytes and [nonce] 12, else [KdbxException.InvalidLength]; both are copied into
 * the state, so the caller zero-fills its own arrays. [initialCounter] (a 32-bit value) exists for
 * the published vectors that start at counter 1 or 42 and for counter-limit tests.
 */
internal class ChaCha20(
    key: ByteArray,
    nonce: ByteArray,
    private val counter: Counter,
    buffers: Buffers = Buffers.Default,
    initialCounter: Int = 0,
) : BlockKeystream(buffers) {

    /** How the 32-bit block counter in state word 12 ends. */
    enum class Counter {
        /**
         * RFC 8439: the block for counter 2^32-1 is computed, then the stream throws instead of
         * using it, so block 2^32-1 is never used.
         */
        RFC8439,

        /**
         * Large counter: when word 12 wraps to 0, word 13 (the first nonce word) counts on, as
         * the original ChaCha with a 64-bit counter does.
         */
        LARGE,
    }

    init {
        if (key.size != 32) throw KdbxException.InvalidLength(KdbxException.Field.KEY)
        if (nonce.size != 12) throw KdbxException.InvalidLength(KdbxException.Field.NONCE)
        state[0] = SIGMA0
        state[1] = SIGMA1
        state[2] = SIGMA2
        state[3] = SIGMA3
        loadWords(state, 4, key, 0, 8)
        state[12] = initialCounter
        loadWords(state, 13, nonce, 0, 3)
    }

    override fun nextBlock() {
        block(state, working)
        state[12]++
        if (state[12] == 0) {
            if (counter == Counter.RFC8439) throw KdbxException.KeystreamExhausted()
            state[13]++
        }
    }

    companion object {
        /** Writes the ChaCha20 block function of [input] (RFC 8439 section 2.3) into [out]. */
        private fun block(input: IntArray, out: IntArray) {
            input.copyInto(out)
            repeat(10) {
                quarterRound(out, 0, 4, 8, 12)
                quarterRound(out, 1, 5, 9, 13)
                quarterRound(out, 2, 6, 10, 14)
                quarterRound(out, 3, 7, 11, 15)
                quarterRound(out, 0, 5, 10, 15)
                quarterRound(out, 1, 6, 11, 12)
                quarterRound(out, 2, 7, 8, 13)
                quarterRound(out, 3, 4, 9, 14)
            }
            for (i in 0 until 16) out[i] += input[i]
        }

        private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
            x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] xor x[a], 16)
            x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] xor x[c], 12)
            x[a] += x[b]; x[d] = Integer.rotateLeft(x[d] xor x[a], 8)
            x[c] += x[d]; x[b] = Integer.rotateLeft(x[b] xor x[c], 7)
        }
    }
}
