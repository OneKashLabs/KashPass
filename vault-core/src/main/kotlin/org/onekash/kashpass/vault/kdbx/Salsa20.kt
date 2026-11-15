package org.onekash.kashpass.vault.kdbx

/**
 * Salsa20/20 with a 256-bit key, a 64-bit nonce and a 64-bit block counter from 0 (eSTREAM). A
 * KDBX 4 file can name it as the inner random stream.
 *
 * [key] must be 32 bytes and [nonce] 8, else [KdbxException.InvalidLength]; both are copied into
 * the state, so the caller zero-fills its own arrays. [initialBlock] exists for tests of later
 * stream positions.
 */
internal class Salsa20(
    key: ByteArray,
    nonce: ByteArray,
    buffers: Buffers = Buffers.Default,
    initialBlock: Long = 0,
) : BlockKeystream(buffers) {

    init {
        if (key.size != 32) throw KdbxException.InvalidLength(KdbxException.Field.KEY)
        if (nonce.size != 8) throw KdbxException.InvalidLength(KdbxException.Field.NONCE)
        state[0] = SIGMA0
        loadWords(state, 1, key, 0, 4)
        state[5] = SIGMA1
        loadWords(state, 6, nonce, 0, 2)
        state[8] = initialBlock.toInt()
        state[9] = (initialBlock ushr 32).toInt()
        state[10] = SIGMA2
        loadWords(state, 11, key, 16, 4)
        state[15] = SIGMA3
    }

    override fun nextBlock() {
        val x = working
        state.copyInto(x)
        repeat(10) {
            quarterRound(x, 0, 4, 8, 12)
            quarterRound(x, 5, 9, 13, 1)
            quarterRound(x, 10, 14, 2, 6)
            quarterRound(x, 15, 3, 7, 11)
            quarterRound(x, 0, 1, 2, 3)
            quarterRound(x, 5, 6, 7, 4)
            quarterRound(x, 10, 11, 8, 9)
            quarterRound(x, 15, 12, 13, 14)
        }
        for (i in 0 until 16) x[i] += state[i]
        state[8]++
        if (state[8] == 0) state[9]++
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[b] = x[b] xor Integer.rotateLeft(x[a] + x[d], 7)
        x[c] = x[c] xor Integer.rotateLeft(x[b] + x[a], 9)
        x[d] = x[d] xor Integer.rotateLeft(x[c] + x[b], 13)
        x[a] = x[a] xor Integer.rotateLeft(x[d] + x[c], 18)
    }
}
