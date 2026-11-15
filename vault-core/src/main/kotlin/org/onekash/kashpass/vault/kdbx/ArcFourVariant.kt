package org.onekash.kashpass.vault.kdbx

/**
 * The KDBX ArcFour variant inner random stream (inner stream id 1, and the stream a KDBX file uses
 * when neither header names one). It differs from RC4 in the key setup, where every swap exchanges
 * entry 0 with entry j instead of entry i with entry j, and it drops the first 512 keystream bytes.
 * The key is used as given (1 byte or more, never hashed), else [KdbxException.InvalidLength]; the
 * caller zero-fills its own key array. [close] runs after the last call returns, never alongside
 * one.
 */
internal class ArcFourVariant(key: ByteArray, buffers: Buffers = Buffers.Default) : Keystream {

    private val s: ByteArray = buffers.bytes(256)
    private var i = 0
    private var j = 0

    @Volatile
    private var closed = false

    init {
        if (key.isEmpty()) throw KdbxException.InvalidLength(KdbxException.Field.ARCFOUR_KEY)
        for (w in 0 until 256) s[w] = w.toByte()
        var jj = 0
        var k = 0
        for (w in 0 until 256) {
            jj = (jj + (s[w].toInt() and 0xFF) + (key[k].toInt() and 0xFF)) and 0xFF
            val t = s[0]
            s[0] = s[jj]
            s[jj] = t
            if (++k >= key.size) k = 0
        }
        repeat(512) { next() }
    }

    override fun xor(data: ByteArray, offset: Int, length: Int) {
        if (closed) throw KdbxException.Closed()
        Bytes.checkRange(data.size, offset, length)
        for (w in offset until offset + length) data[w] = (data[w].toInt() xor next()).toByte()
    }

    private fun next(): Int {
        i = (i + 1) and 0xFF
        j = (j + (s[i].toInt() and 0xFF)) and 0xFF
        val t = s[i]
        s[i] = s[j]
        s[j] = t
        return s[((s[i].toInt() and 0xFF) + (s[j].toInt() and 0xFF)) and 0xFF].toInt()
    }

    override fun close() {
        closed = true
        s.fill(0)
        i = 0
        j = 0
    }
}
