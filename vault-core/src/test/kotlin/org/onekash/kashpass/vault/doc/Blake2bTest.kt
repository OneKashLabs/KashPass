package org.onekash.kashpass.vault.doc

import java.util.HexFormat
import kotlin.test.assertEquals
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class Blake2bTest {

    private fun hash(message: ByteArray, length: Int, chunk: Int): String {
        val digest = Blake2b(length)
        var off = 0
        while (off < message.size) {
            val n = minOf(chunk, message.size - off)
            digest.update(message, off, n)
            off += n
        }
        val out = ByteArray(length)
        digest.digest(out)
        return HexFormat.of().formatHex(out)
    }

    // Messages are bytes i % 251 for i in 0 until size. Expected values: Python 3 hashlib.blake2b
    // with digest_size; the 3-byte "abc" case is RFC 7693 Appendix A.
    @ParameterizedTest(name = "{0} bytes, {1}-byte digest")
    @CsvSource(
        "0, 64, 786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
        "127, 64, b6292669ccd38d5f01caae96ba272c76a879a45743afa0725d83b9ebb26665b731f1848c52f11972b6644f554c064fa90780dbbbf3a89d4fc31f67df3e5857ef",
        "128, 64, 2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115",
        "129, 32, f7f3c46ba2564ff4c4c162da1f5b605f9f1c4aa6a20652a9f9a337c1a2f5b9c9",
        "256, 1, 59",
        "1000, 48, f0a7a4bb3c3290f432e513caa227ab3bf933c4c8c167193dff1cb10a0b992f042f5679e477f00c551e2cf2bec8101f1e",
        "1024, 64, 8d1090909017add40e749df2d0ebac43273d6fc816bc4ffaf2a6dfabe4206dea13677d2002399e4a38e700d8083db4af8341ee9b3a5147110b6a963a3894e4e2",
    )
    fun `digest matches the reference for whole and split input`(size: Int, length: Int, expected: String) {
        val message = ByteArray(size) { (it % 251).toByte() }
        for (chunk in listOf(maxOf(size, 1), 1, 7, 128, 200)) assertEquals(expected, hash(message, length, chunk), "chunk $chunk")
    }

    @ParameterizedTest
    @CsvSource("1", "2")
    fun `abc hashes to the RFC 7693 Appendix A value, also on reuse`(times: Int) {
        val digest = Blake2b(64)
        val out = ByteArray(64)
        repeat(times) {
            digest.update("abc".toByteArray())
            digest.digest(out)
        }
        assertEquals(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            HexFormat.of().formatHex(out),
        )
    }
}
