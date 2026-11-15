package org.onekash.kashpass.vault.kdbx

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.testing.RecordingBuffers

class HmacSha256Test {

    private fun jca(key: ByteArray, data: ByteArray): ByteArray {
        // JCA refuses an empty key; RFC 2104 pads it with zeros like any short key.
        val spec = if (key.isEmpty()) SecretKeySpec(ByteArray(1), "HmacSHA256") else SecretKeySpec(key, "HmacSHA256")
        return Mac.getInstance("HmacSHA256").apply { init(spec) }.doFinal(data)
    }

    @Test
    fun `equals JCA HmacSHA256 on random keys and messages`() {
        val r = Random(1)
        repeat(300) {
            val key = r.nextBytes(r.nextInt(1, 201))
            val data = r.nextBytes(r.nextInt(0, 3001))
            assertContentEquals(jca(key, data), HmacSha256(key).use { it.mac(data) }, "case $it")
        }
    }

    @Test
    fun `an empty key is a key of zeros`() {
        assertContentEquals(HmacSha256(ByteArray(1)).use { it.mac(byteArrayOf(1, 2, 3)) }, HmacSha256(ByteArray(0)).use { it.mac(byteArrayOf(1, 2, 3)) })
    }

    @Test
    fun `one instance computes successive MACs and a message fed in parts`() {
        val key = Random(2).nextBytes(32)
        val data = Random(3).nextBytes(500)
        HmacSha256(key).use { h ->
            assertContentEquals(jca(key, data), h.mac(data))
            h.update(data, 0, 100)
            h.update(data, 100, 0)
            h.update(data, 100, 400)
            val out = ByteArray(40)
            h.finish(out, 5)
            assertContentEquals(jca(key, data), out.copyOfRange(5, 37))
            assertContentEquals(jca(key, ByteArray(0)), h.mac(ByteArray(0)))
        }
    }

    @Test
    fun `ranges outside the arrays are refused`() {
        HmacSha256(ByteArray(32)).use { h ->
            assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { h.update(ByteArray(4), 2, 3) }.field)
            assertThrows<KdbxException.InvalidLength> { h.finish(ByteArray(40), 9) }
        }
    }

    @Test
    fun `close zero-fills the pads and inner hash, and a long key's hash`() {
        val short = RecordingBuffers()
        HmacSha256(Random(4).nextBytes(64), short).use { it.mac(ByteArray(10)) }
        short.assertRecorded(bytes = listOf(64, 64, 32))
        short.assertAllZero()

        val long = RecordingBuffers()
        val h = HmacSha256(Random(5).nextBytes(131), long)
        h.mac(ByteArray(10))
        h.close()
        long.assertRecorded(bytes = listOf(64, 64, 32, 32))
        long.assertAllZero()
        assertThrows<KdbxException.Closed> { h.mac(ByteArray(1)) }
    }
}
