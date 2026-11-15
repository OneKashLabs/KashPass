package org.onekash.kashpass.vault.kdbx

import java.security.MessageDigest
import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.testing.InnerStream
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.KeystreamVectors
import org.onekash.kashpass.vault.testing.RecordingBuffers

class Salsa20Test {

    private fun Keystream.apply(data: ByteArray): ByteArray = data.copyOf().also { xor(it, 0, it.size) }

    // The fixed nonce of the KDBX Salsa20 inner stream.
    private val innerNonce = "e830094b97205d2a".hexToByteArray()

    @Test
    fun `eSTREAM and KeePassLib self-test vectors pass`() {
        assertEquals(5, KeystreamVectors.salsa.size)
        for (v in KeystreamVectors.salsa) {
            val keystream = v.keystream.hexToByteArray()
            val s = Salsa20(v.key.hexToByteArray(), v.nonce.hexToByteArray(), initialBlock = (v.position / 64).toLong())
            assertContentEquals(keystream, s.apply(ByteArray(keystream.size)), v.name)
        }
    }

    @Test
    fun `a later position reached by streaming equals the one reached by the block counter`() {
        val v = KeystreamVectors.salsa.first { it.position == 65536 }
        val s = Salsa20(v.key.hexToByteArray(), v.nonce.hexToByteArray())
        s.xor(ByteArray(65536), 0, 65536)
        assertContentEquals(v.keystream.hexToByteArray(), s.apply(ByteArray(16)))
    }

    @Test
    fun `the block counter carries into its high word`() {
        val key = Random(1).nextBytes(32)
        val nonce = Random(2).nextBytes(8)
        val stream = Salsa20(key, nonce, initialBlock = 0xFFFF_FFFFL).apply(ByteArray(128))
        assertContentEquals(Salsa20(key, nonce, initialBlock = 0x1_0000_0000L).apply(ByteArray(64)), stream.copyOfRange(64, 128))
    }

    @Test
    fun `the KDBX inner stream built on it equals the test toolkit's`() {
        val r = Random(3)
        repeat(200) {
            val innerKey = r.nextBytes(r.nextInt(1, 100))
            val plain = r.nextBytes(r.nextInt(0, 5001))
            val owned = Salsa20(MessageDigest.getInstance("SHA-256").digest(innerKey), innerNonce).apply(plain)
            assertContentEquals(InnerStream.create(KdbxToolkit.SALSA20, innerKey).process(plain), owned, "toolkit, case $it")
        }
    }

    @Test
    fun `a key or nonce of the wrong size is refused`() {
        assertEquals(KdbxException.Field.KEY, assertThrows<KdbxException.InvalidLength> { Salsa20(ByteArray(16), ByteArray(8)) }.field)
        assertEquals(KdbxException.Field.NONCE, assertThrows<KdbxException.InvalidLength> { Salsa20(ByteArray(32), ByteArray(12)) }.field)
    }

    @Test
    fun `a range outside the array is refused`() {
        assertThrows<KdbxException.InvalidLength> { Salsa20(ByteArray(32), ByteArray(8)).xor(ByteArray(4), -1, 2) }
    }

    @Test
    fun `close zero-fills the state and keystream and refuses later use`() {
        val buffers = RecordingBuffers()
        val s = Salsa20(Random(4).nextBytes(32), Random(5).nextBytes(8), buffers)
        s.xor(ByteArray(200), 0, 200)
        s.close()
        buffers.assertRecorded(bytes = listOf(64), ints = listOf(16, 16))
        buffers.assertAllZero()
        assertThrows<KdbxException.Closed> { s.xor(ByteArray(1), 0, 1) }
    }
}
