package org.onekash.kashpass.vault.kdbx

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.InnerStream
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.KeystreamVectors
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.RecordingBuffers

class ChaCha20Test {

    private fun chacha(key: ByteArray, nonce: ByteArray, counter: ChaCha20.Counter = ChaCha20.Counter.RFC8439, initial: Int = 0, buffers: Buffers = Buffers.Default) =
        ChaCha20(key, nonce, counter, buffers, initial)

    private fun ChaCha20.apply(data: ByteArray): ByteArray = data.copyOf().also { xor(it, 0, it.size) }

    @Test
    fun `RFC 8439 section 2-3-2 block function gives the serialized block`() {
        val out = chacha(KeystreamVectors.RFC8439_BLOCK_KEY.hexToByteArray(), KeystreamVectors.RFC8439_BLOCK_NONCE.hexToByteArray(), initial = KeystreamVectors.RFC8439_BLOCK_COUNTER)
            .apply(ByteArray(64))
        assertContentEquals(KeystreamVectors.RFC8439_BLOCK.hexToByteArray(), out)
    }

    @Test
    fun `RFC 8439 section 2-4-2 and appendix A vectors pass`() {
        assertEquals(9, KeystreamVectors.chacha.size)
        for (v in KeystreamVectors.chacha) {
            val out = chacha(v.key.hexToByteArray(), v.nonce.hexToByteArray(), initial = v.counter).apply(v.plaintext.hexToByteArray())
            assertContentEquals(v.ciphertext.hexToByteArray(), out, v.name)
        }
    }

    @Test
    fun `KeePassLib's large-counter self-test vector passes`() {
        val v = KeystreamVectors.chachaLargeCounterTc8
        val out = chacha(v.key.hexToByteArray(), v.nonce.hexToByteArray(), ChaCha20.Counter.LARGE).apply(v.plaintext.hexToByteArray())
        assertContentEquals(v.ciphertext.hexToByteArray(), out)
    }

    @Test
    fun `a stream split at any boundary gives the one-call result`() {
        val r = Random(1)
        val key = r.nextBytes(32)
        val nonce = r.nextBytes(12)
        val whole = chacha(key, nonce).apply(ByteArray(1000))
        repeat(20) {
            val data = ByteArray(1000)
            val c = chacha(key, nonce)
            var at = 0
            while (at < data.size) {
                val n = minOf(r.nextInt(0, 130), data.size - at)
                c.xor(data, at, n)
                at += n
            }
            assertContentEquals(whole, data)
        }
    }

    @Test
    fun `the RFC 8439 counter never uses block 2^32-1, as KeePassLib`() {
        val c = chacha(ByteArray(32), ByteArray(12), initial = -1)
        val data = ByteArray(1)
        assertThrows<KdbxException.KeystreamExhausted> { c.xor(data, 0, 1) }
        assertEquals(0, data[0].toInt())
        assertThrows<KdbxException.KeystreamExhausted> { c.xor(data, 0, 1) }
        // The block before the last counter value is used.
        assertEquals(64, chacha(ByteArray(32), ByteArray(12), initial = -2).apply(ByteArray(64)).size)
    }

    @Test
    fun `the large counter carries into the first nonce word`() {
        val key = Random(2).nextBytes(32)
        val nonce = Random(3).nextBytes(12)
        val stream = chacha(key, nonce, ChaCha20.Counter.LARGE, initial = -1).apply(ByteArray(128))
        val carried = nonce.copyOf().also { Bytes.writeLe32(it, 0, Bytes.readLe32(nonce, 0) + 1) }
        assertContentEquals(chacha(key, carried, ChaCha20.Counter.LARGE).apply(ByteArray(64)), stream.copyOfRange(64, 128))
    }

    @Test
    fun `equals the desktop JDK's ChaCha20 on random inputs`() {
        val r = Random(4)
        repeat(200) {
            val key = r.nextBytes(32)
            val nonce = r.nextBytes(12)
            val counter = if (it % 3 == 0) r.nextInt(0, 1000) else 0
            val plain = r.nextBytes(r.nextInt(0, 5001))
            val jdk = Cipher.getInstance("ChaCha20").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), ChaCha20ParameterSpec(nonce, counter)) }
            val expected = if (plain.isEmpty()) ByteArray(0) else jdk.doFinal(plain)
            assertContentEquals(expected, chacha(key, nonce, initial = counter).apply(plain), "case $it")
        }
    }

    @Test
    fun `the KDBX inner stream built on it equals the test toolkit's`() {
        val r = Random(5)
        repeat(200) {
            val innerKey = r.nextBytes(r.nextInt(1, 100))
            val hash = MessageDigest.getInstance("SHA-512").digest(innerKey)
            val plain = r.nextBytes(r.nextInt(0, 5001))
            val owned = chacha(hash.copyOf(32), hash.copyOfRange(32, 44), ChaCha20.Counter.LARGE).apply(plain)
            assertContentEquals(InnerStream.create(KdbxToolkit.CHACHA20, innerKey).process(plain), owned, "toolkit, case $it")
        }
    }

    @Test
    fun `a key or nonce of the wrong size is refused`() {
        assertEquals(KdbxException.Field.KEY, assertThrows<KdbxException.InvalidLength> { chacha(ByteArray(31), ByteArray(12)) }.field)
        assertEquals(KdbxException.Field.NONCE, assertThrows<KdbxException.InvalidLength> { chacha(ByteArray(32), ByteArray(8)) }.field)
    }

    @Test
    fun `a range outside the array is refused and leaves it unchanged`() {
        val c = chacha(ByteArray(32), ByteArray(12))
        val data = ByteArray(10)
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { c.xor(data, 5, 6) }.field)
        assertContentEquals(ByteArray(10), data)
        // The refused call used no keystream.
        c.xor(data, 0, 10)
        assertContentEquals(chacha(ByteArray(32), ByteArray(12)).apply(ByteArray(10)), data)
    }

    @Test
    fun `close zero-fills the state and keystream and refuses later use`() {
        val buffers = RecordingBuffers()
        val c = chacha(Random(6).nextBytes(32), Random(7).nextBytes(12), buffers = buffers)
        c.xor(ByteArray(100), 0, 100)
        c.close()
        buffers.assertRecorded(bytes = listOf(64), ints = listOf(16, 16))
        buffers.assertAllZero()
        assertThrows<KdbxException.Closed> { c.xor(ByteArray(1), 0, 1) }
    }

    @Test
    fun `close after an exhausted counter zero-fills everything`() {
        val buffers = RecordingBuffers()
        val c = chacha(Random(8).nextBytes(32), ByteArray(12), buffers = buffers, initial = -1)
        assertThrows<KdbxException.KeystreamExhausted> { c.xor(ByteArray(1), 0, 1) }
        c.close()
        buffers.assertRecorded(bytes = listOf(64), ints = listOf(16, 16))
        buffers.assertAllZero()
    }

    @Test
    fun `outer encryption with the header IV and the RFC 8439 counter gives the ciphertext KeePass 2 wrote`() {
        val bytes = Fixtures.bytes("keepass2-chacha20-argon2d.kdbx")
        val opened = KdbxToolkit.open(bytes, KdbxToolkit.Key(TestFiles.password))
        val header = RawKdbx.parse(bytes)
        val cipherKey = KdbxToolkit.sha256(header.field(RawKdbx.MASTER_SEED) + opened.transformedKey)
        val payload = opened.compressedBytes ?: opened.contentBytes
        val encrypted = chacha(cipherKey, header.field(RawKdbx.ENCRYPTION_IV)).apply(payload)
        assertContentEquals(opened.ciphertext, encrypted)
        assertContentEquals(payload, chacha(cipherKey, header.field(RawKdbx.ENCRYPTION_IV)).apply(encrypted))
    }
}
