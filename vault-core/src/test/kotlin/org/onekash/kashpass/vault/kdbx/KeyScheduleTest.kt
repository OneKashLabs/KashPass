package org.onekash.kashpass.vault.kdbx

import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RecordingBuffers

class KeyScheduleTest {

    private val seed = Random(1).nextBytes(32)
    private val transformed = Random(2).nextBytes(32)
    private fun sha256(b: ByteArray) = KdbxToolkit.sha256(b)

    @Test
    fun `the composite key hashes the password hash and the key-file part in that order`() {
        val password = "kashpass-test"
        val passwordHash = sha256(password.encodeToByteArray())
        val part = Random(3).nextBytes(32)
        assertContentEquals(KdbxToolkit.Key(password).composite(), CompositeKey.compute(passwordHash, null))
        assertContentEquals(KdbxToolkit.Key(null, part).composite(), CompositeKey.compute(null, part))
        assertContentEquals(KdbxToolkit.Key(password, part).composite(), CompositeKey.compute(passwordHash, part))
        // An empty password contributes the hash of the empty string.
        assertContentEquals(sha256(sha256(ByteArray(0))), CompositeKey.compute(sha256(ByteArray(0)), null))
        // An XML key file's data can have any non-empty length.
        assertContentEquals(sha256(passwordHash + byteArrayOf(7, 8, 9)), CompositeKey.compute(passwordHash, byteArrayOf(7, 8, 9)))
    }

    @Test
    fun `composite key inputs of the wrong size are refused`() {
        fun field(block: () -> Unit) = assertThrows<KdbxException.InvalidLength> { block() }.field
        assertEquals(KdbxException.Field.NO_KEY_PART, field { CompositeKey.compute(null, null) })
        assertEquals(KdbxException.Field.PASSWORD_HASH, field { CompositeKey.compute(ByteArray(31), null) })
        assertEquals(KdbxException.Field.KEY_FILE_PART, field { CompositeKey.compute(ByteArray(32), ByteArray(0)) })
    }

    @Test
    fun `cipher key, header MAC and block MACs equal the definitions`() {
        val macs = KdbxToolkit.Macs(KdbxToolkit.sha512(seed + transformed + byteArrayOf(1)))
        val data = Random(4).nextBytes(300)
        KeySchedule(seed, transformed).use { k ->
            assertContentEquals(sha256(seed + transformed), k.cipherKey())
            assertContentEquals(macs.header(data), k.headerMac(data, 0, data.size))
            for (index in listOf(0L, 1L, 7L, Long.MAX_VALUE, -2L)) {
                assertContentEquals(macs.block(index, data), k.blockMac(index, data, 0, data.size), "block $index")
            }
            assertContentEquals(macs.block(3L, ByteArray(0)), k.blockMac(3L, data, 10, 0))
            assertContentEquals(macs.block(5L, data.copyOfRange(10, 60)), k.blockMac(5L, data, 10, 50))
        }
    }

    @Test
    fun `the header key is the key of block 2^64-1`() {
        val base = KdbxToolkit.sha512(seed + transformed + byteArrayOf(1))
        val headerKey = KdbxToolkit.sha512(ByteArray(8) { -1 } + base)
        val data = Random(5).nextBytes(100)
        KeySchedule(seed, transformed).use { k -> assertContentEquals(HmacSha256(headerKey).use { it.mac(data) }, k.headerMac(data, 0, data.size)) }
    }

    @Test
    fun `seed, transformed key and ranges of the wrong size are refused`() {
        assertEquals(KdbxException.Field.MASTER_SEED, assertThrows<KdbxException.InvalidLength> { KeySchedule(ByteArray(16), transformed) }.field)
        assertEquals(KdbxException.Field.TRANSFORMED_KEY, assertThrows<KdbxException.InvalidLength> { KeySchedule(seed, ByteArray(64)) }.field)
        KeySchedule(seed, transformed).use { k ->
            assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { k.blockMac(0, ByteArray(4), 3, 2) }.field)
            assertThrows<KdbxException.InvalidLength> { k.headerMac(ByteArray(4), -1, 1) }
        }
    }

    @Test
    fun `close zero-fills the cipher key, the HMAC base and every block key`() {
        val buffers = RecordingBuffers()
        val k = KeySchedule(seed, transformed, buffers)
        k.headerMac(ByteArray(10), 0, 10)
        k.blockMac(0, ByteArray(10), 0, 10)
        k.close()
        // Cipher key and HMAC base, then per MAC: block key, HMAC pads and inner hash.
        buffers.assertRecorded(bytes = listOf(32, 64) + List(2) { listOf(64, 64, 64, 32) }.flatten())
        buffers.assertAllZero()
        assertThrows<KdbxException.Closed> { k.blockMac(1, ByteArray(1), 0, 1) }
        assertThrows<KdbxException.Closed> { k.cipherKey() }
    }

    @Test
    fun `a block key is zero-filled when its MAC call throws after deriving it`() {
        val recording = RecordingBuffers()
        // The 4th allocation is the HMAC's first pad, after the block key is derived.
        var calls = 0
        val failing = object : Buffers {
            override fun bytes(size: Int): ByteArray {
                if (++calls == 4) throw KdbxException.AlgorithmUnavailable()
                return recording.bytes(size)
            }
            override fun ints(size: Int) = recording.ints(size)
        }
        val k = KeySchedule(seed, transformed, failing)
        assertThrows<KdbxException.AlgorithmUnavailable> { k.blockMac(0, ByteArray(4), 0, 4) }
        recording.assertRecorded(bytes = listOf(32, 64, 64))
        // close() clears the cipher key and the HMAC base; the block key was cleared by the call.
        k.close()
        recording.assertAllZero()
    }
}
