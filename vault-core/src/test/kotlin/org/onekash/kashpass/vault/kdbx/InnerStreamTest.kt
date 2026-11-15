package org.onekash.kashpass.vault.kdbx

import kotlin.random.Random
import kotlin.test.assertContentEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.onekash.kashpass.vault.testing.RecordingBuffers
import org.onekash.kashpass.vault.testing.InnerStream as ToolkitStream

class InnerStreamTest {

    @ParameterizedTest(name = "stream {0}, key of {1} bytes")
    @CsvSource("1, 1", "1, 32", "1, 64", "2, 1", "2, 32", "2, 64", "3, 1", "3, 32", "3, 64")
    fun `each stream gives KeePass 2's keystream, split across calls at any boundary`(id: Int, keyLength: Int) {
        val key = Random(keyLength * 10 + id).nextBytes(keyLength)
        val data = Random(id).nextBytes(5_000)
        val expected = ToolkitStream.create(id, key).process(data)
        val buffers = RecordingBuffers()
        val actual = data.copyOf()
        InnerStream.open(id, key, buffers).use { s ->
            var at = 0
            for (n in listOf(1, 63, 64, 65, 1000, 3807)) {
                s.xor(actual, at, n)
                at += n
            }
        }
        assertContentEquals(expected, actual)
        buffers.assertAllZero()
    }

    @Test
    fun `an empty key or an unknown id is refused`() {
        assertThrows<KdbxException.InvalidLength> { InnerStream.open(3, ByteArray(0)) }
        assertThrows<KdbxException.InvalidLength> { InnerStream.open(0, ByteArray(32)) }
        assertThrows<KdbxException.InvalidLength> { InnerStream.open(4, ByteArray(32)) }
    }
}
