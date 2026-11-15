package org.onekash.kashpass.vault.kdbx

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.testing.RecordingBuffers

class BytesTest {

    @Test
    fun `32-bit and 64-bit values round trip little-endian at an offset`() {
        val buf = ByteArray(11)
        for (v in listOf(0, 1, -1, Int.MIN_VALUE, Int.MAX_VALUE, 0x01020304)) {
            Bytes.writeLe32(buf, 3, v)
            assertEquals(v, Bytes.readLe32(buf, 3))
        }
        for (v in listOf(0L, 1L, -1L, Long.MIN_VALUE, Long.MAX_VALUE)) {
            Bytes.writeLe64(buf, 3, v)
            assertEquals(v, Bytes.readLe64(buf, 3))
        }
        for (v in listOf(0, 1, 0x0100, 0xFFFF)) {
            Bytes.writeLe16(buf, 9, v)
            assertEquals(v, Bytes.readLe16(buf, 9))
        }
    }

    @Test
    fun `the byte order is little-endian`() {
        val buf = ByteArray(8)
        Bytes.writeLe32(buf, 0, 0x01020304)
        assertContentEquals(byteArrayOf(4, 3, 2, 1, 0, 0, 0, 0), buf)
        // Block index 2^64-1, the header key's index, is -1 as a Long.
        Bytes.writeLe64(buf, 0, -1L)
        assertContentEquals(ByteArray(8) { -1 }, buf)
        Bytes.writeLe16(buf, 0, 0x0100)
        assertContentEquals(byteArrayOf(0, 1), buf.copyOf(2))
    }

    @Test
    fun `reads and writes outside the array throw InvalidLength RANGE`() {
        val buf = ByteArray(8)
        val calls = listOf<() -> Unit>(
            { Bytes.readLe32(buf, 5) }, { Bytes.readLe32(buf, -1) }, { Bytes.readLe64(buf, 1) },
            { Bytes.readLe16(buf, 7) }, { Bytes.writeLe32(buf, Int.MAX_VALUE, 0) }, { Bytes.writeLe64(buf, 1, 0) },
            { Bytes.writeLe16(buf, 7, 0) },
        )
        for (call in calls) {
            assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { call() }.field)
        }
    }

    @Test
    fun `checkRange accepts the whole array and refuses overflowing sums`() {
        Bytes.checkRange(10, 0, 10)
        Bytes.checkRange(10, 10, 0)
        Bytes.checkRange(0, 0, 0)
        for ((offset, length) in listOf(0 to 11, 11 to 0, -1 to 1, 1 to -1, Int.MAX_VALUE to Int.MAX_VALUE, 1 to Int.MAX_VALUE)) {
            assertThrows<KdbxException.InvalidLength> { Bytes.checkRange(10, offset, length) }
        }
    }

    @Test
    fun `constantTimeEquals compares content and length`() {
        assertTrue(Bytes.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)))
        assertTrue(Bytes.constantTimeEquals(ByteArray(0), ByteArray(0)))
        assertFalse(Bytes.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4)))
        assertFalse(Bytes.constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2)))
    }

    @Test
    fun `zeroFill clears every array it is given`() {
        val a = byteArrayOf(1, 2)
        val b = byteArrayOf(3)
        val c = intArrayOf(4, 5)
        Bytes.zeroFill(a, null, b)
        Bytes.zeroFill(c)
        assertTrue(a.all { it.toInt() == 0 } && b.all { it.toInt() == 0 } && c.all { it == 0 })
    }

    @Test
    fun `recording buffers find a non-zero array and a wrong allocation count`() {
        val buffers = RecordingBuffers()
        val bytes = buffers.bytes(4)
        val ints = buffers.ints(2)
        buffers.assertRecorded(bytes = listOf(4), ints = listOf(2))
        buffers.assertAllZero()
        bytes[1] = 7
        assertTrue(assertThrows<IllegalStateException> { buffers.assertAllZero() }.message!!.contains("4 bytes"))
        bytes.fill(0)
        ints[0] = 1
        assertThrows<IllegalStateException> { buffers.assertAllZero() }
        assertThrows<IllegalStateException> { buffers.assertRecorded(bytes = emptyList(), ints = listOf(2)) }
    }

    @Test
    fun `every KdbxException has no message and no stack trace`() {
        val all = listOf(
            KdbxException.InvalidLength(KdbxException.Field.KEY), KdbxException.CiphertextNotBlockMultiple(),
            KdbxException.BadPadding(), KdbxException.KeystreamExhausted(), KdbxException.Closed(),
            KdbxException.CompressedData(KdbxException.Fault.CRC), KdbxException.InflatedTooLarge(1),
            KdbxException.AlgorithmUnavailable(), KdbxException.DictionaryTooLarge(),
        )
        for (e in all) {
            assertNull(e.message, e.javaClass.simpleName)
            assertEquals(0, e.stackTrace.size, e.javaClass.simpleName)
        }
    }
}
