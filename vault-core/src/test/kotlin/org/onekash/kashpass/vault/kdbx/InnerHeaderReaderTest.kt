package org.onekash.kashpass.vault.kdbx

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawField
import org.onekash.kashpass.vault.testing.RecordingBuffers
import org.onekash.kashpass.vault.testing.le32

class InnerHeaderReaderTest {

    private val key = ByteArray(64) { 5 }
    private val xml = "<KeePassFile/>".encodeToByteArray()

    private fun outer(key: ByteArray? = null, id: Int? = null) = OuterHeader(
        KdbxSignature.NORMAL, 4, 0, OuterCipher.AES_256, Compression.GZIP, ByteArray(32), ByteArray(16),
        KdfParameters.Aes(1UL, ByteArray(32)), null, key, id, 0,
    )

    private fun payload(fields: List<RawField>) = KdbxToolkit.innerBytes(fields) + xml

    private fun read(fields: List<RawField>, outer: OuterHeader = outer(), buffers: Buffers = Buffers.Default): InnerHeaderReader.Read {
        val p = payload(fields)
        return InnerHeaderReader.read(p, p.size, outer, buffers)
    }

    private fun failure(fields: List<RawField>, outer: OuterHeader = outer()): KdbxResult = assertThrows<KdbxFailure> { read(fields, outer) }.result

    private val end = RawField(0, ByteArray(0))
    private fun id(v: Int) = RawField(1, le32(v))
    private fun key(k: ByteArray = key) = RawField(2, k)
    private fun binary(flag: Int, data: ByteArray) = RawField(3, byteArrayOf(flag.toByte()) + data)

    @Test
    fun `fields are read in order and the XML starts after the end field`() {
        val r = read(listOf(id(3), key(), binary(1, byteArrayOf(1, 2)), binary(0, byteArrayOf()), binary(0, byteArrayOf(1, 2)), end))
        assertEquals(3, r.header.streamId)
        assertContentEquals(key, r.header.streamKey)
        assertEquals(listOf(true, false, false), r.header.attachments.map { it.protected })
        assertEquals(listOf(listOf<Byte>(1, 2), listOf(), listOf<Byte>(1, 2)), r.header.attachments.map { it.data.toList() })
        assertEquals(payload(listOf(id(3), key(), binary(1, byteArrayOf(1, 2)), binary(0, byteArrayOf()), binary(0, byteArrayOf(1, 2)), end)).size - xml.size, r.xmlOffset)
    }

    @Test
    fun `unknown ids are skipped, repeats keep the last value, the end value is ignored`() {
        val r = read(listOf(RawField(9, ByteArray(5)), id(1), key(ByteArray(3)), id(2), key(), RawField(0, byteArrayOf(1, 2, 3))))
        assertEquals(2, r.header.streamId)
        assertContentEquals(key, r.header.streamKey)
    }

    @Test
    fun `the outer fields stand in, and ArcFour variant is the default stream`() {
        assertEquals(3, read(listOf(key(), end), outer(id = 3)).header.streamId)
        assertEquals(1, read(listOf(key(), end)).header.streamId)
        assertContentEquals(byteArrayOf(9), read(listOf(id(3), end), outer(key = byteArrayOf(9))).header.streamKey)
        assertEquals(2, read(listOf(id(2), key(), end), outer(id = 3)).header.streamId)
    }

    @Test
    fun `stream id and key problems are damaged or unsupported as KeePass 2 finds them`() {
        val stream = KdbxResult.Damaged(KdbxDamage.INNER_STREAM)
        assertEquals(stream, failure(listOf(id(3), end)))
        assertEquals(stream, failure(listOf(id(3), key(ByteArray(0)), end)))
        assertEquals(stream, failure(listOf(RawField(1, ByteArray(5)), key(), end)))
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.InnerStream(4)), failure(listOf(id(4), RawField(3, ByteArray(0)), end)))
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.InnerStream(0)), failure(listOf(id(0), key(), end)))
        // An id of 0 is refused only after the key is found missing.
        assertEquals(stream, failure(listOf(id(0), end)))
        // ...and after the whole header was read.
        assertEquals(KdbxResult.Damaged(KdbxDamage.INNER_HEADER), failure(listOf(id(0), key(), RawField(3, ByteArray(0)), end)))
    }

    @Test
    fun `cut fields and lying lengths are damaged and allocate nothing from the length`() {
        val damaged = KdbxResult.Damaged(KdbxDamage.INNER_HEADER)
        assertEquals(damaged, failure(listOf(id(3), key(), RawField(3, ByteArray(0)), end)))
        for (length in listOf(-1, Int.MAX_VALUE, 1000)) {
            val buffers = RecordingBuffers()
            val p = KdbxToolkit.innerBytes(listOf(id(3), key(), RawField(3, ByteArray(4), declaredLength = length), end))
            assertEquals(damaged, assertThrows<KdbxFailure> { InnerHeaderReader.read(p, p.size, outer(), buffers) }.result)
            assertTrue(buffers.byteSizes.all { it <= 64 })
            buffers.assertAllZero()
        }
        val full = payload(listOf(id(3), key(), binary(1, byteArrayOf(1, 2)), end))
        for (cut in 0 until full.size - xml.size) {
            val buffers = RecordingBuffers()
            assertThrows<KdbxFailure> { InnerHeaderReader.read(full, cut, outer(), buffers) }
            buffers.assertAllZero()
        }
    }

    @Test
    fun `attachments are never merged`() {
        val r = read(listOf(id(3), key(), binary(0, byteArrayOf(7)), binary(0, byteArrayOf(7)), end))
        assertEquals(2, r.header.attachments.size)
        assertFalse(r.header.attachments[0].data === r.header.attachments[1].data)
    }
}
