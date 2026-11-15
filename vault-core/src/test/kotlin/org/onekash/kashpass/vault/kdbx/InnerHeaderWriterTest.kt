package org.onekash.kashpass.vault.kdbx

import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawField
import org.onekash.kashpass.vault.testing.RecordingBuffers
import org.onekash.kashpass.vault.testing.le32

class InnerHeaderWriterTest {

    private val key = Random(1).nextBytes(64)

    private val outer = OuterHeader(
        KdbxSignature.NORMAL, 4, 0, OuterCipher.AES_256, Compression.GZIP, ByteArray(32), ByteArray(16),
        KdfParameters.Aes(1UL, ByteArray(32)), null, null, null, 0,
    )

    private val attachments = listOf(
        Attachment(true, byteArrayOf(1, 2, 3)),
        Attachment(false, ByteArray(0)),
        Attachment(false, byteArrayOf(1, 2, 3)),
        Attachment(true, ByteArray(0)),
        Attachment(false, Random(2).nextBytes(70_000)),
    )

    private fun written(key: ByteArray = this.key, attachments: List<Attachment> = this.attachments): ByteArray =
        InnerHeaderWriter.write(key, attachments, Buffers.Default)

    @Test
    fun `fields are stream id 3, the key, one binary per attachment with its flag, then an empty end field`() {
        val expected = listOf(RawField(1, le32(3)), RawField(2, key)) +
            attachments.map { RawField(3, byteArrayOf(if (it.protected) 1 else 0) + it.data) } +
            RawField(0, ByteArray(0))
        assertContentEquals(KdbxToolkit.innerBytes(expected), written())
        assertEquals(KdbxToolkit.innerBytes(expected).size, InnerHeaderWriter.size(key, attachments))
    }

    @Test
    fun `it reads back through InnerHeaderReader to the same stream, key and attachments`() {
        val xml = "<KeePassFile/>".encodeToByteArray()
        val payload = written() + xml
        val read = InnerHeaderReader.read(payload, payload.size, outer)
        assertEquals(InnerStream.CHACHA20, read.header.streamId)
        assertContentEquals(key, read.header.streamKey)
        assertEquals(attachments.map { it.protected }, read.header.attachments.map { it.protected })
        assertEquals(attachments.map { it.data.toList() }, read.header.attachments.map { it.data.toList() })
        assertEquals(payload.size - xml.size, read.xmlOffset)
    }

    @Test
    fun `a KeePass 2 file's inner header is written back byte for byte`() {
        for (name in listOf("keepass2-shared-attachments.kdbx", "keepass2-weak-aeskdf-6000.kdbx", "keepass2-multiblock-attachment.kdbx")) {
            val opened = KdbxToolkit.open(Fixtures.bytes(name), KdbxToolkit.Key(TestFiles.password))
            val stored = KdbxToolkit.innerBytes(opened.layers.inner)
            val read = InnerHeaderReader.read(stored, stored.size, outer)
            assertContentEquals(stored, written(read.header.streamKey, read.header.attachments), name)
        }
    }

    @Test
    fun `attachments are written as given, never XORed or merged`() {
        val same = byteArrayOf(9, 9, 9)
        val bytes = written(attachments = listOf(Attachment(true, same), Attachment(true, same.copyOf())))
        val read = InnerHeaderReader.read(bytes, bytes.size, outer)
        assertEquals(2, read.header.attachments.size)
        read.header.attachments.forEach { assertContentEquals(same, it.data) }
    }

    @Test
    fun `it writes at an offset and refuses an output without room or a key that is not 64 bytes`() {
        val whole = written()
        val out = ByteArray(3 + whole.size + 2)
        assertEquals(3 + whole.size, InnerHeaderWriter.write(key, attachments, out, 3))
        assertContentEquals(whole, out.copyOfRange(3, 3 + whole.size))

        val short = ByteArray(whole.size - 1)
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { InnerHeaderWriter.write(key, attachments, short, 0) }.field)
        assertContentEquals(ByteArray(short.size), short)
        for (size in listOf(0, 32, 63, 65)) {
            assertEquals(KdbxException.Field.KEY, assertThrows<KdbxException.InvalidLength> { InnerHeaderWriter.size(ByteArray(size), attachments) }.field, "key of $size bytes")
        }
    }

    @Test
    fun `the returned array is the only one kept from Buffers, the stream fields are released`() {
        val buffers = RecordingBuffers()
        val bytes = InnerHeaderWriter.write(key, attachments, buffers)
        buffers.assertRecorded(bytes = listOf(bytes.size, 78))
        assertEquals(listOf(78), buffers.releasedSizes)
        buffers.assertAllZeroExcept(bytes)
        bytes.fill(0)
        buffers.assertAllZero()
    }

    @Test
    fun `an OutOfMemoryError from Buffers leaves nothing behind`() {
        val recording = RecordingBuffers()
        val failing = object : Buffers {
            override fun bytes(size: Int): ByteArray = throw OutOfMemoryError("test")
            override fun ints(size: Int) = recording.ints(size)
        }
        assertThrows<OutOfMemoryError> { InnerHeaderWriter.write(key, attachments, failing) }
        recording.assertRecorded(bytes = emptyList())
    }
}
