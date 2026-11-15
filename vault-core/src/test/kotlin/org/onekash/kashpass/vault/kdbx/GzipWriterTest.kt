package org.onekash.kashpass.vault.kdbx

import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.GZIPInputStream
import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.kdbx.GzipReader.Ending
import org.onekash.kashpass.vault.testing.Gzip
import org.onekash.kashpass.vault.testing.RecordingBuffers

class GzipWriterTest {

    private val mib = 1024 * 1024

    private val inputs: List<Pair<String, ByteArray>> = listOf(
        "empty" to ByteArray(0),
        "small" to "<KeePassFile><Meta/></KeePassFile>".encodeToByteArray(),
        "1 MiB + 1" to ByteArray(mib + 1) { "<Entry>x</Entry>"[it % 16].code.toByte() },
        "incompressible" to Random(1).nextBytes(300_000),
    )

    private fun GzipWriter.Deflated.member() = bytes.copyOf(size)

    // Raw deflate (RFC 1951) of [content] at the default level, the whole input given at once.
    private fun rawDeflate(content: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, true)
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        try {
            deflater.setInput(content)
            deflater.finish()
            while (!deflater.finished()) out.write(buf, 0, deflater.deflate(buf))
        } finally {
            deflater.end()
        }
        return out.toByteArray()
    }

    @Test
    fun `the member inflates through GzipReader with its trailer checked`() {
        for ((name, content) in inputs) {
            val member = GzipWriter.compress(content, 0, content.size).member()
            val r = GzipReader.inflate(member, 0, member.size, 4 * mib)
            assertEquals(Ending.TRAILER_CHECKED, r.ending, name)
            assertContentEquals(content, r.bytes.copyOf(r.size), name)
        }
    }

    @Test
    fun `the member inflates through the JDK's GZIPInputStream`() {
        for ((name, content) in inputs) {
            val member = GzipWriter.compress(content, 0, content.size).member()
            assertContentEquals(content, GZIPInputStream(member.inputStream()).use { it.readBytes() }, name)
        }
    }

    @Test
    fun `one member with KeePass 2's header, default-level raw deflate, CRC-32 and ISIZE`() {
        for ((name, content) in inputs) {
            val member = GzipWriter.compress(content, 0, content.size).member()
            assertContentEquals(Gzip.HEADER, member.copyOf(10), name)
            val crc = CRC32().apply { update(content) }.value.toInt()
            assertEquals(crc, Bytes.readLe32(member, member.size - 8), name)
            assertEquals(content.size, Bytes.readLe32(member, member.size - 4), name)
            assertContentEquals(rawDeflate(content), member.copyOfRange(10, member.size - 8), name)
        }
    }

    @Test
    fun `it compresses a range of its input and leaves the spare room asked for`() {
        val data = Random(2).nextBytes(500)
        for (spare in listOf(0, 1, 16)) {
            val d = GzipWriter.compress(data, 100, 300, spare)
            assertTrue(d.bytes.size - d.size >= spare, "spare $spare")
            assertContentEquals(data.copyOfRange(100, 400), GZIPInputStream(d.member().inputStream()).use { it.readBytes() })
        }
        // Incompressible input fills the buffer up to the bound computed for it.
        val big = Random(3).nextBytes(200_000)
        val d = GzipWriter.compress(big, 0, big.size, 16)
        assertTrue(d.bytes.size - d.size >= 16)
    }

    @Test
    fun `a range outside the input or a negative spare is refused`() {
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { GzipWriter.compress(ByteArray(10), 5, 6) }.field)
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { GzipWriter.compress(ByteArray(10), -1, 2) }.field)
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { GzipWriter.compress(ByteArray(10), 0, 10, -1) }.field)
    }

    @Test
    fun `replaced buffers are zero-filled and only the result stays live`() {
        for ((name, content) in inputs) {
            val buffers = RecordingBuffers()
            val d = GzipWriter.compress(content, 0, content.size, 16, buffers)
            assertTrue(buffers.byteSizes.isNotEmpty(), name)
            buffers.assertAllZeroExcept(d.bytes)
            d.bytes.fill(0)
            buffers.assertAllZero()
        }
        // Incompressible input grows the buffer from a quarter of zlib's bound; each buffer it
        // outgrows is released.
        val grown = RecordingBuffers()
        val input = inputs[3].second
        GzipWriter.compress(input, 0, input.size, 0, grown).bytes.fill(0)
        val bound = input.size + (input.size shr 12) + (input.size shr 14) + 7 + 18
        assertEquals(bound / 4, grown.byteSizes.first())
        assertTrue(grown.byteSizes.size > 1)
        assertEquals(grown.byteSizes.dropLast(1), grown.releasedSizes)
        grown.assertAllZero()
        // A small input starts at 64 KiB, or at its bound when that is smaller.
        val small = RecordingBuffers()
        GzipWriter.compress(inputs[1].second, 0, inputs[1].second.size, 0, small).bytes.fill(0)
        assertEquals(listOf(inputs[1].second.size + 7 + 18), small.byteSizes)
    }

    @Test
    fun `an OutOfMemoryError at any allocation leaves no compressed data behind`() {
        val content = inputs[3].second
        val total = RecordingBuffers().also { GzipWriter.compress(content, 0, content.size, 16, it).bytes.fill(0) }.byteSizes.size
        assertTrue(total > 1)
        for (failAt in 0 until total) {
            val recording = RecordingBuffers()
            var n = 0
            val failing = object : Buffers {
                override fun bytes(size: Int): ByteArray {
                    if (n++ == failAt) throw OutOfMemoryError("test")
                    return recording.bytes(size)
                }
                override fun ints(size: Int) = recording.ints(size)
            }
            assertThrows<OutOfMemoryError>("allocation $failAt") { GzipWriter.compress(content, 0, content.size, 16, failing) }
            assertEquals(failAt, recording.byteSizes.size, "allocation $failAt")
            recording.assertAllZero()
        }
    }
}
