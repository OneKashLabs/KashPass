package org.onekash.kashpass.vault.kdbx

import java.io.ByteArrayOutputStream
import java.util.zip.CRC32
import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.kdbx.GzipReader.Ending
import org.onekash.kashpass.vault.testing.Gzip
import org.onekash.kashpass.vault.testing.RecordingBuffers
import org.onekash.kashpass.vault.testing.le32

class GzipReaderTest {

    private val content = ("<KeePassFile>" + "x".repeat(5000) + "</KeePassFile>").encodeToByteArray() + Random(1).nextBytes(3000)
    private val member = Gzip.compress(content)

    private fun inflate(data: ByteArray, limit: Int = 1 shl 20) = GzipReader.inflate(data, 0, data.size, limit)

    private fun GzipReader.Inflated.content() = bytes.copyOf(size)

    private fun fault(data: ByteArray) = assertThrows<KdbxException.CompressedData> { inflate(data) }.fault

    private fun le16(v: Int) = byteArrayOf(v.toByte(), (v shr 8).toByte())

    // A gzip member without its 10-byte header and 8-byte trailer is raw deflate data.
    private fun deflateRaw(data: ByteArray): ByteArray = Gzip.compress(data).let { it.copyOfRange(10, it.size - 8) }

    private fun zlib(data: ByteArray, header: ByteArray = byteArrayOf(0x78, 0x9C.toByte())): ByteArray {
        val adler = java.util.zip.Adler32().apply { update(data) }.value.toInt()
        return header + deflateRaw(data) + byteArrayOf((adler ushr 24).toByte(), (adler ushr 16).toByte(), (adler ushr 8).toByte(), adler.toByte())
    }

    // A gzip member with [flags] and the given optional header fields.
    private fun member(flags: Int, extra: ByteArray? = null, name: String? = null, comment: String? = null, hcrc: Int? = null, os: Int = 0): ByteArray {
        val header = ByteArrayOutputStream()
        header.write(byteArrayOf(0x1F, 0x8B.toByte(), 8, flags.toByte(), 0, 0, 0, 0, 4, os.toByte()))
        extra?.let { header.write(le16(it.size)); header.write(it) }
        name?.let { header.write(it.encodeToByteArray()); header.write(0) }
        comment?.let { header.write(it.encodeToByteArray()); header.write(0) }
        val h = header.toByteArray()
        val crc16 = hcrc ?: (CRC32().apply { update(h) }.value.toInt() and 0xFFFF)
        val withCrc = if (flags and 0x02 != 0) h + le16(crc16) else h
        return withCrc + member.copyOfRange(10, member.size)
    }

    @Test
    fun `a member with a valid trailer inflates and checks it`() {
        val r = inflate(member)
        assertContentEquals(content, r.content())
        assertEquals(Ending.TRAILER_CHECKED, r.ending)
    }

    @Test
    fun `only the first member is read`() {
        for (after in listOf(Gzip.compress(ByteArray(100) { 'y'.code.toByte() }), Gzip.compress(ByteArray(0)), Random(2).nextBytes(16), byteArrayOf(0x1F))) {
            val r = inflate(member + after)
            assertContentEquals(content, r.content())
            assertEquals(Ending.TRAILER_CHECKED, r.ending)
        }
    }

    @Test
    fun `a missing or cut trailer is accepted and not checked`() {
        for (cut in 1..8) {
            val r = inflate(member.copyOf(member.size - cut))
            assertContentEquals(content, r.content(), "cut $cut")
            assertEquals(Ending.TRAILER_INCOMPLETE, r.ending, "cut $cut")
        }
    }

    @Test
    fun `a wrong CRC or ISIZE is refused once its 4 bytes are present`() {
        val badCrc = member.copyOf().also { it[it.size - 8] = (it[it.size - 8] + 1).toByte() }
        val badSize = member.copyOf().also { it[it.size - 4] = (it[it.size - 4] + 1).toByte() }
        assertEquals(KdbxException.Fault.CRC, fault(badCrc))
        assertEquals(KdbxException.Fault.ISIZE, fault(badSize))
        assertEquals(KdbxException.Fault.CRC, fault(badCrc.copyOf(badCrc.size - 4)))
        assertEquals(Ending.TRAILER_INCOMPLETE, inflate(badCrc.copyOf(badCrc.size - 5)).ending)
    }

    @Test
    fun `input that ends inside the header or the deflate data returns what inflated`() {
        for (cut in listOf(0, 1, 3, 9)) assertEquals(Ending.INPUT_ENDED, inflate(member.copyOf(cut)).ending, "cut at $cut")
        val half = inflate(member.copyOf(member.size / 2))
        assertEquals(Ending.INPUT_ENDED, half.ending)
        assertContentEquals(content.copyOf(half.size), half.content())
        assertEquals(true, half.size < content.size)
    }

    @Test
    fun `a stream cut after the last content byte returns the whole content`() {
        // Deflate data built by hand so the result does not depend on the zlib build: a stored
        // block (BFINAL 0, BTYPE 00) holding the content, then an empty final stored block.
        val data = "<KeePassFile></KeePassFile>".encodeToByteArray()
        val stored = byteArrayOf(0) + le16(data.size) + le16(data.size.inv() and 0xFFFF) + data
        val final = byteArrayOf(1, 0, 0, -1, -1)
        val crc = CRC32().apply { update(data) }.value.toInt()
        val trailer = le32(crc) + le32(data.size)
        val whole = Gzip.HEADER + stored + final + trailer
        assertEquals(Ending.TRAILER_CHECKED, inflate(whole).ending)
        // Cut inside the final block: the content is complete, the stream has not ended.
        val cut = inflate(Gzip.HEADER + stored + final.copyOf(3))
        assertEquals(Ending.INPUT_ENDED, cut.ending)
        assertContentEquals(data, cut.content())
        // Cut inside the stored bytes: what arrived is returned.
        val short = inflate(Gzip.HEADER + stored.copyOf(stored.size - 5))
        assertEquals(Ending.INPUT_ENDED, short.ending)
        assertContentEquals(data.copyOf(data.size - 5), short.content())
    }

    @Test
    fun `corrupt deflate data is refused`() {
        val bad = Gzip.HEADER + byteArrayOf(0x07, 0, 0, 0, 0)
        assertEquals(KdbxException.Fault.DEFLATE_DATA, fault(bad))
    }

    @Test
    fun `gzip header fields are read as zlib reads them`() {
        val extra = Random(3).nextBytes(7)
        for (flags in 0..0x1F) {
            val m = member(flags, if (flags and 0x04 != 0) extra else null, if (flags and 0x08 != 0) "vault.xml" else null, if (flags and 0x10 != 0) "comment" else null)
            val r = inflate(m)
            assertContentEquals(content, r.content(), "flags $flags")
            assertEquals(Ending.TRAILER_CHECKED, r.ending, "flags $flags")
        }
        // The header a Windows KDBX writer emits (XFL 4, OS 0) and the one zlib writes (OS 3).
        assertContentEquals(content, inflate(member(0, os = 3)).content())
        assertEquals(KdbxException.Fault.HEADER_CRC, fault(member(0x02, hcrc = 0x1234)))
        for (bit in listOf(0x20, 0x40, 0x80)) assertEquals(KdbxException.Fault.GZIP_FLAGS, fault(member(bit)))
        assertEquals(KdbxException.Fault.GZIP_METHOD, fault(member.copyOf().also { it[2] = 7 }))
        // A header that ends inside FNAME or FEXTRA waits for more input.
        assertEquals(Ending.INPUT_ENDED, inflate(member(0x08, name = "vault.xml").copyOf(14)).ending)
        assertEquals(Ending.INPUT_ENDED, inflate(member(0x04, extra = extra).copyOf(13)).ending)
    }

    @Test
    fun `a zlib stream behind the gzip flag inflates and checks its Adler-32`() {
        for (header in listOf(byteArrayOf(0x78, 0x9C.toByte()), byteArrayOf(0x78, 0x01), byteArrayOf(0x78, 0xDA.toByte()))) {
            val r = inflate(zlib(content, header))
            assertContentEquals(content, r.content())
            assertEquals(Ending.TRAILER_CHECKED, r.ending)
        }
        val z = zlib(content)
        assertEquals(Ending.TRAILER_INCOMPLETE, inflate(z.copyOf(z.size - 2)).ending)
        assertEquals(KdbxException.Fault.ADLER, fault(z.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }))
        assertContentEquals(content, inflate(z + byteArrayOf(1, 2, 3)).content())
    }

    @Test
    fun `invalid zlib headers are refused`() {
        assertEquals(KdbxException.Fault.ZLIB_HEADER, fault(byteArrayOf(0x78, 0x9D.toByte(), 0, 0)))
        // The payload of a gzip-flagged file holding plain content starts with inner header id 1.
        assertEquals(KdbxException.Fault.ZLIB_HEADER, fault(byteArrayOf(0x01, 0x04, 0, 0, 0)))
        assertEquals(KdbxException.Fault.ZLIB_METHOD, fault(byteArrayOf(0x77, 0x85.toByte())))
        assertEquals(KdbxException.Fault.ZLIB_WINDOW, fault(byteArrayOf(0x88.toByte(), 0x98.toByte())))
        assertEquals(KdbxException.Fault.ZLIB_DICTIONARY, fault(byteArrayOf(0x78, 0xBB.toByte(), 1, 2, 3, 4)))
        assertEquals(Ending.INPUT_ENDED, inflate(byteArrayOf(0x78, 0xBB.toByte(), 1, 2)).ending)
    }

    @Test
    fun `the size limit is exact`() {
        val n = content.size
        assertContentEquals(content, inflate(member, limit = n).content())
        assertContentEquals(content, inflate(member, limit = n + 1).content())
        assertEquals(n - 1, assertThrows<KdbxException.InflatedTooLarge> { inflate(member, limit = n - 1) }.limit)
        assertEquals(KdbxException.Field.LIMIT, assertThrows<KdbxException.InvalidLength> { inflate(member, limit = 0) }.field)
        // A limit below the first buffer size, and growth past it.
        val large = Random(4).nextBytes(300_000)
        assertContentEquals(large, inflate(Gzip.compress(large), limit = 300_000).content())
        assertThrows<KdbxException.InflatedTooLarge> { inflate(Gzip.compress(large), limit = 299_999) }
    }

    @Test
    fun `a range outside the array is refused`() {
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { GzipReader.inflate(member, 5, member.size, 100) }.field)
    }

    @Test
    fun `replaced and failed buffers are zero-filled and released, and only the result stays live`() {
        val large = Random(5).nextBytes(300_000)
        // A zlib stream states no size: 64 KiB, grown to 128 KiB, 256 KiB and 512 KiB.
        val grown = RecordingBuffers()
        val z = zlib(large)
        val r = GzipReader.inflate(z, 0, z.size, 1 shl 20, grown)
        grown.assertRecorded(bytes = listOf(65536, 131072, 262144, 524288))
        assertEquals(listOf(65536, 131072, 262144), grown.releasedSizes)
        r.bytes.fill(0)
        grown.assertAllZero()

        val failed = RecordingBuffers()
        assertThrows<KdbxException.InflatedTooLarge> { GzipReader.inflate(Gzip.compress(large), 0, Gzip.compress(large).size, 100_000, failed) }
        failed.assertRecorded(bytes = listOf(100_000, 1))
        failed.assertAllZero()

        val crc = RecordingBuffers()
        val bad = member.copyOf().also { it[it.size - 8] = (it[it.size - 8] + 1).toByte() }
        assertThrows<KdbxException.CompressedData> { GzipReader.inflate(bad, 0, bad.size, 1 shl 20, crc) }
        crc.assertRecorded(bytes = listOf(content.size + 1))
        crc.assertAllZero()
    }

    @Test
    fun `a gzip member's ISIZE sizes the output once, within the limit and deflate's ratio`() {
        val large = Random(5).nextBytes(300_000)
        val exact = RecordingBuffers()
        val data = Gzip.compress(large)
        val r = GzipReader.inflate(data, 0, data.size, 1 shl 20, exact)
        assertContentEquals(large, r.bytes.copyOf(r.size))
        // One byte past ISIZE lets the inflater report the end without growing.
        exact.assertRecorded(bytes = listOf(300_001))
        r.bytes.fill(0)

        // An ISIZE that understates the content grows the buffer as a zlib stream does.
        val under = data.copyOf().also { le32(1000).copyInto(it, it.size - 4) }
        val small = RecordingBuffers()
        assertThrows<KdbxException.CompressedData> { GzipReader.inflate(under, 0, under.size, 1 shl 20, small) }
        assertEquals(1001, small.byteSizes.first())
        small.assertAllZero()

        // An ISIZE beyond 1032 times the input, deflate's largest ratio, is not believed.
        val tiny = Gzip.compress(ByteArray(10)).also { le32(1 shl 30).copyInto(it, it.size - 4) }
        val capped = RecordingBuffers()
        assertThrows<KdbxException.CompressedData> { GzipReader.inflate(tiny, 0, tiny.size, 1 shl 20, capped) }
        assertEquals(tiny.size * 1032 + 1, capped.byteSizes.first())
        capped.assertAllZero()
    }

    @Test
    fun `an OutOfMemoryError while the buffer grows leaves no plaintext behind`() {
        val large = Random(6).nextBytes(300_000)
        // A zlib stream states no size, so its buffer grows.
        val data = zlib(large)
        val recording = RecordingBuffers()
        var calls = 0
        val failing = object : Buffers {
            override fun bytes(size: Int): ByteArray {
                if (++calls == 2) throw OutOfMemoryError("test")
                return recording.bytes(size)
            }
            override fun ints(size: Int) = recording.ints(size)
        }
        assertThrows<OutOfMemoryError> { GzipReader.inflate(data, 0, data.size, 1 shl 20, failing) }
        recording.assertRecorded(bytes = listOf(65536))
        recording.assertAllZero()
    }
}
