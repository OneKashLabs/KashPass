package org.onekash.kashpass.vault.kdbx

import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.RecordingBuffers

class BlockStreamWriterTest {

    private val key = KdbxToolkit.Key(TestFiles.password)
    private val mib = 1024 * 1024

    private fun keys(opened: KdbxToolkit.Opened, buffers: Buffers = Buffers.Default) =
        KeySchedule(opened.layers.header.field(RawKdbx.MASTER_SEED), opened.transformedKey, buffers)

    // The stored frames of a block stream: (declared length, data) per block, end block included.
    private fun frames(stream: ByteArray): List<Pair<Int, ByteArray>> {
        val out = ArrayList<Pair<Int, ByteArray>>()
        var p = 0
        while (true) {
            val length = Bytes.readLe32(stream, p + 32)
            out += length to stream.copyOfRange(p + 36, p + 36 + length)
            p += 36 + length
            if (length == 0) break
        }
        assertEquals(stream.size, p, "bytes after the end block")
        return out
    }

    @Test
    fun `the blocks of a KeePass 2 file come out byte for byte as KeePass 2 wrote them`() {
        for (name in listOf("keepass2-weak-aeskdf-6000.kdbx", "keepass2-multiblock-attachment.kdbx")) {
            val bytes = Fixtures.bytes(name)
            val opened = KdbxToolkit.open(bytes, key)
            val start = RawKdbx.parse(bytes).headerBytes().size + 64
            val written = keys(opened).use { BlockStreamWriter.write(opened.ciphertext, 0, opened.ciphertext.size, it) }
            assertContentEquals(bytes.copyOfRange(start, bytes.size), written, name)
        }
        assertEquals(3, KdbxToolkit.open(Fixtures.bytes("keepass2-multiblock-attachment.kdbx"), key).blocks.size)
    }

    @Test
    fun `a full block is written only when more data follows, then the end block`() {
        val opened = KdbxToolkit.open(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"), key)
        val macs = KdbxToolkit.macs(opened.layers)
        val headerPart = Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx").let { it.copyOf(RawKdbx.parse(it).headerBytes().size + 64) }
        val expected = mapOf(0 to 1, mib - 1 to 2, mib to 2, mib + 1 to 3, 3 * mib to 4)
        for ((length, count) in expected) {
            val data = Random(length).nextBytes(length)
            val stream = keys(opened).use { BlockStreamWriter.write(data, 0, length, it) }
            assertEquals(BlockStreamWriter.size(length), stream.size, "size for $length")

            val f = frames(stream)
            assertEquals(count, f.size, "blocks for $length")
            assertEquals(List(count - 1) { i -> minOf(mib, length - i * mib) }, f.dropLast(1).map { it.first }, "data block lengths for $length")
            assertEquals(0, f.last().first, "end block for $length")

            val read = keys(opened).use { BlockStream.read(stream, 0, it) }
            assertEquals(length, read.length)
            assertContentEquals(data, read.ciphertext.copyOf(read.length))
            assertFalse(read.bytesAfterEnd)

            val split = KdbxToolkit.split(headerPart + stream)
            assertEquals(count, split.blocks.size, "toolkit blocks for $length")
            split.blocks.forEachIndexed { i, b ->
                assertContentEquals(macs.block(i.toLong(), b.data), b.hmac, "block $i HMAC for $length")
            }
            assertEquals(0, split.afterEnd.size)
        }
    }

    @Test
    fun `it writes at an offset of a larger array and reads a range of its input`() {
        val opened = KdbxToolkit.open(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"), key)
        val data = Random(7).nextBytes(100)
        val whole = keys(opened).use { BlockStreamWriter.write(data, 10, 80, it) }
        val out = ByteArray(5 + whole.size + 3)
        val end = keys(opened).use { BlockStreamWriter.write(data, 10, 80, it, out, 5) }
        assertEquals(5 + whole.size, end)
        assertContentEquals(whole, out.copyOfRange(5, end))
        val read = keys(opened).use { BlockStream.read(whole, 0, it) }
        assertContentEquals(data.copyOfRange(10, 90), read.ciphertext.copyOf(read.length))
    }

    @Test
    fun `a range outside the input or an output without room is refused before writing`() {
        val opened = KdbxToolkit.open(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"), key)
        keys(opened).use { k ->
            assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { BlockStreamWriter.write(ByteArray(10), 5, 6, k) }.field)
            val out = ByteArray(BlockStreamWriter.size(10) - 1)
            assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { BlockStreamWriter.write(ByteArray(10), 0, 10, k, out, 0) }.field)
            assertContentEquals(ByteArray(out.size), out)
        }
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { BlockStreamWriter.size(Int.MAX_VALUE) }.field)
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { BlockStreamWriter.size(-1) }.field)
    }

    @Test
    fun `block keys are zero-filled and the key schedule's arrays are zero once closed`() {
        val opened = KdbxToolkit.open(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"), key)
        // The key schedule takes its cipher key and HMAC base key first; they stay live until
        // close. Every later array is a block key or HMAC state of one blockMac call.
        val schedule = RecordingBuffers()
        val perBlock = RecordingBuffers()
        var n = 0
        val split = object : Buffers {
            override fun bytes(size: Int) = if (n++ < 2) schedule.bytes(size) else perBlock.bytes(size)
            override fun ints(size: Int) = perBlock.ints(size)
        }
        val k = keys(opened, split)
        BlockStreamWriter.write(Random(8).nextBytes(mib + 1), 0, mib + 1, k)
        schedule.assertRecorded(bytes = listOf(32, 64))
        // Three blocks, each a 64-byte block key and the HMAC's two pads and inner hash.
        perBlock.assertRecorded(bytes = List(3) { listOf(64, 64, 64, 32) }.flatten())
        perBlock.assertAllZero()
        k.close()
        schedule.assertAllZero()
    }
}
