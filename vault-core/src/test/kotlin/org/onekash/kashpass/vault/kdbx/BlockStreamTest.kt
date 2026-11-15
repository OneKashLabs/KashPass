package org.onekash.kashpass.vault.kdbx

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.KdbxToolkit.editBlock
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.RecordingBuffers
import org.onekash.kashpass.vault.testing.le32

class BlockStreamTest {

    private val key = KdbxToolkit.Key(TestFiles.password)
    private val weak = KdbxToolkit.open(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"), key)

    private class Read(val blocks: BlockStream.Blocks?, val failure: KdbxResult?, val buffers: RecordingBuffers)

    private fun read(bytes: ByteArray, transformed: ByteArray = weak.transformedKey): Read {
        val header = RawKdbx.parse(bytes)
        val buffers = RecordingBuffers()
        KeySchedule(header.field(RawKdbx.MASTER_SEED), transformed).use { keys ->
            return try {
                Read(BlockStream.read(bytes, header.headerBytes().size + 64, keys, buffers), null, buffers)
            } catch (e: KdbxFailure) {
                Read(null, e.result, buffers)
            }
        }
    }

    private fun blocks(bytes: ByteArray) = read(bytes).blocks ?: error("refused: ${read(bytes).failure}")

    private fun failure(bytes: ByteArray) = read(bytes).failure

    private fun build(edit: (KdbxToolkit.Layers) -> KdbxToolkit.Layers) = KdbxToolkit.build(edit(weak.layers))

    @Test
    fun `the blocks of a fixture join into its ciphertext`() {
        val bytes = Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx")
        val b = blocks(bytes)
        assertContentEquals(weak.ciphertext, b.ciphertext.copyOf(b.length))
        assertFalse(b.bytesAfterEnd)
    }

    @Test
    fun `blocks of any size, a 1 MiB boundary included, join in order`() {
        for (size in listOf(37, 1024 * 1024, 1024 * 1024 + 1)) {
            val bytes = build { it.copy(blockSize = size, ciphertext = ByteArray(3 * 1024 * 1024 + 16) { i -> i.toByte() }) }
            val b = blocks(bytes)
            assertEquals(3 * 1024 * 1024 + 16, b.length, "block size $size")
            assertContentEquals(ByteArray(3 * 1024 * 1024 + 16) { i -> i.toByte() }, b.ciphertext.copyOf(b.length), "block size $size")
        }
    }

    @Test
    fun `bytes after the end block are not read and are reported`() {
        val b = blocks(build { it.copy(afterEnd = byteArrayOf(1, 2, 3)) })
        assertTrue(b.bytesAfterEnd)
        assertContentEquals(weak.ciphertext, b.ciphertext.copyOf(b.length))
    }

    @Test
    fun `a changed, moved, repeated or dropped block fails its HMAC`() {
        val hmac = KdbxResult.Damaged(KdbxDamage.BLOCK_HMAC)
        assertEquals(hmac, failure(build { it.editBlock(0) { b -> KdbxToolkit.Block(b.hmac, b.declaredLength, b.data.copyOf().also { d -> d[0] = (d[0] + 1).toByte() }) } }))
        assertEquals(hmac, failure(build { it.editBlock(0) { b -> KdbxToolkit.Block(b.hmac.copyOf().also { h -> h[0] = (h[0] + 1).toByte() }, b.declaredLength, b.data) } }))
        val multi = { edit: (List<KdbxToolkit.Block>) -> List<KdbxToolkit.Block> ->
            build { it.copy(blockSize = 64, editBlocks = { _, b -> edit(b) }) }
        }
        assertEquals(hmac, failure(multi { b -> listOf(b[1], b[0]) + b.drop(2) }))
        assertEquals(hmac, failure(multi { b -> listOf(b[0], b[0]) + b.drop(1) }))
        assertEquals(hmac, failure(multi { b -> b.drop(1) }))
        assertEquals(hmac, failure(build { it.copy(editBlocks = { _, b -> b.dropLast(1) + KdbxToolkit.Block(ByteArray(32), 0, ByteArray(0)) }) }))
    }

    @Test
    fun `a wrong transformed key fails the first block`() {
        assertEquals(KdbxResult.Damaged(KdbxDamage.BLOCK_HMAC), read(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"), transformed = ByteArray(32)).failure)
    }

    @Test
    fun `a missing end block or a cut frame is damaged, a lying length allocates nothing`() {
        val bytes = Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx")
        assertEquals(KdbxResult.Damaged(KdbxDamage.END_BLOCK_MISSING), failure(build { it.copy(editBlocks = { _, b -> b.dropLast(1) }) }))
        assertEquals(KdbxResult.Damaged(KdbxDamage.END_BLOCK_MISSING), failure(bytes.copyOf(bytes.size - 1)))
        val start = RawKdbx.parse(bytes).headerBytes().size + 64
        for (length in listOf(-1, Int.MIN_VALUE, Int.MAX_VALUE, bytes.size)) {
            val lying = bytes.copyOf().also { le32(length).copyInto(it, start + 32) }
            val r = read(lying)
            assertEquals(KdbxResult.Damaged(KdbxDamage.BLOCK_LENGTH), r.failure, "length $length")
            assertEquals(emptyList(), r.buffers.byteSizes.filter { it > 64 }, "length $length")
        }
    }

    @Test
    fun `the ciphertext buffer is the only array the reader allocates`() {
        val r = read(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"))
        assertEquals(weak.ciphertext.size, r.blocks!!.length)
        assertTrue(r.buffers.byteSizes.contains(weak.ciphertext.size))
        r.blocks.ciphertext.fill(0)
        r.buffers.assertAllZero()
    }
}
