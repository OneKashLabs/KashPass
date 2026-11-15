package org.onekash.kashpass.vault.storage

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.VaultXmlCodec

class VaultSizeLimitTest {

    private val mib = 1024L * 1024

    @Test
    fun `the read limit is the heap divided by 8_6, with no fixed cap`() {
        assertEquals(256 * mib * 5 / 43, maxVaultBytes(256 * mib).toLong())
        assertEquals(31_213_425L, maxVaultBytes(256 * mib).toLong())
        assertEquals(62_426_850L, maxVaultBytes(512 * mib).toLong())
        assertEquals(124_853_700L, maxVaultBytes(1024 * mib).toLong())
        assertTrue(maxVaultBytes(1024 * mib) > 64 * mib, "no fixed 64 MiB cap")
        assertEquals(Int.MAX_VALUE - 8, maxVaultBytes(Long.MAX_VALUE))
        assertEquals(0, maxVaultBytes(0))
    }

    @Test
    fun `the content limits at 256 MiB, 512 MiB and 1 GiB`() {
        // open, save, decompression, payloadSave, read limit; in bytes.
        val expected = mapOf(
            256L to listOf(7_456_540L, 3_195_660L, 44_739_242L, 29_826_161L, 31_213_425L),
            512L to listOf(14_913_080L, 6_391_320L, 89_478_485L, 59_652_323L, 62_426_850L),
            1024L to listOf(29_826_161L, 12_782_640L, 178_956_970L, 119_304_647L, 124_853_700L),
        )
        for ((heapMib, values) in expected) {
            val heap = heapMib * mib
            val l = VaultXmlCodec.Limits.forHeap(heap)
            assertEquals(values, listOf(l.open.toLong(), l.save, l.decompression.toLong(), l.payloadSave, maxVaultBytes(heap).toLong()), "$heapMib MiB")
        }
    }

    @Test
    fun `no save cap exceeds the read-back's matching limit, so the read-back admits every save the caps admit`() {
        // The file-size cap of a save is maxVaultBytes itself, the read limit of its re-read.
        val heaps = listOf(16L, 64L, 256L, 384L, 512L, 1024L, 4096L).map { it * mib } + Long.MAX_VALUE
        for (heap in heaps) {
            val limits = VaultXmlCodec.Limits.forHeap(heap)
            assertTrue(limits.save <= limits.open, "XML on a heap of $heap: $limits")
            assertTrue(limits.payloadSave <= limits.decompression, "payload on a heap of $heap: $limits")
            assertTrue(limits.open <= limits.decompression, "the XML is part of the payload: $limits")
        }
    }
}
