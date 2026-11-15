package org.onekash.kashpass.vault.kdbx

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawEntry
import org.onekash.kashpass.vault.testing.le32
import org.onekash.kashpass.vault.testing.le64

class VariantDictionaryTest {

    private val base = RawDictionary(0x0100, listOf(RawEntry(RawDictionary.UINT64, "R", le64(7)), RawEntry(RawDictionary.BYTES, "S", ByteArray(32) { 1 })))

    private fun read(d: RawDictionary, budget: Long = Long.MAX_VALUE) = VariantDictionary.read(d.toBytes(), KdbxDamage.KDF_PARAMETERS, budget)

    private fun failure(d: RawDictionary): KdbxResult = assertThrows<KdbxFailure> { read(d) }.result

    @Test
    fun `each entry is charged its fixed cost and its bytes, and past the budget the read is NotEnoughMemory`() {
        // R: 1-byte name, 8-byte value; S: 1-byte name, 32-byte value.
        val cost = 2 * VariantDictionary.ENTRY_HEAP_BYTES + 1 + 8 + 1 + 32
        assertEquals(cost, read(base, budget = cost).heapBytes)
        val memory = KdbxResult.NotEnoughMemory(MemoryCause.LIMIT)
        assertEquals(memory, assertThrows<KdbxFailure> { read(base, budget = cost - 1) }.result)
        // A dropped entry with an empty name is charged too.
        val dropped = base.plus(RawEntry(RawDictionary.BYTES, "", ByteArray(0)))
        assertEquals(memory, assertThrows<KdbxFailure> { read(dropped, budget = cost) }.result)
        assertEquals(cost + VariantDictionary.ENTRY_HEAP_BYTES, read(dropped, budget = cost + VariantDictionary.ENTRY_HEAP_BYTES).heapBytes)
    }

    @Test
    fun `the budget is checked before an entry's arrays are allocated`() {
        // One entry whose value is 1 MiB: refused on its declared length with a 1 KiB budget.
        val big = RawDictionary(0x0100, listOf(RawEntry(RawDictionary.BYTES, "X", ByteArray(1 shl 20))))
        assertEquals(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT), assertThrows<KdbxFailure> { read(big, budget = 1024) }.result)
    }

    @Test
    fun `entries are read by name and type`() {
        val e = read(base)
        assertEquals(VariantDictionary.UINT64, e["R"]?.type)
        assertContentEquals(le64(7), e["R"]?.value)
        assertContentEquals(ByteArray(32) { 1 }, e.bytes("S"))
        assertNull(e.bytes("R"))
        assertNull(e["X"])
    }

    @Test
    fun `majors 0 and 1 with any minor are read, a major above 1 is unsupported`() {
        for (version in listOf(0x0000, 0x00FF, 0x0100, 0x01FF)) read(base.copy(version = version))
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.DictionaryVersion(2)), failure(base.copy(version = 0x0200)))
    }

    @Test
    fun `an unknown type is unsupported, a wrong fixed size is damaged`() {
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.DictionaryValueType(0x7F)), failure(base.plus(RawEntry(0x7F, "X", ByteArray(4)))))
        val damaged = KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS)
        assertEquals(damaged, failure(base.plus(RawEntry(RawDictionary.UINT32, "X", ByteArray(5)))))
        assertEquals(damaged, failure(base.plus(RawEntry(RawDictionary.BOOL, "X", ByteArray(2)))))
        assertEquals(damaged, failure(base.plus(RawEntry(RawDictionary.UINT64, "X", ByteArray(4)))))
    }

    @Test
    fun `the last entry for a name wins whatever its type, and an empty name is dropped`() {
        val e = read(base.plus(RawEntry(RawDictionary.UINT32, "R", le32(5))).plus(RawEntry(RawDictionary.BYTES, "", ByteArray(3))))
        assertEquals(VariantDictionary.UINT32, e["R"]?.type)
        assertNull(e[""])
    }

    @Test
    fun `bytes after the terminator are ignored, a missing terminator or a cut entry is damaged`() {
        read(base.copy(trailing = byteArrayOf(1, 2, 3)))
        val damaged = KdbxResult.Damaged(KdbxDamage.HEADER_FIELD)
        assertEquals(damaged, assertThrows<KdbxFailure> { VariantDictionary.read(base.copy(terminated = false).toBytes(), KdbxDamage.HEADER_FIELD, Long.MAX_VALUE) }.result)
        val bytes = base.toBytes()
        for (cut in 0 until bytes.size - 1) {
            assertEquals(damaged, assertThrows<KdbxFailure> { VariantDictionary.read(bytes.copyOf(cut), KdbxDamage.HEADER_FIELD, Long.MAX_VALUE) }.result, "cut at $cut")
        }
    }

    @Test
    fun `a negative or overlong length is damaged`() {
        val damaged = KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS)
        assertEquals(damaged, failure(base.plus(RawEntry(RawDictionary.BYTES, "X", ByteArray(4), declaredLength = -1))))
        assertEquals(damaged, failure(base.plus(RawEntry(RawDictionary.BYTES, "X", ByteArray(4), declaredLength = Int.MAX_VALUE))))
        assertEquals(damaged, failure(base.plus(RawEntry(RawDictionary.BYTES, "X", ByteArray(4), declaredNameLength = -5))))
        assertEquals(damaged, failure(base.plus(RawEntry(RawDictionary.BYTES, "X", ByteArray(4), declaredNameLength = Int.MAX_VALUE))))
    }
}
