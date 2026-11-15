package org.onekash.kashpass.vault.kdbx

import java.nio.ByteBuffer

/**
 * The KDBX VariantDictionary format: a 2-byte version, then entries of a type byte, a name and a
 * value, each with a 4-byte little-endian length, ended by an [END] type byte.
 */
internal object VariantDictionary {

    /** Value type bytes; [END] ends the entries. */
    const val END = 0x00
    const val UINT32 = 0x04
    const val UINT64 = 0x05
    const val BOOL = 0x08
    const val INT32 = 0x0C
    const val INT64 = 0x0D
    const val STRING = 0x18
    const val BYTE_ARRAY = 0x42

    /** The version written: major 1, minor 0. */
    const val VERSION = 0x0100

    private const val MAJOR_MASK = 0xFF00

    private val FIXED_SIZE = mapOf(UINT32 to 4, UINT64 to 8, BOOL to 1, INT32 to 4, INT64 to 8)
    private val VARIABLE = setOf(STRING, BYTE_ARRAY)

    /** One value: its [type] byte and its bytes. */
    class Entry(val type: Int, val value: ByteArray)

    /**
     * Entries by name: the last entry for a name wins, whatever its type. Names are compared as
     * bytes, which for the names KDBX defines gives the same answer as comparing them after a
     * lenient UTF-8 decoding. [heapBytes] is the heap [read] charged for
     * them ([ENTRY_HEAP_BYTES] per entry read plus its name and value bytes); 0 for entries built
     * otherwise.
     */
    class Entries internal constructor(private val byName: LinkedHashMap<ByteBuffer, Entry>, val heapBytes: Long = 0) {
        /** Returns the entry named [name], or null. */
        operator fun get(name: String): Entry? = byName[key(name)]

        /** Returns the value of [name] when it is a byte array, else null. */
        fun bytes(name: String): ByteArray? = get(name)?.takeIf { it.type == BYTE_ARRAY }?.value

        /** Returns every entry with its name bytes, in the order the names first appeared. */
        fun all(): List<Pair<ByteArray, Entry>> = byName.map { (name, entry) -> name.array().copyOf() to entry }

        /** Sets [name] to [entry], replacing any entry of that name. */
        fun set(name: String, entry: Entry) {
            byName[key(name)] = entry
        }

        private fun key(name: String) = ByteBuffer.wrap(name.encodeToByteArray())

        companion object {
            /** Returns a set with no entries. */
            fun empty() = Entries(LinkedHashMap())
        }
    }

    /**
     * The heap one entry costs beyond its name and value bytes, as [read] charges it: the largest
     * measured cost of a whole entry, 203 bytes for a 16-byte name and an 8-byte value (186 for a
     * 3-byte name and an empty value) on a 64-bit JVM with compressed references, times a margin
     * of 1.5. The cost is the two arrays, the [Entry], the ByteBuffer key and the map node, which
     * turn into tree nodes when many short names share a hash. [FixedHeapLimitTest] measures it.
     */
    const val ENTRY_HEAP_BYTES = 305L

    /**
     * Reads [bytes]: any minor version and majors 0 and 1 are read; an entry with an empty name is
     * read and dropped; bytes after the [END] byte are ignored. Throws [KdbxFailure] with
     * [KdbxUnsupported.DictionaryVersion] for a major above 1 and
     * [KdbxUnsupported.DictionaryValueType] for an unknown type (both mean a newer format), and
     * with Damaged([damage]) for a negative or overlong length, a fixed-size
     * value of the wrong size, or input that ends before [END]. Nothing is allocated from a length
     * before it is checked against the bytes left.
     *
     * Each entry is charged [ENTRY_HEAP_BYTES] plus its name and value bytes before its arrays are
     * allocated, dropped entries included; when the charges pass [budgetBytes] this throws
     * [KdbxFailure] with NotEnoughMemory([MemoryCause.LIMIT]). The format allows any number of
     * entries, so the limit is the heap's, never a format rule.
     */
    fun read(bytes: ByteArray, damage: KdbxDamage, budgetBytes: Long): Entries {
        if (bytes.size < 2) damaged(damage)
        val version = Bytes.readLe16(bytes, 0)
        if (version and MAJOR_MASK > VERSION and MAJOR_MASK) {
            throw KdbxFailure(KdbxResult.Unsupported(KdbxUnsupported.DictionaryVersion(version ushr 8)))
        }
        val entries = LinkedHashMap<ByteBuffer, Entry>()
        var charged = 0L
        var p = 2
        fun charge(bytes: Long) {
            charged += bytes
            if (charged > budgetBytes) throw KdbxFailure(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT))
        }
        fun field(): ByteArray {
            if (bytes.size - p < 4) damaged(damage)
            val length = Bytes.readLe32(bytes, p)
            p += 4
            if (length < 0 || length > bytes.size - p) damaged(damage)
            charge(length.toLong())
            return bytes.copyOfRange(p, p + length).also { p += length }
        }
        while (true) {
            if (p >= bytes.size) damaged(damage)
            val type = bytes[p++].toInt() and 0xFF
            if (type == END) break
            charge(ENTRY_HEAP_BYTES)
            val name = field()
            val value = field()
            val size = FIXED_SIZE[type]
            when {
                size != null -> if (value.size != size) damaged(damage)
                type !in VARIABLE -> throw KdbxFailure(KdbxResult.Unsupported(KdbxUnsupported.DictionaryValueType(type)))
            }
            if (name.isNotEmpty()) entries[ByteBuffer.wrap(name)] = Entry(type, value)
        }
        return Entries(entries, charged)
    }
}
