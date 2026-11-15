package org.onekash.kashpass.vault.kdbx

/**
 * Writes a KDBX VariantDictionary (the KDF parameters and public custom data of the outer
 * header): version 0x0100, then each entry as a type byte, the name length (4 bytes
 * little-endian), the UTF-8 name, the value length (4 bytes little-endian) and the value, in the
 * order given, then a 0x00 terminator. The caller passes the entries in the dictionary's
 * insertion order. An entry with an empty name is skipped.
 */
internal object VariantDictionaryWriter {

    /** A typed dictionary value; [type] is its VariantDictionary type byte. */
    sealed class Value(val type: Int) {
        class UInt32(val value: UInt) : Value(VariantDictionary.UINT32)
        class UInt64(val value: ULong) : Value(VariantDictionary.UINT64)
        class Bool(val value: Boolean) : Value(VariantDictionary.BOOL)
        class Int32(val value: Int) : Value(VariantDictionary.INT32)
        class Int64(val value: Long) : Value(VariantDictionary.INT64)

        /** A string value, written as UTF-8; KDF parameters hold none, public custom data can. */
        class Text(val value: String) : Value(VariantDictionary.STRING)
        class Binary(val value: ByteArray) : Value(VariantDictionary.BYTE_ARRAY)
    }

    class Entry(val name: String, val value: Value)

    /**
     * An entry as stored: its [type] byte, its [name] bytes and its [value] bytes, written as
     * given. [writeRaw] checks neither the type nor the value's size against it.
     */
    class RawEntry(val type: Int, val name: ByteArray, val value: ByteArray)

    /**
     * Returns the serialized dictionary. Throws [KdbxException.DictionaryTooLarge] when it would
     * not fit in an array; the size is computed before the output is allocated.
     */
    fun write(entries: List<Entry>): ByteArray = writeRaw(entries.map(::raw))

    /** Returns [entry] as stored: its type byte, its UTF-8 name and its value bytes. */
    fun raw(entry: Entry): RawEntry = RawEntry(entry.value.type, entry.name.encodeToByteArray(), valueBytes(entry.value))

    /** Returns the serialized dictionary of [entries], as [write] does. */
    fun writeRaw(entries: List<RawEntry>): ByteArray {
        val named = entries.filter { it.name.isNotEmpty() }
        var size = 2L + 1
        for (e in named) size += 1L + 4 + e.name.size + 4 + e.value.size
        if (size > Int.MAX_VALUE) throw KdbxException.DictionaryTooLarge()
        val out = ByteArray(size.toInt())
        Bytes.writeLe16(out, 0, VariantDictionary.VERSION)
        var p = 2
        for (e in named) {
            out[p++] = e.type.toByte()
            p = field(out, p, e.name)
            p = field(out, p, e.value)
        }
        out[p] = VariantDictionary.END.toByte()
        return out
    }

    // Writes [data]'s length and [data] at [p]; returns the position after them.
    private fun field(out: ByteArray, p: Int, data: ByteArray): Int {
        Bytes.writeLe32(out, p, data.size)
        data.copyInto(out, p + 4)
        return p + 4 + data.size
    }

    private fun valueBytes(v: Value): ByteArray = when (v) {
        is Value.UInt32 -> ByteArray(4).also { Bytes.writeLe32(it, 0, v.value.toInt()) }
        is Value.UInt64 -> ByteArray(8).also { Bytes.writeLe64(it, 0, v.value.toLong()) }
        is Value.Bool -> byteArrayOf(if (v.value) 1 else 0)
        is Value.Int32 -> ByteArray(4).also { Bytes.writeLe32(it, 0, v.value) }
        is Value.Int64 -> ByteArray(8).also { Bytes.writeLe64(it, 0, v.value) }
        is Value.Text -> v.value.encodeToByteArray()
        is Value.Binary -> v.value
    }
}
