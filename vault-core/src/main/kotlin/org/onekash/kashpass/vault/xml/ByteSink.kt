package org.onekash.kashpass.vault.xml

/**
 * Collects the bytes [XmlWriter] writes in one growable array. Every array comes from [allocate],
 * so a caller can hand out arrays it tracks; when the sink grows it copies into a larger array,
 * zero-fills the old one and passes it to [release], and [truncate] and [clear] zero-fill what
 * they drop. A grown sink holds twice the bytes it needs, or the need plus [GROWTH_STEP] when
 * that is less, so a large payload sized close to its need does not double when an edit
 * outgrows it.
 *
 * [buffer] and [size] hand the written bytes over without a copy: a caller that takes them owns
 * zero-filling the array and stops writing to the sink.
 */
internal class ByteSink(
    private val allocate: (Int) -> ByteArray,
    initialCapacity: Int = 8192,
    private val release: (ByteArray) -> Unit = {},
) {

    /** The backing array; the written bytes are its first [size] bytes. */
    var buffer: ByteArray = allocated(maxOf(initialCapacity, 16))
        private set

    /** Number of bytes written. */
    var size: Int = 0
        private set

    /** Writes the low eight bits of [byte]. */
    fun write(byte: Int) {
        ensure(1)
        buffer[size++] = byte.toByte()
    }

    /** Writes [length] bytes of [bytes] from [offset]. */
    fun write(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size) {
        require(offset >= 0 && length >= 0 && offset <= bytes.size - length) { "range outside the array" }
        ensure(length)
        bytes.copyInto(buffer, size, offset, offset + length)
        size += length
    }

    /**
     * Writes [text] as UTF-8. A lone surrogate is written as U+FFFD.
     */
    fun writeUtf8(text: CharSequence) {
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                c.code < 0x80 -> write(c.code)
                c.code < 0x800 -> {
                    write(0xC0 or (c.code shr 6))
                    write(0x80 or (c.code and 0x3F))
                }
                Character.isHighSurrogate(c) && i + 1 < text.length && Character.isLowSurrogate(text[i + 1]) -> {
                    val code = Character.toCodePoint(c, text[i + 1])
                    write(0xF0 or (code shr 18))
                    write(0x80 or ((code shr 12) and 0x3F))
                    write(0x80 or ((code shr 6) and 0x3F))
                    write(0x80 or (code and 0x3F))
                    i++
                }
                Character.isSurrogate(c) -> write(REPLACEMENT)
                else -> {
                    write(0xE0 or (c.code shr 12))
                    write(0x80 or ((c.code shr 6) and 0x3F))
                    write(0x80 or (c.code and 0x3F))
                }
            }
            i++
        }
    }

    /** Drops every byte after the first [size] and zero-fills them. */
    fun truncate(size: Int) {
        require(size in 0..this.size) { "size outside the written bytes" }
        buffer.fill(0, size, this.size)
        this.size = size
    }

    /** Zero-fills the written bytes and empties the sink. */
    fun clear() = truncate(0)

    private fun ensure(extra: Int) {
        val needed = size.toLong() + extra
        if (needed <= buffer.size) return
        if (needed > MAX_CAPACITY) throw OutOfMemoryError()
        val grown = minOf(needed + minOf(needed, GROWTH_STEP), MAX_CAPACITY.toLong()).toInt()
        val next = allocated(grown)
        val old = buffer
        old.copyInto(next, 0, 0, size)
        old.fill(0)
        buffer = next
        release(old)
    }

    private fun allocated(capacity: Int): ByteArray = allocate(capacity).also {
        check(it.size >= capacity) { "allocator returned a smaller array" }
    }

    companion object {
        /** The largest array a sink allocates; some JVMs refuse one within 8 of Int.MAX_VALUE. */
        const val MAX_CAPACITY = Int.MAX_VALUE - 8

        /** The most a sink grows by beyond what a write needs. */
        const val GROWTH_STEP = 1L shl 20

        private val REPLACEMENT = byteArrayOf(0xEF.toByte(), 0xBF.toByte(), 0xBD.toByte())
    }
}
