package org.onekash.kashpass.vault.xml

/**
 * Holds the UTF-8 bytes a document was read from: [length] bytes of [bytes] from [offset]. Every
 * node [XmlReader] builds locates its original bytes as indexes into [bytes], so [XmlWriter] copies
 * an unchanged node byte for byte.
 *
 * The array is not copied. Its owner keeps it unchanged while a tree read from it can be written,
 * and zero-fills it only once no tree is left; edit copies of a tree share the source.
 */
internal class XmlSource(internal val bytes: ByteArray, val offset: Int, val length: Int) {

    init {
        require(offset >= 0 && length >= 0 && offset <= bytes.size - length) { "range outside the array" }
    }

    /** Index in [bytes] after the document's last byte. */
    val end: Int get() = offset + length

    /**
     * Decodes the bytes from [start] until [end] as one node's String. Every String the reader
     * builds from the source comes from here ([XmlStringRuleTest]); the reader checked the whole
     * range as UTF-8 before building any node.
     */
    fun string(start: Int, end: Int): String =
        // allowed: per-node decoding, the one place vault.xml turns bytes into a String
        String(bytes, start, end - start, Charsets.UTF_8)
}
