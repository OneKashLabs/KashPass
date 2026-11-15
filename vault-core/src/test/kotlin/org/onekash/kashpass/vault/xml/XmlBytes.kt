package org.onekash.kashpass.vault.xml

/** Test helpers that read and write XML as bytes. */
internal object XmlBytes {

    /** Parses [text] encoded as UTF-8. */
    fun parse(text: String): XmlReadResult = parse(text.encodeToByteArray())

    /** Parses [bytes] with no size limit. */
    fun parse(bytes: ByteArray): XmlReadResult = XmlReader.read(bytes, 0, bytes.size, Int.MAX_VALUE)

    /** Writes [document], through [hooks] when given, and returns the bytes. */
    fun write(document: XmlDocument, hooks: XmlWriter.Hooks? = null): ByteArray {
        val sink = ByteSink(::ByteArray)
        if (hooks == null) XmlWriter.write(document, sink) else XmlWriter.write(document, sink, hooks)
        return sink.buffer.copyOf(sink.size)
    }

    /** Writes [document] like [write] and decodes the bytes as UTF-8, for comparisons. */
    fun text(document: XmlDocument, hooks: XmlWriter.Hooks? = null): String = write(document, hooks).decodeToString()

    /** Hooks whose [content] replacements are text, escaped by the caller and written as UTF-8. */
    open class TextHooks : XmlWriter.Hooks {
        /** Returns the escaped text to write as [element]'s content, or null to keep it. */
        open fun text(element: XmlElement): String? = null

        final override fun content(element: XmlElement, sink: ByteSink): Boolean {
            val text = text(element) ?: return false
            sink.writeUtf8(text)
            return true
        }
    }
}
