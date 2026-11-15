package org.onekash.kashpass.vault.xml

/**
 * Writes an [XmlDocument] as UTF-8 into a [ByteSink]. Every node that wasn't changed since it was
 * read is copied from its original bytes, so an unedited document comes out identical to its
 * input, line ends included; changed elements are serialized, reusing their original start tag,
 * end tag and attributes where those are unchanged, and each serialized node is encoded on its
 * own. No byte order mark is written. [Hooks] change the
 * output without touching the tree. [XmlWriterTest] pins what an edit can touch.
 */
internal object XmlWriter {

    /** Changes made while writing, without touching the tree; called in document order. */
    interface Hooks {
        /** Returns true to leave [element] out of the output. */
        fun omit(element: XmlElement): Boolean = false

        /**
         * Writes already-escaped UTF-8 into [sink] as [element]'s whole content, instead of its
         * children, and returns true; or returns false without writing, to write the element as
         * it is.
         */
        fun content(element: XmlElement, sink: ByteSink): Boolean = false

        /**
         * Writes already-escaped UTF-8 into [sink] before [element]'s first child, or nothing.
         * Not called when [content] replaced the element's content. An element written
         * self-closing gets a start and an end tag when this writes anything.
         */
        fun prepend(element: XmlElement, sink: ByteSink) {}

        /**
         * Returns the value to write for [element]'s attribute [name] instead of the tree's, or
         * null to keep it. Called for each attribute the element has. The value is escaped like
         * any attribute value; a character XML 1.0 forbids is refused with
         * IllegalArgumentException, as [XmlElement.setAttribute] refuses it.
         */
        fun attribute(element: XmlElement, name: String): String? = null
    }

    private object NoHooks : Hooks

    /** Appends [document] to [sink]. */
    fun write(document: XmlDocument, sink: ByteSink, hooks: Hooks = NoHooks) {
        for (node in document.nodes) sink.node(node, hooks)
    }

    private fun ByteSink.copy(source: XmlSource, start: Int, end: Int) = write(source.bytes, start, end - start)

    private fun ByteSink.node(node: XmlNode, hooks: Hooks) {
        when (node) {
            is XmlElement -> if (!hooks.omit(node)) element(node, hooks)
            is XmlText -> {
                val source = node.source
                if (source != null) copy(source, node.start, node.end) else writeUtf8(escapeText(node.value))
            }
            is XmlRaw -> copy(node.source!!, node.start, node.end)
        }
    }

    // Depth is bounded by XmlReader.MAX_DEPTH for read elements; edits add at most a few levels.
    private fun ByteSink.element(element: XmlElement, hooks: Hooks) {
        val source = element.source
        // With hooks, an unchanged subtree can hold elements the hooks change, so it is walked.
        if (source != null && !element.subtreeChanged && hooks === NoHooks) {
            copy(source, element.start, element.end)
            return
        }
        val overrides = overrides(element, hooks)
        val attributesChanged = element.attributesChanged || overrides != null
        val selfClosing = source != null && element.endTagStart < 0
        val mark = size
        if (source != null && !attributesChanged && !selfClosing) {
            copy(source, element.start, element.startTagEnd)
        } else {
            startTag(element, overrides, ">")
        }
        val contentStart = size
        if (hooks.content(element, this)) {
            // An empty replacement for an element that is empty as written keeps its original form.
            val emptyAsWritten = element.children.all { it is XmlText && it.value.isEmpty() }
            if (size == contentStart && source != null && !element.subtreeChanged && overrides == null && emptyAsWritten) {
                truncate(mark)
                copy(source, element.start, element.end)
            } else {
                endTag(element)
            }
            return
        }
        hooks.prepend(element, this)
        if (size == contentStart && element.children.isEmpty() && (source == null || selfClosing)) {
            // An empty element is written in its self-closing form, not the start tag above.
            truncate(mark)
            if (source != null && !attributesChanged) copy(source, element.start, element.startTagEnd) else startTag(element, overrides, "/>")
            return
        }
        for (child in element.children) node(child, hooks)
        endTag(element)
    }

    // The hooks' value for each of [element]'s attributes by index, or null when none changes.
    private fun overrides(element: XmlElement, hooks: Hooks): Array<String?>? {
        if (hooks === NoHooks) return null
        var out: Array<String?>? = null
        element.attributes.forEachIndexed { i, attribute ->
            val value = hooks.attribute(element, attribute.name) ?: return@forEachIndexed
            require(XmlChars.allValid(value)) { "character not allowed in XML" }
            (out ?: arrayOfNulls<String>(element.attributes.size).also { out = it })[i] = value
        }
        return out
    }

    private fun ByteSink.endTag(element: XmlElement) {
        val source = element.source
        if (source != null && element.endTagStart >= 0) {
            copy(source, element.endTagStart, element.end)
        } else {
            writeUtf8("</")
            writeUtf8(element.name)
            write('>'.code)
        }
    }

    private fun ByteSink.startTag(element: XmlElement, overrides: Array<String?>?, close: String) {
        write('<'.code)
        writeUtf8(element.name)
        val source = element.source
        element.attributes.forEachIndexed { i, attribute ->
            write(' '.code)
            val override = overrides?.get(i)
            if (override == null && source != null && attribute.rawStart >= 0) {
                copy(source, attribute.rawStart, attribute.rawEnd)
            } else {
                writeUtf8(attribute.name)
                writeUtf8("=\"")
                writeUtf8(escapeAttribute(override ?: attribute.value))
                write('"'.code)
            }
        }
        writeUtf8(close)
    }

    /**
     * Escapes text content; a carriage return becomes a reference so a reader's line-end
     * normalization keeps it.
     */
    fun escapeText(value: String): String = buildString(value.length) {
        for (c in value) {
            when (c) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '\r' -> append("&#xD;")
                else -> append(c)
            }
        }
    }

    /**
     * Escapes a double-quoted attribute value; whitespace other than space becomes a reference
     * so attribute normalization keeps it.
     */
    fun escapeAttribute(value: String): String = buildString(value.length) {
        for (c in value) {
            when (c) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                '\t' -> append("&#x9;")
                '\n' -> append("&#xA;")
                '\r' -> append("&#xD;")
                else -> append(c)
            }
        }
    }
}
