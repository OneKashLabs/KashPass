package org.onekash.kashpass.vault.xml

/**
 * A parsed XML document that remembers where every node came from, so [XmlWriter] copies each
 * untouched node's original bytes and re-serializes only the changed nodes. [nodes] are the
 * top-level nodes in order (declaration, comments, processing instructions, whitespace, the
 * document type declaration and [root]). [source] holds the bytes it was read from.
 */
internal class XmlDocument(
    /**
     * True when the input started with a byte order mark. The writer leaves it out and writes
     * UTF-8 without one.
     */
    val bom: Boolean,
    val nodes: List<XmlNode>,
    val root: XmlElement,
    /**
     * True when the document has a document type declaration. It is kept as one opaque raw node:
     * nothing in it is parsed as a definition, so no entity is ever defined or expanded.
     */
    val hasDoctype: Boolean,
    internal val source: XmlSource,
) {
    /** Returns an independent copy that writes the same bytes; it shares [source]. */
    fun copy(): XmlDocument {
        val copies = nodes.map { it.deepCopy() }
        val rootIndex = nodes.indexOfFirst { it === root }
        return XmlDocument(bom, copies, copies[rootIndex] as XmlElement, hasDoctype, source)
    }
}

/**
 * A node of the tree. [source] and [start] until [end] locate the node's original bytes, as
 * indexes into [XmlSource.bytes]; a node created or replaced in memory has no source and is always
 * serialized.
 */
internal sealed class XmlNode(
    internal val source: XmlSource?,
    internal val start: Int,
    end: Int,
) {
    /** End of the original bytes (exclusive); set once when the reader closes an element. */
    internal var end: Int = end
        private set

    internal fun close(end: Int) {
        this.end = end
    }

    /** The element holding this node, or null at the top level or when detached. */
    var parent: XmlElement? = null
        internal set

    /** Returns an independent copy that writes the same bytes. */
    abstract fun deepCopy(): XmlNode
}

/** Character data. [value] is decoded (references resolved, line ends normalized). */
internal class XmlText(val value: String, val isCData: Boolean, source: XmlSource?, start: Int, end: Int) :
    XmlNode(source, start, end) {
    constructor(value: String) : this(value, false, null, 0, 0)

    override fun deepCopy() = XmlText(value, isCData, source, start, end)
    override fun toString() = "XmlText(${value.length} chars)"
}

/** A comment, a processing instruction or the document type declaration, kept verbatim. */
internal class XmlRaw(val kind: Kind, source: XmlSource, start: Int, end: Int) : XmlNode(source, start, end) {
    enum class Kind { COMMENT, PROCESSING_INSTRUCTION, DOCTYPE }

    override fun deepCopy() = XmlRaw(kind, source!!, start, end)
    override fun toString() = "XmlRaw($kind)"
}

/**
 * One attribute; [rawStart] until [rawEnd] locate its original `name="value"` bytes in its
 * element's source, when it has them.
 */
internal class XmlAttribute(val name: String, val value: String, internal val rawStart: Int = -1, internal val rawEnd: Int = -1)

/**
 * An element. Changing its attributes or children marks it and every ancestor as changed, which
 * tells [XmlWriter] to stop copying their original bytes wholesale.
 */
internal class XmlElement private constructor(
    val name: String,
    attributes: List<XmlAttribute>,
    source: XmlSource?,
    start: Int,
    end: Int,
    /** End of the original start tag (after its `>`), or -1 for a new element. */
    internal val startTagEnd: Int,
    endTagStart: Int,
) : XmlNode(source, start, end) {

    /** Start of the original end tag, or -1 for a new or self-closing element. */
    internal var endTagStart: Int = endTagStart
        private set


    /** Creates a new, empty element with no original bytes. */
    constructor(name: String) : this(name, emptyList(), null, 0, 0, -1, -1)

    private val attrs = attributes.toMutableList()
    private val kids = mutableListOf<XmlNode>()

    internal var attributesChanged = false
        private set
    internal var childrenChanged = false
        private set

    /** True when this element or anything inside it changed since it was read. */
    internal var subtreeChanged = false
        private set

    val attributes: List<XmlAttribute> get() = attrs
    val children: List<XmlNode> get() = kids

    /** Child elements, in document order. */
    fun elements(): List<XmlElement> = kids.filterIsInstance<XmlElement>()

    /** Child elements named [name], in document order. */
    fun children(name: String): List<XmlElement> = kids.filter { it is XmlElement && it.name == name }.map { it as XmlElement }

    /** The first child element named [name], or null. */
    fun child(name: String): XmlElement? = kids.firstOrNull { it is XmlElement && it.name == name } as XmlElement?

    /** The value of attribute [name], or null when absent. */
    fun attribute(name: String): String? = attrs.firstOrNull { it.name == name }?.value

    /**
     * Returns the element's text: the decoded text and CDATA children concatenated, leaving out
     * each text child of XML whitespace alone (space, tab, LF, CR) unless the nearest xml:space
     * attribute on this element or an ancestor is "preserve", padding trimmed. CDATA is always
     * kept. [XmlReaderTest] pins it; KeePass2TextFidelityTest checks each case against KeePass 2.
     */
    fun text(): String {
        var preserve: Boolean? = null
        return buildString {
            for (kid in kids) {
                if (kid !is XmlText) continue
                val blank = !kid.isCData && kid.value.all { XmlChars.isSpace(it.code) }
                if (blank && !(preserve ?: preservesSpace().also { preserve = it })) continue
                append(kid.value)
            }
        }
    }

    private fun preservesSpace(): Boolean =
        generateSequence(this) { it.parent }.firstNotNullOfOrNull { it.attribute("xml:space") }?.trim() == "preserve"

    /** True when the element has a child element. */
    val hasElementChildren: Boolean get() = kids.any { it is XmlElement }

    /** True when the element was read as a self-closing tag (`<X/>`), which has no end tag. */
    internal val selfClosing: Boolean get() = startTagEnd >= 0 && endTagStart < 0

    /**
     * Replaces every child with one text node holding [value]. Refuses characters XML 1.0
     * forbids.
     */
    fun setText(value: String) {
        require(XmlChars.allValid(value)) { "character not allowed in XML" }
        for (kid in kids) kid.parent = null
        kids.clear()
        if (value.isNotEmpty()) kids += XmlText(value).also { it.parent = this }
        changedChildren()
    }

    /** Sets attribute [name] to [value], in place when it exists, appended otherwise. */
    fun setAttribute(name: String, value: String) {
        require(XmlChars.allValid(value)) { "character not allowed in XML" }
        val i = attrs.indexOfFirst { it.name == name }
        if (i >= 0) attrs[i] = XmlAttribute(name, value) else attrs += XmlAttribute(name, value)
        attributesChanged = true
        markSubtree()
    }

    /** Inserts the detached [node] at [index] among the children. */
    fun insert(index: Int, node: XmlNode) {
        require(node.parent == null) { "node already has a parent" }
        kids.add(index, node)
        node.parent = this
        changedChildren()
    }

    /** Appends the detached [node] as the last child. */
    fun append(node: XmlNode) = insert(kids.size, node)

    /** Removes [node], a child of this element; returns its former index. */
    fun remove(node: XmlNode): Int {
        val i = kids.indexOfFirst { it === node }
        require(i >= 0) { "not a child" }
        kids.removeAt(i)
        node.parent = null
        changedChildren()
        return i
    }

    // Adds [node] while the reader builds the tree, without marking anything as changed.
    internal fun adopt(node: XmlNode) {
        kids += node
        node.parent = this
    }

    override fun deepCopy(): XmlElement {
        val copy = XmlElement(name, attrs, source, start, end, startTagEnd, endTagStart)
        for (kid in kids) copy.adopt(kid.deepCopy())
        copy.attributesChanged = attributesChanged
        copy.childrenChanged = childrenChanged
        copy.subtreeChanged = subtreeChanged
        return copy
    }

    private fun changedChildren() {
        childrenChanged = true
        markSubtree()
    }

    private fun markSubtree() {
        var at: XmlElement? = this
        while (at != null && !at.subtreeChanged) {
            at.subtreeChanged = true
            at = at.parent
        }
    }

    override fun toString() = "XmlElement($name)"

    internal companion object {
        fun read(name: String, attributes: List<XmlAttribute>, source: XmlSource, start: Int, startTagEnd: Int) =
            XmlElement(name, attributes, source, start, -1, startTagEnd, -1)

        /** Records the original end tag of [element]; [endTagStart] is -1 when self-closing. */
        fun closed(element: XmlElement, endTagStart: Int, end: Int) {
            element.endTagStart = endTagStart
            element.close(end)
        }
    }
}

/** XML 1.0 (fifth edition) character classes. */
internal object XmlChars {

    /** The Char production of section 2.2, on UTF-16 with surrogates checked as pairs. */
    fun allValid(text: CharSequence): Boolean = firstInvalid(text) < 0

    /** Index of the first character outside the Char production, or -1. */
    fun firstInvalid(text: CharSequence): Int {
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                c == '\t' || c == '\n' || c == '\r' -> Unit
                c < ' ' -> return i
                Character.isHighSurrogate(c) -> {
                    if (i + 1 >= text.length || !Character.isLowSurrogate(text[i + 1])) return i
                    i++
                }
                Character.isLowSurrogate(c) -> return i
                c == '￾' || c == '￿' -> return i
            }
            i++
        }
        return -1
    }

    /** True when [code] is a code point the Char production allows. */
    fun isChar(code: Int): Boolean = when {
        code == 0x9 || code == 0xA || code == 0xD -> true
        code in 0x20..0xD7FF -> true
        code in 0xE000..0xFFFD -> true
        else -> code in 0x10000..0x10FFFF
    }

    fun isSpace(code: Int) = code == 0x20 || code == 0x9 || code == 0xA || code == 0xD

    /**
     * NameStartChar of section 2.3 for the code point [code]. Every code point above #xFFFF is
     * accepted, #xF0000-#x10FFFF included, which the production leaves out.
     */
    fun isNameStart(code: Int): Boolean = code > 0xFFFF || isNameStart(code.toChar())

    /**
     * NameChar of section 2.3 for the code point [code], with [isNameStart]'s rule above #xFFFF.
     */
    fun isName(code: Int): Boolean = code > 0xFFFF || isName(code.toChar())

    /**
     * Index of the first byte from [from] until [until] that does not start a well-formed UTF-8
     * sequence (RFC 3629: no overlong form, no surrogate, nothing above #x10FFFF) of a code point
     * the Char production allows, or -1.
     */
    fun firstInvalidUtf8(bytes: ByteArray, from: Int, until: Int): Int {
        var i = from
        while (i < until) {
            val lead = bytes[i].toInt() and 0xFF
            if (lead < 0x80) {
                if (!isChar(lead)) return i
                i++
                continue
            }
            val length = utf8Length(lead)
            if (length == 0 || length > until - i) return i
            // The lead byte's payload: 5, 4 or 3 bits for a sequence of 2, 3 or 4 bytes.
            var code = lead and (0xFF shr (length + 1))
            for (k in 1 until length) {
                val next = bytes[i + k].toInt() and 0xFF
                if (next and 0xC0 != 0x80) return i
                code = (code shl 6) or (next and 0x3F)
            }
            if (code < MIN_CODE[length] || !isChar(code)) return i
            i += length
        }
        return -1
    }

    /**
     * Length of the UTF-8 sequence the byte [lead] starts: 1 to 4, or 0 when none starts with it.
     */
    fun utf8Length(lead: Int): Int = when {
        lead < 0x80 -> 1
        lead < 0xC2 -> 0
        lead < 0xE0 -> 2
        lead < 0xF0 -> 3
        lead < 0xF5 -> 4
        else -> 0
    }

    // The smallest code point each sequence length encodes; a smaller one is an overlong form.
    private val MIN_CODE = intArrayOf(0, 0, 0x80, 0x800, 0x10000)

    // NameStartChar of section 2.3 within the Basic Multilingual Plane.
    private fun isNameStart(c: Char): Boolean = c == ':' || c == '_' || c in 'A'..'Z' || c in 'a'..'z' ||
        c in 'À'..'Ö' || c in 'Ø'..'ö' || c in 'ø'..'˿' ||
        c in 'Ͱ'..'ͽ' || c in 'Ϳ'..'῿' || c in '‌'..'‍' ||
        c in '⁰'..'↏' || c in 'Ⰰ'..'⿯' || c in '、'..'퟿' ||
        c in '豈'..'﷏' || c in 'ﷰ'..'�'

    // NameChar of section 2.3 within the Basic Multilingual Plane.
    private fun isName(c: Char): Boolean = isNameStart(c) || c == '-' || c == '.' || c in '0'..'9' ||
        c == '·' || c in '̀'..'ͯ' || c in '‿'..'⁀'
}
