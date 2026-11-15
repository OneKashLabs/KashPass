package org.onekash.kashpass.vault.xml

import java.nio.charset.Charset
import java.nio.charset.IllegalCharsetNameException
import java.io.InputStream

/** Outcome of [XmlReader.read]. */
internal sealed interface XmlReadResult {

    class Parsed(val document: XmlDocument) : XmlReadResult

    /**
     * Not well-formed XML 1.0 in UTF-8. [offset] is the byte position in the document where
     * reading stopped; no content is kept.
     */
    data class Malformed(val offset: Int) : XmlReadResult

    /** The input was longer than the caller's limit. */
    data object TooLarge : XmlReadResult
}

/**
 * Parses well-formed XML 1.0 in UTF-8, and nothing else, into an [XmlDocument] whose nodes locate
 * their original bytes in one [XmlSource].
 *
 * The bytes are parsed in place: no String of the whole document is built. The whole input is
 * first checked as UTF-8 of characters the Char production allows; text, attribute values and
 * names then become Strings one node at a time, through [XmlSource.string]. Only the five
 * predefined entities and character references are resolved. A document type declaration is kept
 * as one raw node and never interpreted, so a document cannot define an entity, reference an
 * external file or expand anything. The parser is iterative and refuses nesting deeper than
 * [MAX_DEPTH], so no input can overflow the stack here or in recursive readers of the tree. No
 * namespace processing: names are taken as written. The XML declaration is checked as .NET's
 * reader checks it. [XmlReaderTest] pins each rule.
 */
internal object XmlReader {

    /** Deepest element nesting accepted; KDBX vaults nest a few dozen levels at most. */
    const val MAX_DEPTH = 512

    private const val CHUNK = 64 * 1024

    /**
     * Reads at most [maxBytes] + 1 bytes of UTF-8 from [input] and parses them. Longer input is
     * [XmlReadResult.TooLarge]; invalid UTF-8 is [XmlReadResult.Malformed]. The document owns the
     * array it reads into.
     */
    fun read(input: InputStream, maxBytes: Int): XmlReadResult {
        val chunks = ArrayList<ByteArray>()
        var total = 0L
        while (true) {
            val wanted = minOf(CHUNK.toLong(), maxBytes + 1L - total).toInt()
            if (wanted <= 0) return XmlReadResult.TooLarge
            val chunk = ByteArray(wanted)
            var n = 0
            while (n < wanted) {
                val read = input.read(chunk, n, wanted - n)
                if (read < 0) break
                n += read
            }
            if (n > 0) chunks += if (n == wanted) chunk else chunk.copyOf(n)
            total += n
            if (n < wanted) break
        }
        val bytes = ByteArray(total.toInt())
        var offset = 0
        for (chunk in chunks) {
            chunk.copyInto(bytes, offset)
            offset += chunk.size
        }
        return read(bytes, 0, bytes.size, maxBytes)
    }

    /**
     * Parses [length] bytes of UTF-8 in [bytes] from [offset] without copying them; more than
     * [maxBytes] is [XmlReadResult.TooLarge] and invalid UTF-8 is [XmlReadResult.Malformed]. The
     * document's [XmlSource] is a view of [bytes], which the caller keeps unchanged while the
     * document can be written.
     */
    fun read(bytes: ByteArray, offset: Int, length: Int, maxBytes: Int): XmlReadResult {
        if (length > maxBytes) return XmlReadResult.TooLarge
        val source = XmlSource(bytes, offset, length)
        return try {
            XmlReadResult.Parsed(Parser(source).document())
        } catch (e: Bad) {
            XmlReadResult.Malformed(e.offset)
        }
    }

    private class Bad(val offset: Int) : Exception(null, null, false, false)

    private const val TAB = 0x09
    private const val LF = 0x0A
    private const val CR = 0x0D
    private const val QUOTE = 0x22
    private const val AMP = 0x26
    private const val APOS = 0x27
    private const val LT = 0x3C
    private const val EQ = 0x3D
    private const val GT = 0x3E
    private const val RBRACKET = 0x5D

    // Every delimiter the grammar names is ASCII, and in UTF-8 no byte of a multi-byte sequence is
    // below 0x80, so a scan for a delimiter byte never stops inside a character.
    private class Parser(private val src: XmlSource) {
        private val b = src.bytes
        private val limit = src.end
        private var i = src.offset

        private fun fail(at: Int = i): Nothing = throw Bad(at - src.offset)

        private fun byteAt(k: Int): Int = b[k].toInt() and 0xFF

        // True when the ASCII [prefix] starts at [k].
        private fun startsWith(prefix: String, k: Int): Boolean {
            if (prefix.length > limit - k) return false
            for (n in prefix.indices) if (byteAt(k + n) != prefix[n].code) return false
            return true
        }

        // Index of the first byte [byte] from [from] until [end], or -1.
        private fun indexOf(byte: Int, from: Int, end: Int = limit): Int {
            for (k in from until end) if (byteAt(k) == byte) return k
            return -1
        }

        // Index of the ASCII [text] from [from], or -1. [text] is at most three bytes, so the
        // scan stays linear.
        private fun indexOf(text: String, from: Int): Int {
            var k = from
            while (k <= limit - text.length) {
                if (startsWith(text, k)) return k
                k++
            }
            return -1
        }

        private fun space(k: Int) = XmlChars.isSpace(byteAt(k))

        // The code point of the sequence at [k]; the input was checked as UTF-8 before parsing.
        private fun codePoint(k: Int): Int {
            val lead = byteAt(k)
            val length = XmlChars.utf8Length(lead)
            if (length == 1) return lead
            var code = lead and (0xFF shr (length + 1))
            for (n in 1 until length) code = (code shl 6) or (byteAt(k + n) and 0x3F)
            return code
        }

        fun document(): XmlDocument {
            XmlChars.firstInvalidUtf8(b, i, limit).let { if (it >= 0) fail(it) }
            val bom = limit - i >= 3 && byteAt(i) == 0xEF && byteAt(i + 1) == 0xBB && byteAt(i + 2) == 0xBF
            if (bom) i += 3
            val first = i
            val nodes = mutableListOf<XmlNode>()
            var root: XmlElement? = null
            var doctype = false
            val stack = ArrayList<XmlElement>()
            while (i < limit) {
                val top = stack.lastOrNull()
                when {
                    byteAt(i) != LT -> {
                        val text = text(top)
                        if (top == null) nodes += text else top.adopt(text)
                    }
                    startsWith("</", i) -> {
                        if (top == null) fail()
                        endTag(top)
                        stack.removeAt(stack.size - 1)
                    }
                    startsWith("<!--", i) -> {
                        val comment = comment()
                        if (top == null) nodes += comment else top.adopt(comment)
                    }
                    startsWith("<![CDATA[", i) -> {
                        if (top == null) fail()
                        top.adopt(cdata())
                    }
                    startsWith("<!DOCTYPE", i) -> {
                        if (top != null || root != null || doctype) fail()
                        nodes += doctype()
                        doctype = true
                    }
                    startsWith("<?", i) -> {
                        val pi = processingInstruction(declarationAllowed = i == first)
                        if (top == null) nodes += pi else top.adopt(pi)
                    }
                    else -> {
                        if (top == null && root != null) fail()
                        if (stack.size >= MAX_DEPTH) fail()
                        val (element, selfClosing) = startTag()
                        if (top == null) {
                            root = element
                            nodes += element
                        } else {
                            top.adopt(element)
                        }
                        if (!selfClosing) stack += element
                    }
                }
            }
            if (stack.isNotEmpty() || root == null) fail()
            return XmlDocument(bom, nodes, root, doctype, src)
        }

        // Character data up to the next '<'. At the top level only whitespace is allowed.
        private fun text(top: XmlElement?): XmlText {
            val start = i
            val end = indexOf(LT, i).let { if (it < 0) limit else it }
            i = end
            if (top == null) {
                for (k in start until end) if (!space(k)) fail(k)
                return XmlText(src.string(start, end), false, src, start, end)
            }
            return XmlText(textValue(start, end), false, src, start, end)
        }

        // The decoded value of the text from [start] until [end]: references resolved, line ends
        // normalized.
        private fun textValue(start: Int, end: Int): String {
            var k = start
            while (k < end && byteAt(k) != CR && byteAt(k) != AMP && byteAt(k) != RBRACKET) k++
            if (k == end) return src.string(start, end)
            val value = StringBuilder(end - start)
            var run = start
            while (k < end) {
                when (byteAt(k)) {
                    CR -> {
                        value.append(src.string(run, k)).append('\n')
                        k++
                        if (k < end && byteAt(k) == LF) k++
                        run = k
                    }
                    AMP -> {
                        value.append(src.string(run, k))
                        k = reference(k, end, value)
                        run = k
                    }
                    RBRACKET -> {
                        // "]]>" is not allowed in text; checked here, within this text only, so a
                        // parse stays linear in the document's size.
                        if (startsWith("]]>", k) && k + 3 <= end) fail(k)
                        k++
                    }
                    else -> k++
                }
            }
            return value.append(src.string(run, end)).toString()
        }

        // Resolves the reference starting at '&' at [amp]; returns the index after its ';'.
        private fun reference(amp: Int, end: Int, out: StringBuilder): Int {
            val semi = indexOf(';'.code, amp, end)
            if (semi < 0) fail(amp)
            val name = src.string(amp + 1, semi)
            when {
                name.startsWith("#x") -> out.appendCodePoint(characterReference(name.substring(2), 16, amp))
                name.startsWith("#") -> out.appendCodePoint(characterReference(name.substring(1), 10, amp))
                else -> out.append(PREDEFINED[name] ?: fail(amp))
            }
            return semi + 1
        }

        private fun characterReference(digits: String, radix: Int, amp: Int): Int {
            if (digits.isEmpty() || digits.length > 8) fail(amp)
            val valid = if (radix == 16) digits.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } else digits.all { it in '0'..'9' }
            if (!valid) fail(amp)
            val code = digits.toLong(radix)
            if (code > Int.MAX_VALUE || !XmlChars.isChar(code.toInt())) fail(amp)
            return code.toInt()
        }

        private fun name(): String {
            val start = i
            if (i >= limit || !XmlChars.isNameStart(codePoint(i))) fail()
            i += XmlChars.utf8Length(byteAt(i))
            while (i < limit && XmlChars.isName(codePoint(i))) i += XmlChars.utf8Length(byteAt(i))
            return src.string(start, i)
        }

        private fun skipSpace(): Boolean {
            val start = i
            while (i < limit && space(i)) i++
            return i > start
        }

        private fun startTag(): Pair<XmlElement, Boolean> {
            val start = i
            i++
            val name = name()
            val attributes = mutableListOf<XmlAttribute>()
            // Names seen in this tag, filled once it has more than [SCAN_ATTRIBUTES], so a tag
            // with many attributes is checked for duplicates in linear time.
            var names: HashSet<String>? = null
            while (true) {
                val spaced = skipSpace()
                if (i >= limit) fail()
                if (byteAt(i) == GT) {
                    i++
                    return XmlElement.read(name, attributes, src, start, i) to false
                }
                if (startsWith("/>", i)) {
                    i += 2
                    val element = XmlElement.read(name, attributes, src, start, i)
                    XmlElement.closed(element, -1, i)
                    return element to true
                }
                if (!spaced) fail()
                val attributeStart = i
                val attributeName = name()
                skipSpace()
                if (i >= limit || byteAt(i) != EQ) fail()
                i++
                skipSpace()
                if (i >= limit || (byteAt(i) != QUOTE && byteAt(i) != APOS)) fail()
                val quote = byteAt(i)
                val valueEnd = indexOf(quote, i + 1)
                if (valueEnd < 0) fail()
                val value = attributeValue(i + 1, valueEnd)
                i = valueEnd + 1
                val duplicate = names?.let { !it.add(attributeName) } ?: attributes.any { it.name == attributeName }
                if (duplicate) fail(attributeStart)
                attributes += XmlAttribute(attributeName, value, attributeStart, i)
                if (names == null && attributes.size > SCAN_ATTRIBUTES) names = attributes.mapTo(HashSet()) { it.name }
            }
        }

        // XML 1.0 section 3.3.3 for an attribute without a declaration (CDATA type).
        private fun attributeValue(start: Int, end: Int): String {
            var k = start
            while (k < end && byteAt(k) != LT && byteAt(k) != AMP && byteAt(k) != CR && byteAt(k) != LF && byteAt(k) != TAB) k++
            if (k == end) return src.string(start, end)
            val value = StringBuilder(end - start)
            var run = start
            while (k < end) {
                when (byteAt(k)) {
                    LT -> fail(k)
                    AMP -> {
                        value.append(src.string(run, k))
                        k = reference(k, end, value)
                        run = k
                    }
                    CR -> {
                        value.append(src.string(run, k)).append(' ')
                        k++
                        if (k < end && byteAt(k) == LF) k++
                        run = k
                    }
                    LF, TAB -> {
                        value.append(src.string(run, k)).append(' ')
                        k++
                        run = k
                    }
                    else -> k++
                }
            }
            return value.append(src.string(run, end)).toString()
        }

        private fun endTag(top: XmlElement) {
            val start = i
            i += 2
            if (name() != top.name) fail(start)
            skipSpace()
            if (i >= limit || byteAt(i) != GT) fail()
            i++
            XmlElement.closed(top, start, i)
        }

        private fun comment(): XmlRaw {
            val start = i
            val close = indexOf("-->", i + 4)
            if (close < 0) fail()
            // A comment's body holds no "--" and does not end with '-' (XML 1.0 section 2.5).
            for (k in start + 4 until close) {
                if (byteAt(k) == '-'.code && (k + 1 == close || byteAt(k + 1) == '-'.code)) fail(start)
            }
            i = close + 3
            return XmlRaw(XmlRaw.Kind.COMMENT, src, start, i)
        }

        private fun processingInstruction(declarationAllowed: Boolean): XmlRaw {
            val start = i
            i += 2
            val target = name()
            if (target.equals("xml", ignoreCase = true) && !(declarationAllowed && target == "xml")) fail(start)
            if (target == "xml") {
                declaration()
                return XmlRaw(XmlRaw.Kind.PROCESSING_INSTRUCTION, src, start, i)
            }
            val close = indexOf("?>", i)
            if (close < 0) fail()
            if (close > i && !space(i)) fail()
            i = close + 2
            return XmlRaw(XmlRaw.Kind.PROCESSING_INSTRUCTION, src, start, i)
        }

        // The XML declaration after `<?xml`, as XML 1.0 section 2.8 (XMLDecl) and .NET's reader
        // read it: version 1.0, then an optional encoding name the platform supports and an
        // optional standalone yes or no, in that order, each `name = 'value'` or `name = "value"`
        // after white space, then optional white space and `?>`. Anything else fails, including
        // an unsupported encoding. The document is read as UTF-8 whatever encoding it names.
        private fun declaration() {
            if (!pseudoAttribute("version") { it == "1.0" }) fail()
            pseudoAttribute("encoding") { v -> v.isNotEmpty() && v[0].isAsciiLetter() && v.all { it.isAsciiLetterOrDigit() || it in "._-" } && supported(v) }
            pseudoAttribute("standalone") { it == "yes" || it == "no" }
            while (i < limit && space(i)) i++
            if (!startsWith("?>", i)) fail()
            i += 2
        }

        // Reads ` name = "value"` when white space and [name] follow, failing when [valid] refuses
        // the value; false when they don't follow, with nothing read.
        private fun pseudoAttribute(name: String, valid: (String) -> Boolean): Boolean {
            var k = i
            if (k >= limit || !space(k)) return false
            while (k < limit && space(k)) k++
            if (!startsWith(name, k)) return false
            k += name.length
            while (k < limit && space(k)) k++
            if (k >= limit || byteAt(k) != '='.code) fail(k)
            k++
            while (k < limit && space(k)) k++
            val quote = if (k < limit) byteAt(k) else fail(k)
            if (quote != QUOTE && quote != APOS) fail(k)
            val close = indexOf(quote, k + 1)
            if (close < 0) fail(k)
            if (!valid(src.string(k + 1, close))) fail(k)
            i = close + 1
            return true
        }

        // .NET refuses an encoding it does not support; the JDK's list stands in for .NET's, plus
        // the UTF-16 names .NET keeps for a UTF-16 document ([XmlEncoding.UTF_16_NAMES]).
        private fun supported(name: String): Boolean = name.lowercase() in XmlEncoding.UTF_16_NAMES || try {
            Charset.isSupported(name)
        } catch (e: IllegalCharsetNameException) {
            false
        }

        private fun Char.isAsciiLetter() = this in 'A'..'Z' || this in 'a'..'z'

        private fun Char.isAsciiLetterOrDigit() = isAsciiLetter() || this in '0'..'9'

        private fun cdata(): XmlText {
            val start = i
            val close = indexOf("]]>", start + 9)
            if (close < 0) fail()
            val raw = src.string(start + 9, close)
            i = close + 3
            return XmlText(raw.replace("\r\n", "\n").replace('\r', '\n'), true, src, start, i)
        }

        // Finds the declaration's closing '>' outside quoted literals, and inside an internal
        // subset also outside comments and processing instructions; nothing is interpreted.
        private fun doctype(): XmlRaw {
            val start = i
            i += 9
            if (i >= limit || !space(i)) fail()
            var inSubset = false
            while (i < limit) {
                val c = byteAt(i)
                when {
                    c == QUOTE || c == APOS -> {
                        val close = indexOf(c, i + 1)
                        if (close < 0) fail()
                        i = close + 1
                    }
                    inSubset && startsWith("<!--", i) -> {
                        val close = indexOf("-->", i + 4)
                        if (close < 0) fail()
                        i = close + 3
                    }
                    inSubset && startsWith("<?", i) -> {
                        val close = indexOf("?>", i + 2)
                        if (close < 0) fail()
                        i = close + 2
                    }
                    !inSubset && c == '['.code -> {
                        inSubset = true
                        i++
                    }
                    inSubset && c == RBRACKET -> {
                        inSubset = false
                        i++
                    }
                    !inSubset && c == GT -> {
                        i++
                        return XmlRaw(XmlRaw.Kind.DOCTYPE, src, start, i)
                    }
                    else -> i++
                }
            }
            fail(start)
        }

        companion object {
            val PREDEFINED = mapOf("lt" to "<", "gt" to ">", "amp" to "&", "apos" to "'", "quot" to "\"")

            // KDBX elements carry at most a few attributes; a linear scan of so few is cheaper
            // than a hash set.
            const val SCAN_ATTRIBUTES = 8

        }
    }
}
