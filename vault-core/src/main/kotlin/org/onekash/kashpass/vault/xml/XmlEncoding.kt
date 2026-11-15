package org.onekash.kashpass.vault.xml

/**
 * The encoding of an XML document as .NET Framework's XmlReader detects it from the first four
 * bytes when given a stream and no encoding (XmlTextReaderImpl.DetectEncoding in the .NET
 * Framework reference source). An XML key file is read with this encoding.
 * [bomBytes] is the length of the byte order mark that starts the document, if any; a UTF-8 byte
 * order mark is left to [XmlReader]. [XmlEncodingTest] pins each rule.
 */
internal enum class XmlEncoding(val bomBytes: Int, private val unit: Int) {
    UTF_8(0, 1),
    UTF_16LE(2, 2),
    UTF_16LE_UNMARKED(0, 2),
    UTF_16BE(2, 2),
    UTF_16BE_UNMARKED(0, 2),
    ;

    /**
     * Returns the document in UTF-8, without a byte order mark, or null when its XML
     * declaration names an encoding .NET's XmlReader refuses or switches to for a UTF-16
     * document. [bytes] must be UTF-16 ([UTF_8] is read as it is). A surrogate without its pair,
     * and an odd last byte, each become U+FFFD and the next unit is read as it is, as .NET's
     * UTF-16 decoder replaces them. The caller zero-fills the result; the working buffer is
     * zero-filled here.
     */
    fun toUtf8(bytes: ByteArray): ByteArray? {
        check(this != UTF_8) { "UTF-8 is read as it is" }
        val units = (bytes.size - bomBytes) / 2
        val odd = (bytes.size - bomBytes) % 2 != 0
        // Each unit is at most 3 bytes of UTF-8; a pair of 2 units is 4.
        val out = ByteArray(units * 3 + if (odd) 3 else 0)
        try {
            var n = 0
            fun put(code: Int) {
                when {
                    code < 0x80 -> out[n++] = code.toByte()
                    code < 0x800 -> {
                        out[n++] = (0xC0 or (code shr 6)).toByte()
                        out[n++] = (0x80 or (code and 0x3F)).toByte()
                    }
                    code < 0x10000 -> {
                        out[n++] = (0xE0 or (code shr 12)).toByte()
                        out[n++] = (0x80 or ((code shr 6) and 0x3F)).toByte()
                        out[n++] = (0x80 or (code and 0x3F)).toByte()
                    }
                    else -> {
                        out[n++] = (0xF0 or (code shr 18)).toByte()
                        out[n++] = (0x80 or ((code shr 12) and 0x3F)).toByte()
                        out[n++] = (0x80 or ((code shr 6) and 0x3F)).toByte()
                        out[n++] = (0x80 or (code and 0x3F)).toByte()
                    }
                }
            }
            var k = 0
            while (k < units) {
                val unit = unitAt(bytes, bomBytes + 2 * k)
                val next = if (k + 1 < units) unitAt(bytes, bomBytes + 2 * (k + 1)) else -1
                when {
                    unit in 0xD800..0xDBFF && next in 0xDC00..0xDFFF -> {
                        put(0x10000 + ((unit - 0xD800) shl 10) + (next - 0xDC00))
                        k += 2
                    }
                    unit in 0xD800..0xDFFF -> {
                        put(REPLACEMENT)
                        k++
                    }
                    else -> {
                        put(unit)
                        k++
                    }
                }
            }
            if (odd) put(REPLACEMENT)
            if (!declarationAllowsUtf16(out, n)) return null
            return out.copyOf(n)
        } finally {
            out.fill(0)
        }
    }

    private fun unitAt(bytes: ByteArray, i: Int): Int {
        val a = bytes[i].toInt() and 0xFF
        val b = bytes[i + 1].toInt() and 0xFF
        return if (this == UTF_16LE || this == UTF_16LE_UNMARKED) a or (b shl 8) else (a shl 8) or b
    }

    /**
     * Returns true when the first element of [bytes] is named [name], found by a scan past white
     * space, the XML declaration, processing instructions, comments and a document type
     * declaration (with its internal subset), without parsing the document. [name] is ASCII;
     * namespaces and well-formedness are not checked.
     */
    fun rootIs(bytes: ByteArray, name: String): Boolean {
        val u = unit
        var k = bomBytes
        if (this == UTF_8 && bytes.size >= 3 && bytes[0] == 0xEF.toByte() && bytes[1] == 0xBB.toByte() && bytes[2] == 0xBF.toByte()) k = 3
        fun at(i: Int): Int = when {
            i + u > bytes.size -> -1
            u == 1 -> bytes[i].toInt() and 0xFF
            else -> unitAt(bytes, i)
        }
        fun startsWith(text: String, i: Int) = text.indices.all { at(i + it * u) == text[it].code }
        fun find(text: String, from: Int): Int {
            var i = from
            while (at(i) >= 0) {
                if (startsWith(text, i)) return i
                i += u
            }
            return -1
        }
        while (true) {
            while (XmlChars.isSpace(at(k))) k += u
            when {
                startsWith("<?", k) -> k = find("?>", k + 2 * u).takeIf { it >= 0 }?.plus(2 * u) ?: return false
                startsWith("<!--", k) -> k = find("-->", k + 4 * u).takeIf { it >= 0 }?.plus(3 * u) ?: return false
                startsWith("<!DOCTYPE", k) -> {
                    val close = find(">", k)
                    val subset = find("[", k)
                    val end = if (subset in 0 until close) find("]", subset).takeIf { it >= 0 }?.let { find(">", it) } else close
                    k = end?.takeIf { it >= 0 }?.plus(u) ?: return false
                }
                else -> {
                    if (!startsWith("<$name", k)) return false
                    val after = at(k + (name.length + 1) * u)
                    return XmlChars.isSpace(after) || after == '/'.code || after == '>'.code
                }
            }
        }
    }

    companion object {
        /**
         * Returns the encoding of [bytes] as .NET's DetectEncoding finds it: FE FF or FF FE is
         * UTF-16 with a byte order mark, 00 3C or 3C 00 ('<') is UTF-16 without one, anything
         * else is UTF-8 until the declaration says otherwise. Null for UCS-4, which .NET also
         * detects (00 00 or a byte order mark followed by 00 00) and KashPass does not read.
         */
        fun detect(bytes: ByteArray): XmlEncoding? {
            if (bytes.size < 2) return UTF_8
            val first = ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
            val next = if (bytes.size >= 4) ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF) else 0
            return when (first) {
                0x0000 -> if (next == 0xFEFF || next == 0x003C || next == 0xFFFE || next == 0x3C00) null else UTF_8
                0xFEFF -> if (next == 0) null else UTF_16BE
                0xFFFE -> if (next == 0) null else UTF_16LE
                0x3C00 -> if (next == 0) null else UTF_16LE_UNMARKED
                0x003C -> if (next == 0) null else UTF_16BE_UNMARKED
                else -> UTF_8
            }
        }

        // The encoding names XmlTextReaderImpl.CheckEncoding keeps for a document it detected as
        // UTF-16; it switches to any other name, and the rest of a UTF-16 document read in that
        // encoding is not XML.
        val UTF_16_NAMES = setOf("utf-16", "ucs-2", "iso-10646-ucs-2", "ucs-4")

        private const val REPLACEMENT = 0xFFFD

        // True when the UTF-8 document in the first [length] bytes of [utf8] has no XML
        // declaration, or one without an encoding or with a UTF-16 name. The name is compared
        // byte by byte, so no String holds any of the document.
        private fun declarationAllowsUtf16(utf8: ByteArray, length: Int): Boolean {
            fun at(i: Int) = if (i < length) utf8[i].toInt() and 0xFF else -1
            fun startsWith(text: String, i: Int) = text.indices.all { at(i + it) == text[it].code }
            if (!startsWith("<?xml", 0) || !XmlChars.isSpace(at(5))) return true
            val limit = minOf(length, DECLARATION_BYTES)
            var end = 6
            while (end < limit && !startsWith("?>", end)) end++
            if (end >= limit) return true
            var k = 5
            while (k < end && !(XmlChars.isSpace(at(k)) && startsWith("encoding", k + 1))) k++
            if (k >= end) return true
            k += 1 + "encoding".length
            while (XmlChars.isSpace(at(k))) k++
            if (at(k) != '='.code) return true
            k++
            while (XmlChars.isSpace(at(k))) k++
            val quote = at(k)
            if (quote != '"'.code && quote != '\''.code) return true
            val start = k + 1
            var close = start
            while (close < end && at(close) != quote) close++
            return UTF_16_NAMES.any { name ->
                name.length == close - start && name.indices.all { i -> lower(at(start + i)) == name[i].code }
            }
        }

        private fun lower(code: Int) = if (code in 'A'.code..'Z'.code) code + 32 else code

        // Longer than any XML declaration a KDBX writer or a text editor writes.
        private const val DECLARATION_BYTES = 256
    }
}
