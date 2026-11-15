package org.onekash.kashpass.vault.doc

import java.security.MessageDigest
import java.util.Base64
import org.onekash.kashpass.vault.xml.XmlElement
import org.onekash.kashpass.vault.xml.XmlEncoding
import org.onekash.kashpass.vault.xml.XmlReadResult
import org.onekash.kashpass.vault.xml.XmlReader

/** Outcome of [KeyFile.parse]. */
internal sealed interface KeyFileResult {

    /** The key-file part of the composite key, any length for an XML key file. */
    class Key(val part: ByteArray) : KeyFileResult {
        override fun toString() = "Key(${part.size} bytes)"
    }

    /**
     * An XML key file whose key can't be read: a hash that doesn't match, data that isn't valid
     * base64 or hex, no data, an unknown version, or a document type declaration.
     */
    data object Damaged : KeyFileResult

    /**
     * An XML file whose root element is KeyFile and whose XML is longer than the heap's limit for
     * it; it was not parsed.
     */
    data object NotEnoughMemory : KeyFileResult
}

/**
 * Reads key files: the key part goes into the composite key ([VaultKey]). [KeyFileTest] pins each
 * rule.
 */
internal object KeyFile {

    private const val HASH_BYTES = 4

    /**
     * Returns the key part of [bytes], tried in this order: an XML key file (version 1 base64 or
     * version 2 hex data, with its 4-byte SHA-256 hash checked when the Hash attribute is not
     * empty), then exactly 32 bytes as they are, then exactly 64 hex characters decoded, else
     * the SHA-256 of the whole file. A document whose root element is KeyFile, without a
     * namespace, is a key file: any failure to read its key is [KeyFileResult.Damaged], never a
     * fall-through to hashing.
     *
     * The XML is UTF-8, or UTF-16 as [XmlEncoding.detect] finds it. Only a document whose root
     * element is KeyFile ([XmlEncoding.rootIs]) is parsed; any other file, XML included, is hashed
     * without a parse. A KeyFile document of more than [maxXmlBytes] UTF-8 bytes (by default the
     * limit for this heap), or one whose parse runs out of memory, is
     * [KeyFileResult.NotEnoughMemory]. [bytes] is left as it is; the caller zero-fills it and the
     * returned part.
     */
    fun parse(bytes: ByteArray, maxXmlBytes: Int = maxXmlBytes(Runtime.getRuntime().maxMemory())): KeyFileResult {
        xml(bytes, maxXmlBytes)?.let { return it }
        if (bytes.size == 32) return KeyFileResult.Key(bytes.copyOf())
        if (bytes.size == 64 && bytes.all { hexValue(it.toInt().toChar()) >= 0 }) {
            return KeyFileResult.Key(ByteArray(32) { i -> (hexValue(bytes[2 * i].toInt().toChar()) * 16 + hexValue(bytes[2 * i + 1].toInt().toChar())).toByte() })
        }
        return KeyFileResult.Key(MessageDigest.getInstance("SHA-256").digest(bytes))
    }

    /**
     * Returns the longest XML key file, in UTF-8 bytes, parsed on a heap of [maxHeapBytes]: the
     * heap divided by 60. A key file of tiny elements (`<a/>` repeated) keeps 39.4 bytes of heap
     * per byte once parsed, measured on the host, and 60 leaves a margin of 1.5 over that.
     * [FixedHeapLimitTest] opens such a file at the limit.
     */
    fun maxXmlBytes(maxHeapBytes: Long): Int = (maxHeapBytes / XML_HEAP_DIVISOR).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

    private const val XML_HEAP_DIVISOR = 60L

    // Null when [bytes] is not an XML document with a KeyFile root without a namespace; such a
    // file is a raw key.
    private fun xml(bytes: ByteArray, maxXmlBytes: Int): KeyFileResult? {
        val encoding = XmlEncoding.detect(bytes) ?: return null
        if (!encoding.rootIs(bytes, "KeyFile")) return null
        val tooLarge = if (encoding == XmlEncoding.UTF_8) bytes.size > maxXmlBytes else (bytes.size - encoding.bomBytes) / 2 > maxXmlBytes
        if (tooLarge) return KeyFileResult.NotEnoughMemory
        var utf8: ByteArray? = null
        try {
            // The UTF-8 copy of a UTF-16 file holds the key, so it is zero-filled after the parse.
            val text = if (encoding == XmlEncoding.UTF_8) bytes else encoding.toUtf8(bytes) ?: return null
            utf8 = text
            if (text.size > maxXmlBytes) return KeyFileResult.NotEnoughMemory
            // Invalid UTF-8 is malformed, so such a file is a raw key. The text of each node, the
            // key data included, is a String that stays in memory until garbage collection.
            val parsed = XmlReader.read(text, 0, text.size, text.size)
            val document = (parsed as? XmlReadResult.Parsed)?.document ?: return null
            val root = document.root
            if (root.name != "KeyFile" || !root.attribute("xmlns").isNullOrEmpty()) return null
            // A DTD is refused; no key is read past one.
            if (document.hasDoctype) return KeyFileResult.Damaged
            return key(root) ?: KeyFileResult.Damaged
        } catch (e: OutOfMemoryError) {
            return KeyFileResult.NotEnoughMemory
        } finally {
            utf8?.takeIf { it !== bytes }?.fill(0)
        }
    }

    // White space is removed from the data, the major version picks base64 or hex, empty data is
    // damage, and a non-empty Hash must match.
    private fun key(root: XmlElement): KeyFileResult.Key? {
        val dataElement = root.child("Key")?.child("Data")
        val data = dataElement?.text()?.filterNot(::isDotNetWhiteSpace).orEmpty()
        if (data.isEmpty()) return null
        val key = when (majorVersion(root.child("Meta")?.child("Version")?.text().orEmpty())) {
            1 -> try {
                Base64.getDecoder().decode(data)
            } catch (e: IllegalArgumentException) {
                return null
            }
            2 -> hex(data) ?: return null
            else -> return null
        }
        val hash = hex(dataElement?.attribute("Hash").orEmpty())
        val matches = when {
            key.isEmpty() || hash == null -> false
            hash.isEmpty() -> true
            else -> MessageDigest.isEqual(hash, MessageDigest.getInstance("SHA-256").digest(key).copyOf(HASH_BYTES))
        }
        if (!matches) {
            key.fill(0)
            return null
        }
        return KeyFileResult.Key(key)
    }

    /**
     * Returns true for the characters .NET Framework's Char.IsWhiteSpace accepts, the white space
     * removed from key data. The table is written out, not taken from the platform's Unicode data:
     * Kotlin's Char.isWhitespace on the JVM keeps U+0085 and drops U+001C-U+001F, and ART's data
     * can differ from the JVM's.
     *
     * Source: referencesource mscorlib/system/char.cs IsWhiteSpaceLatin1 (U+0009-U+000D, U+0020,
     * U+0085, U+00A0) and globalization/charunicodeinfo.cs IsWhiteSpace (categories Zs, Zl and Zp),
     * with the Zs members Microsoft's Char.IsWhiteSpace documentation lists, for .NET Framework 4.8
     * on current Windows, whose character data is Unicode 8.0 (CharUnicodeInfo documentation, 4.6.2
     * and later). U+180E is Cf from Unicode 6.3 on, so it is not white space.
     */
    fun isDotNetWhiteSpace(c: Char): Boolean = when (c) {
        in '\u0009'..'\u000D', ' ', '\u0085', '\u00A0', '\u1680', in '\u2000'..'\u200A',
        '\u2028', '\u2029', '\u202F', '\u205F', '\u3000' -> true
        else -> false
    }

    /**
     * Returns the major part of [version]: the text before the first '.' or ',', trimmed, as an
     * unsigned 16-bit number; 0 when it isn't one. Minor parts are ignored, so "1.0", "1.00",
     * "2.0", "2" and "2.1" all count.
     */
    fun majorVersion(version: String): Int {
        val major = version.split('.', ',').first().trim().removePrefix("+")
        if (major.isEmpty() || !major.all { it in '0'..'9' }) return 0
        val digits = major.trimStart('0')
        if (digits.length > 5) return 0
        return digits.ifEmpty { "0" }.toInt().takeIf { it <= 0xFFFF } ?: 0
    }

    // Strict hex of even length; null otherwise.
    private fun hex(text: String): ByteArray? {
        if (text.length % 2 != 0 || text.any { hexValue(it) < 0 }) return null
        return ByteArray(text.length / 2) { i -> (hexValue(text[2 * i]) * 16 + hexValue(text[2 * i + 1])).toByte() }
    }

    private fun hexValue(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }
}
