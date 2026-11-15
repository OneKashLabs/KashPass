package org.onekash.kashpass.vault.doc

import java.util.Base64

/**
 * Decodes a Base64 value of a KDBX file: spaces, tabs, CRs and LFs anywhere are skipped; the rest
 * must be a multiple of 4 characters of the standard alphabet, with at most two `=` and only at
 * the end. Missing padding is refused, which Java's basic decoder accepts. [ConvertBase64Test]
 * pins each rule.
 */
internal object ConvertBase64 {

    /** Returns the bytes [text] holds, or null when it breaks one of these rules. */
    fun decode(text: CharSequence): ByteArray? {
        val sb = StringBuilder(text.length)
        for (c in text) if (c != ' ' && c != '\t' && c != '\r' && c != '\n') sb.append(c)
        if (sb.length % 4 != 0) return null
        var pad = 0
        while (pad < sb.length && sb[sb.length - 1 - pad] == '=') pad++
        if (pad > 2) return null
        for (i in 0 until sb.length - pad) {
            val c = sb[i]
            val ok = c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '+' || c == '/'
            if (!ok) return null
        }
        return try {
            Base64.getDecoder().decode(sb.toString())
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
