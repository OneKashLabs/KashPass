package org.onekash.kashpass.vault.doc

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

private val REPLACEMENT_UTF8 = byteArrayOf(0xEF.toByte(), 0xBF.toByte(), 0xBD.toByte())

/**
 * Runs [block] on the UTF-8 encoding of [chars], as .NET's UTF-8 encoder writes it: a lone
 * surrogate becomes U+FFFD (the JDK encoder's default replacement is '?'). The bytes are the
 * first `length` of `buffer`, one array sized for the worst case (3 bytes per char) so the
 * encoder never grows and abandons a partial copy; the buffer is zero-filled when [block]
 * returns or throws. [chars] are left as they are.
 */
internal inline fun <T> withUtf8(chars: CharArray, block: (buffer: ByteArray, length: Int) -> T): T {
    val buffer = ByteArray(chars.size * 3)
    try {
        val out = ByteBuffer.wrap(buffer)
        Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
            .replaceWith(REPLACEMENT_UTF8)
            .apply {
                encode(CharBuffer.wrap(chars), out, true)
                flush(out)
            }
        return block(buffer, out.position())
    } finally {
        buffer.fill(0)
    }
}
