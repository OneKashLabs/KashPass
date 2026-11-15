package org.onekash.kashpass.vault.doc


/**
 * A value the vault marks protected, held XOR-masked in memory ([MaskedBytes]) so no plaintext
 * String exists until [reveal]. Never shows its content in `toString`.
 */
class ProtectedText private constructor(private val masked: MaskedBytes) {

    /** Returns the plaintext. Call only to display or copy it. */
    fun reveal(): String {
        val bytes = utf8()
        return try {
            String(bytes, Charsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }

    /** True when the value is empty. */
    val isEmpty: Boolean get() = masked.byteLength == 0

    // A fresh plaintext copy the caller must wipe.
    internal fun utf8(): ByteArray = masked.plain()

    /** Length in UTF-16 code units, as .NET counts string length, without making a String. */
    internal val utf16Length: Int
        get() {
            val bytes = utf8()
            try {
                var n = 0
                for (b in bytes) {
                    val v = b.toInt() and 0xFF
                    when {
                        v and 0xC0 == 0x80 -> Unit
                        v >= 0xF0 -> n += 2
                        else -> n++
                    }
                }
                return n
            } finally {
                bytes.fill(0)
            }
        }

    override fun toString() = "ProtectedText(****)"

    override fun equals(other: Any?): Boolean = other is ProtectedText && masked.contentEquals(other.masked)

    override fun hashCode() = 0

    companion object {
        /** Protects [text] as [of] does for a CharArray: a lone surrogate becomes U+FFFD. */
        fun of(text: String): ProtectedText = of(text.toCharArray())

        /** Protects [chars] and zero-fills them. A lone surrogate becomes U+FFFD ([withUtf8]). */
        fun of(chars: CharArray): ProtectedText = try {
            withUtf8(chars) { buffer, length -> fromUtf8(buffer.copyOf(length)) }
        } finally {
            chars.fill('\u0000')
        }

        // Takes ownership of [bytes]: they are masked in place, so no plaintext copy remains.
        internal fun fromUtf8(bytes: ByteArray) = ProtectedText(MaskedBytes.of(bytes))
    }
}
