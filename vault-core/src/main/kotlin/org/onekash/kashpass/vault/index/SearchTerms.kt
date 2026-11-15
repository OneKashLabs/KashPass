package org.onekash.kashpass.vault.index

import java.text.Normalizer
import java.util.Locale

/**
 * Simple-mode search terms: the query splits into words ([split]); an entry matches when every
 * included word occurs in at least one of its searched texts and no excluded word occurs in any.
 * Texts and words are compared after [fold]. The search box ([VaultIndex.rows]) and field
 * references ([FieldRefs]) share these rules. [SearchTermsTest] pins them.
 */
internal object SearchTerms {

    /**
     * A parsed query: [include] and [exclude] hold folded words. No words at all matches
     * everything.
     */
    class Query(val include: List<String>, val exclude: List<String>) {
        val isEmpty: Boolean get() = include.isEmpty() && exclude.isEmpty()
    }

    /**
     * Splits [query] into words: outside quotes, space, tab, CR and LF end a word; a double quote
     * toggles quoting and is dropped, so a quoted phrase can start or end mid-word and an
     * unterminated quote runs to the end. Empty words are dropped; words are not trimmed.
     */
    fun split(query: String): List<String> {
        val words = mutableListOf<String>()
        val word = StringBuilder()
        var quoted = false
        for (c in query) {
            when {
                (c == ' ' || c == '\t' || c == '\r' || c == '\n') && !quoted -> {
                    if (word.isNotEmpty()) words += word.toString()
                    word.setLength(0)
                }
                c == '"' -> quoted = !quoted
                else -> word.append(c)
            }
        }
        if (word.isNotEmpty()) words += word.toString()
        return words
    }

    /**
     * Parses [query]: a word of two or more characters that starts with '-' excludes the rest of
     * it, checked after [split] drops the quotes, so "-a" in quotes excludes too; '-' alone is an
     * ordinary word.
     */
    fun parse(query: String): Query {
        val include = mutableListOf<String>()
        val exclude = mutableListOf<String>()
        for (word in split(query)) {
            if (word.length >= 2 && word[0] == '-') exclude += fold(word.substring(1)) else include += fold(word)
        }
        return Query(include, exclude)
    }

    /**
     * True when every included word occurs in some text of [folded] and no excluded word in any.
     */
    fun matches(query: Query, folded: List<String>): Boolean =
        query.include.all { word -> folded.any { it.contains(word) } } &&
            query.exclude.none { word -> folded.any { it.contains(word) } }

    /**
     * Returns [text] for comparison: each code point lowercased (Locale.ROOT), final sigma as σ,
     * decomposed (NFD), and its combining marks (Unicode categories Mn, Me, Mc) dropped, so an
     * accented letter matches its base letter; ß, æ, ø and ligatures stay as themselves. Folding
     * each code point on its own keeps the result independent of its neighbours, so [foldedRange]
     * can map a match back to [text].
     */
    fun fold(text: String): String {
        if (text.all { it < '\u0080' }) return text.lowercase(Locale.ROOT)
        val out = StringBuilder(text.length)
        forEachFolded(text) { _, _, part -> out.append(part) }
        return out.toString()
    }

    /**
     * Returns the characters of [text] whose fold holds [word] (already folded, not empty) at its
     * first occurrence, with any following marks that fold to nothing, or null when it doesn't
     * occur.
     */
    fun foldedRange(text: String, word: String): IntRange? {
        if (text.all { it < '\u0080' }) {
            val at = text.lowercase(Locale.ROOT).indexOf(word)
            return if (at < 0) null else at until at + word.length
        }
        val folded = StringBuilder(text.length)
        var origin = IntArray(text.length + 8)
        var originEnd = IntArray(text.length + 8)
        forEachFolded(text) { start, end, part ->
            if (origin.size < folded.length + part.length) {
                origin = origin.copyOf(origin.size * 2 + part.length)
                originEnd = originEnd.copyOf(origin.size)
            }
            for (k in part.indices) {
                origin[folded.length + k] = start
                originEnd[folded.length + k] = end
            }
            folded.append(part)
        }
        val at = folded.indexOf(word)
        if (at < 0) return null
        // Marks that fold to nothing after the match belong to its last letter.
        var end = originEnd[at + word.length - 1]
        while (end < text.length) {
            val cp = text.codePointAt(end)
            if (cp >= 0x10000 || BMP_FOLDS[cp].isNotEmpty()) break
            end += Character.charCount(cp)
        }
        return origin[at] until end
    }

    // The fold of every BMP code point, built once on first use and independent of any vault's
    // content, so nothing about a vault's text outlives its lock.
    private val BMP_FOLDS: Array<String> by lazy { Array(0x10000) { foldCodePoint(it) } }

    // Calls [part] with each code point's range in [text] and its fold.
    private inline fun forEachFolded(text: String, part: (start: Int, end: Int, folded: String) -> Unit) {
        val table = BMP_FOLDS
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (!Character.isHighSurrogate(c) || i + 1 >= text.length || !Character.isLowSurrogate(text[i + 1])) {
                part(i, i + 1, table[c.code])
                i++
                continue
            }
            val cp = text.codePointAt(i)
            part(i, i + 2, foldCodePoint(cp))
            i += 2
        }
    }

    private fun foldCodePoint(cp: Int): String {
        if (cp in 0xD800..0xDFFF) return String(Character.toChars(cp))
        val lower = String(Character.toChars(cp)).lowercase(Locale.ROOT).replace('\u03C2', '\u03C3')
        val decomposed = Normalizer.normalize(lower, Normalizer.Form.NFD)
        val out = StringBuilder(decomposed.length)
        var i = 0
        while (i < decomposed.length) {
            val c = decomposed.codePointAt(i)
            if (!isMark(c)) out.appendCodePoint(c)
            i += Character.charCount(c)
        }
        return out.toString()
    }

    private fun isMark(cp: Int): Boolean = when (Character.getType(cp).toByte()) {
        Character.NON_SPACING_MARK, Character.ENCLOSING_MARK, Character.COMBINING_SPACING_MARK -> true
        else -> false
    }
}
