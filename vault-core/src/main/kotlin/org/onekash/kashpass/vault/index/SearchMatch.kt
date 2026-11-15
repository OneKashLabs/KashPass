package org.onekash.kashpass.vault.index

/** The field a search matched; [VaultIndex.matchFor] states their priority. */
enum class MatchSource { TITLE, USER_NAME, GROUP, URL, TAG, CUSTOM_NAME, CUSTOM_VALUE, NOTES }

/**
 * Why an entry matched a search: the field, its name for a custom field, the matched characters
 * in the field's own text ([textRange], what a row highlights in place), and a one-line [snippet]
 * of that text with the match at [highlight].
 */
data class SearchMatch(
    val source: MatchSource,
    val fieldName: String?,
    val textRange: IntRange,
    val snippet: String,
    val highlight: IntRange,
)

/** Positions and queries for the search's matching rule; [VaultIndex.rows] defines what matches. */
object SearchText {

    private const val BEFORE = 20
    private const val AFTER = 100
    private const val BOUNDARY_REACH = 10
    private const val ELLIPSIS = "…"
    private const val WORD_BREAKS = " /.-_:@"

    // Raw text kept around a match before whitespace collapses; wide enough that the collapsed
    // window keeps its full lead-in and tail unless a long whitespace run takes their place.
    private const val REGION = 1_000

    /**
     * Returns the search box query that finds entries tagged [tag] under [SearchTerms]' rules: the
     * tag itself when it is one plain word, else the tag in double quotes so its spaces stay part
     * of it. The search syntax has no escape for a double quote or for a leading '-' (the quotes
     * are dropped before the '-' check), so such a tag is searched by its longest run of
     * characters between double quotes, with leading '-' removed. A tag of dashes only is searched
     * as "-", an ordinary word. A tag of double quotes only leaves nothing to search for, and its
     * query, the tag itself, has no words, so it matches every entry.
     */
    fun tagQuery(tag: String): String {
        if (SearchTerms.split(tag) == listOf(tag) && !tag.startsWith("-")) return tag
        if (tag.isNotEmpty() && tag.all { it == '-' }) return "-"
        val run = tag.split('"').map { it.trimStart('-') }.maxByOrNull { it.length }.orEmpty()
        return if (run.isEmpty()) tag else "\"$run\""
    }

    /**
     * Returns where [word] occurs in [text], or null when it doesn't: the characters whose fold
     * ([SearchTerms.fold]) holds [word] at its first occurrence. [word] is folded already; an empty
     * one gives null. The range always lies inside [text] and covers whole code points.
     */
    fun find(text: String, word: String): IntRange? =
        if (word.isEmpty()) null else SearchTerms.foldedRange(text, word)

    /**
     * Returns [text] as one line around [range]: whitespace runs collapse to one space, and long
     * text is cut to a window from at most 20 characters before the match to at most 100 after
     * its start, with an ellipsis on each cut side. A cut start moves back up to 10 more characters
     * to the start of a word (after a space or one of / . - _ : @), and no cut separates a letter
     * from a combining mark. The range (not empty) moves with the text.
     */
    internal fun snippet(text: String, range: IntRange): Pair<String, IntRange> {
        val anchor = range.first
        val regionStart = maxOf(0, anchor - REGION)
        val regionEnd = minOf(text.length, anchor + REGION)
        val out = StringBuilder()
        // position[i] = where text[regionStart + i] lands (or would land) in the collapsed region.
        val position = IntArray(regionEnd - regionStart + 1)
        for (i in regionStart until regionEnd) {
            position[i - regionStart] = out.length
            val c = text[i]
            if (c.isWhitespace()) {
                if (out.isNotEmpty() && out.last() != ' ') out.append(' ')
            } else {
                out.append(c)
            }
        }
        position[regionEnd - regionStart] = out.length
        val collapsed = out.toString().trimEnd()
        val matchStart = position[range.first - regionStart]
        // A match can run past the region (a letter with a long run of marks); it ends there.
        val matchEnd = minOf(position[minOf(range.last + 1, regionEnd) - regionStart], collapsed.length)
        var from = maxOf(0, matchStart - BEFORE)
        var to = minOf(collapsed.length, matchStart + AFTER)
        if (from > 0) {
            val boundary = (from - 1 downTo maxOf(0, from - 1 - BOUNDARY_REACH)).firstOrNull { collapsed[it] in WORD_BREAKS }
            if (boundary != null) from = boundary + 1
        }
        while (from in 1 until matchStart && (collapsed[from].isLowSurrogate() || collapsed[from].isMark())) from++
        // Ending before a mark would strip it from its letter, so the letter goes too.
        while (to in (matchEnd + 1) until collapsed.length && (collapsed[to].isMark() || collapsed[to].isLowSurrogate())) to--
        if (to in (matchEnd + 1) until collapsed.length && collapsed[to - 1].isHighSurrogate()) to--
        val prefix = if (from > 0 || regionStart > 0) ELLIPSIS else ""
        val suffix = if (to < collapsed.length || regionEnd < text.length) ELLIPSIS else ""
        val shown = prefix + collapsed.substring(from, to) + suffix
        val highlight = (matchStart - from + prefix.length) until (minOf(matchEnd, to) - from + prefix.length)
        return shown to highlight
    }

    private fun Char.isMark(): Boolean = when (Character.getType(this).toByte()) {
        Character.NON_SPACING_MARK, Character.ENCLOSING_MARK, Character.COMBINING_SPACING_MARK -> true
        else -> false
    }
}
