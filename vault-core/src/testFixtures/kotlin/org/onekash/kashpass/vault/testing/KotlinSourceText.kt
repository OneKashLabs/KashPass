package org.onekash.kashpass.vault.testing

/**
 * Reads Kotlin source the way the source-scanning rule tests need it: the
 * text of comments and the contents of string and character literals are
 * replaced by spaces, and everything that is code stays where it was.
 *
 * - Line comments, block comments (which nest in Kotlin) and KDoc are blanked,
 *   so code before or after a comment on the same line is seen.
 * - String, raw-string and character literal contents are blanked, so a class
 *   name that only appears inside a string is not mistaken for a reference.
 *   The quotes themselves stay.
 * - Code inside string templates (`${...}` and `$name`) is kept, so a
 *   reference written inside a template is seen.
 * - Multi-dollar strings (`$$"..."`) follow Kotlin's rule: a template needs as
 *   many `$` as the string's prefix, so a lone `${` inside is plain text.
 * - Backtick identifiers are kept as code; quotes inside them open nothing.
 * - Newlines are kept, so line numbers are unchanged.
 */
object KotlinSourceText {

    /** Holds the blanked lines and whether the scan ended back in plain code. */
    data class Result(val lines: List<String>, val endsInCode: Boolean)

    fun codeLines(source: String): List<String> = scan(source).lines

    /**
     * Returns every match of [pattern] in the code of [source], as (1-based line of the match
     * start, match text with whitespace and backticks removed). Matching runs over the whole
     * blanked text, so a name split across lines or statements (`import a.B; import c.D`, a dotted
     * name continued on the next line) is one match. Throws when the scan does not end in plain
     * code, since part of the file was then skipped.
     */
    fun references(source: String, pattern: Regex): List<Pair<Int, String>> {
        val result = scan(source)
        check(result.endsInCode) { "Source reader lost track of this file; refusing to scan it" }
        val text = result.lines.joinToString("\n")
        return pattern.findAll(text).map { match ->
            val line = text.substring(0, match.range.first).count { it == '\n' } + 1
            line to match.value.filterNot { it.isWhitespace() || it == '`' }
        }.toList()
    }

    /**
     * Returns a pattern for a dotted name that starts with one of [roots] (for example
     * `org.onekash.kashpass`) and continues with any further segments, `*` included.
     * Kotlin allows whitespace around each dot and backticks around any segment, as Kotlin
     * allows; a name right after a `.` or an identifier character does not match, so
     * `x.org.onekash` is not a reference. With [requireMore], the root alone does not
     * match (`android` as a plain word is not a name).
     */
    fun qualifiedName(vararg roots: String, requireMore: Boolean = false): Regex {
        val dot = """\s*\.\s*"""
        val segment = """`?[A-Za-z_*]\w*`?"""
        val alternatives = roots.joinToString("|") { root -> root.split('.').joinToString(dot) { "`?" + Regex.escape(it) + "`?" } }
        val more = if (requireMore) "+" else "*"
        return Regex("""(?<![\w.`])(?:""" + alternatives + """)(?:""" + dot + segment + ")" + more)
    }

    fun scan(source: String): Result {
        val out = source.toCharArray()
        val frames = ArrayDeque<Frame>().apply { addLast(Frame.Code(inTemplate = false)) }
        var blockDepth = 0
        var inLineComment = false
        var i = 0

        fun blank(from: Int, until: Int) {
            for (k in from until minOf(until, out.size)) if (out[k] != '\n') out[k] = ' '
        }
        fun at(k: Int): Char = if (k < source.length) source[k] else '\u0000'
        fun startsWith(prefix: String): Boolean = source.startsWith(prefix, i)

        while (i < source.length) {
            val c = source[i]
            if (inLineComment) {
                if (c == '\n') inLineComment = false else blank(i, i + 1)
                i++
                continue
            }
            if (blockDepth > 0) {
                when {
                    startsWith("/*") -> { blockDepth++; blank(i, i + 2); i += 2 }
                    startsWith("*/") -> { blockDepth--; blank(i, i + 2); i += 2 }
                    else -> { blank(i, i + 1); i++ }
                }
                continue
            }
            when (val frame = frames.last()) {
                is Frame.Code -> when {
                    startsWith("//") -> { inLineComment = true; blank(i, i + 2); i += 2 }
                    startsWith("/*") -> { blockDepth = 1; blank(i, i + 2); i += 2 }
                    c == '$' -> {
                        // A run of dollars right before a quote is a multi-dollar
                        // string prefix; anywhere else it is code.
                        var end = i
                        while (at(end) == '$') end++
                        if (at(end) == '"') {
                            val raw = source.startsWith("\"\"\"", end)
                            frames.addLast(if (raw) Frame.Raw(end - i) else Frame.Str(end - i))
                            i = end + if (raw) 3 else 1
                        } else {
                            i = end
                        }
                    }
                    startsWith("\"\"\"") -> { frames.addLast(Frame.Raw(1)); i += 3 }
                    c == '"' -> { frames.addLast(Frame.Str(1)); i++ }
                    c == '\'' -> i = skipCharLiteral(source, i, ::blank)
                    c == '`' -> {
                        val close = source.indexOf('`', i + 1)
                        i = if (close < 0) source.length else close + 1
                    }
                    frame.inTemplate && c == '{' -> { frame.braceDepth++; i++ }
                    frame.inTemplate && c == '}' -> {
                        if (frame.braceDepth == 0) frames.removeLast() else frame.braceDepth--
                        i++
                    }
                    else -> i++
                }
                is Frame.Str -> when {
                    c == '\\' -> { blank(i, i + 2); i += 2 }
                    c == '"' -> { frames.removeLast(); i++ }
                    c == '$' -> i = template(frames, frame.dollars, i, ::at, ::blank, source)
                    else -> { blank(i, i + 1); i++ }
                }
                is Frame.Raw -> when {
                    startsWith("\"\"\"") -> {
                        // A run of more than three quotes ends the string at its
                        // last three; the extra quotes belong to the content.
                        var end = i
                        while (at(end) == '"') end++
                        blank(i, end - 3)
                        frames.removeLast()
                        i = end
                    }
                    c == '$' -> i = template(frames, frame.dollars, i, ::at, ::blank, source)
                    else -> { blank(i, i + 1); i++ }
                }
            }
        }
        val endsInCode = blockDepth == 0 && frames.size == 1
        return Result(String(out).split("\n"), endsInCode)
    }

    /**
     * Blanks a character literal starting at [start] (the opening quote); returns the index
     * after it.
     */
    private fun skipCharLiteral(source: String, start: Int, blank: (Int, Int) -> Unit): Int {
        var k = start + 1
        if (k < source.length && source[k] == '\\') k += 2 else k += 1
        // Unicode escapes (\uXXXX) run to the closing quote.
        while (k < source.length && source[k] != '\'' && source[k] != '\n') k++
        blank(start + 1, k)
        return if (k < source.length && source[k] == '\'') k + 1 else k
    }

    /**
     * Scans a run of `$` inside a string whose prefix has [dollars] dollars.
     * With at least that many before `{` or a name it opens a template, whose
     * code is kept (extra leading dollars are text); otherwise the run is text.
     * Returns the index to continue from.
     */
    private fun template(
        frames: ArrayDeque<Frame>,
        dollars: Int,
        start: Int,
        at: (Int) -> Char,
        blank: (Int, Int) -> Unit,
        source: String,
    ): Int {
        var end = start
        while (at(end) == '$') end++
        val run = end - start
        return when {
            run >= dollars && at(end) == '{' -> {
                blank(start, end - dollars)
                frames.addLast(Frame.Code(inTemplate = true))
                end + 1
            }
            run >= dollars && at(end).isIdentifierStart() -> {
                blank(start, end - dollars)
                skipIdentifier(source, end)
            }
            else -> {
                blank(start, end)
                end
            }
        }
    }

    private fun skipIdentifier(source: String, start: Int): Int {
        var k = start
        while (k < source.length && (source[k].isLetterOrDigit() || source[k] == '_')) k++
        return k
    }

    private fun Char.isIdentifierStart(): Boolean = isLetter() || this == '_'

    private sealed interface Frame {
        class Code(val inTemplate: Boolean) : Frame {
            var braceDepth = 0
        }
        /** Marks a quoted string; [dollars] is its `$` prefix length (1 for a plain string). */
        class Str(val dollars: Int) : Frame
        class Raw(val dollars: Int) : Frame
    }
}
