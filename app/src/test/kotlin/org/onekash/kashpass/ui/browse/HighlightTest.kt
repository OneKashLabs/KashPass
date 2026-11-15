package org.onekash.kashpass.ui.browse

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import org.junit.Assert.assertEquals
import org.junit.Test

class HighlightTest {

    private val style = matchStyle(Color.Yellow)

    private fun spans(text: String, range: IntRange?, prefix: String = "") =
        highlighted(text, range, style, prefix).let { a -> a.spanStyles.map { a.text.substring(it.start, it.end) } to a.text }

    @Test
    fun `the range is styled and the text is unchanged`() {
        assertEquals(listOf("mail") to "URL · mail.example", spans("mail.example", 0..3, prefix = "URL · "))
    }

    @Test
    fun `the match is bold on the given background`() {
        val span = highlighted("mail.example", 0..3, style).spanStyles.single().item
        assertEquals(FontWeight.Bold, span.fontWeight)
        assertEquals(Color.Yellow, span.background)
    }

    @Test
    fun `no, empty or out-of-bounds ranges give plain text`() {
        for (range in listOf(null, 0 until 0, 3..20, -1..2)) assertEquals("$range", emptyList<String>() to "abcde", spans("abcde", range))
    }
}
