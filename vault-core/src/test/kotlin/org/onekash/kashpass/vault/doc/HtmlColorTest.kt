package org.onekash.kashpass.vault.doc

import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/** ColorTranslator.FromHtml as .NET Framework 4.8 runs it, with the list separator ','. */
class HtmlColorTest {

    @Test
    fun `a # form with 6 or 3 characters takes hex pairs, a + sign and leading zeros as Convert does`() {
        for (c in listOf("#FF8000", "#ff8000", "#f80", "#+1+1+1", "#000000001", "#+0x1F")) assertTrue(HtmlColor.accepts(c), c)
        // Convert.ToInt32 takes "0x" as a prefix, so "0x" alone has no digits.
        for (c in listOf("#GG0000", "#f8g", "#-1-1-1", "# F F F", "#0x", "#0x0x0x")) assertFalse(HtmlColor.accepts(c), c)
    }

    @Test
    fun `Color and SystemColors names match in any case, HTML system names only as written lower`() {
        for (c in listOf("Red", "red", "LIGHTGREY", "LightGray", "Transparent", "ButtonFace", "threeddarkshadow", "Control", " Red ")) {
            assertTrue(HtmlColor.accepts(c), c)
        }
        // The HTML system color table is matched without trimming; ColorConverter's names are not
        // lower-case HTML names.
        for (c in listOf("NotAColor", "RebeccaPurple", "Empty")) assertFalse(HtmlColor.accepts(c), c)
        for (c in listOf("'any'", "\"any\"", "''")) assertTrue(HtmlColor.accepts(c), c)
    }

    @Test
    fun `one integer or 3 or 4 integers from 0 to 255 split by commas are colors`() {
        for (c in listOf("0", "-1", "16777215", "#12345", "0xFF00FF00", "&hFF", "1,2,3", "255, 0 ,0", "1,2,3,4", "+5")) {
            assertTrue(HtmlColor.accepts(c), c)
        }
        for (c in listOf("1,2", "1,2,3,4,5", "256,0,0", "-1,0,0", "1,,3", "2147483648", "0x123456789", "1.5", "12a", "0x-1", "#1FFFFFFFF", "+0x1F")) {
            assertFalse(HtmlColor.accepts(c), c)
        }
    }
}
