package org.onekash.kashpass.vault.index

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class SearchTermsTest {

    @Test
    fun `split separates on space, tab, CR and LF and drops empty words`() {
        assertEquals(listOf("bank", "login"), SearchTerms.split("bank login"))
        assertEquals(listOf("a", "b", "c", "d"), SearchTerms.split("a\tb\rc\nd"))
        assertEquals(listOf("a", "b"), SearchTerms.split("   a  \t\r\n  b   "))
        assertEquals(emptyList(), SearchTerms.split(" \t\r\n "))
        assertEquals(emptyList(), SearchTerms.split(""))
    }

    @Test
    fun `other whitespace does not separate words`() {
        assertEquals(listOf("a b", "c d"), SearchTerms.split("a b c d"))
    }

    @Test
    fun `a double quote toggles quoting and is dropped, also mid-word`() {
        assertEquals(listOf("bank login", "x"), SearchTerms.split("\"bank login\" x"))
        assertEquals(listOf("abc de"), SearchTerms.split("ab\"c d\"e"))
        assertEquals(listOf(" a "), SearchTerms.split("\" a \""))
        assertEquals(emptyList(), SearchTerms.split("\"\""))
        assertEquals(emptyList(), SearchTerms.split("\"\" \"\""))
    }

    @Test
    fun `an unterminated quote runs to the end, keeping its spaces`() {
        assertEquals(listOf("a", "b c "), SearchTerms.split("a \"b c "))
    }

    @Test
    fun `a word of two or more characters starting with a minus excludes, a lone minus is a word`() {
        val q = SearchTerms.parse("mail -bank - \"-old\"")
        assertEquals(listOf("mail", "-"), q.include)
        assertEquals(listOf("bank", "old"), q.exclude)
        assertEquals(listOf("--x".substring(1)), SearchTerms.parse("--x").exclude)
    }

    @Test
    fun `fold ignores case and accents`() {
        assertEquals("cafe", SearchTerms.fold("CAFÉ"))
        assertEquals("cafe", SearchTerms.fold("Café"))
        assertEquals("istanbul", SearchTerms.fold("İstanbul"))
        assertEquals("straße", SearchTerms.fold("STRAßE"))
        assertEquals("σσ", SearchTerms.fold("ΣΣ"))
    }

    @Test
    fun `fold drops nonspacing, enclosing and spacing combining marks`() {
        assertEquals("a", SearchTerms.fold("á"))
        assertEquals("a", SearchTerms.fold("a⃝"))
        // DEVANAGARI KA + VOWEL SIGN AA (Mc).
        assertEquals("क", SearchTerms.fold("का"))
    }

    @Test
    fun `every included word must occur in some field, in any order and in different fields`() {
        val fields = listOf("Example Bank", "alice", "online login page")
        assertTrue(SearchTerms.matches(SearchTerms.parse("login bank"), folded(fields)))
        assertTrue(SearchTerms.matches(SearchTerms.parse("BANK ALICE"), folded(fields)))
        assertFalse(SearchTerms.matches(SearchTerms.parse("bank bob"), folded(fields)))
        assertFalse(SearchTerms.matches(SearchTerms.parse("\"bank login\""), folded(fields)))
        assertTrue(SearchTerms.matches(SearchTerms.parse("\"online login\""), folded(fields)))
    }

    @Test
    fun `an excluded word in any field rejects the entry`() {
        val fields = folded(listOf("Example Bank", "alice"))
        assertFalse(SearchTerms.matches(SearchTerms.parse("example -alice"), fields))
        assertTrue(SearchTerms.matches(SearchTerms.parse("example -bob"), fields))
        assertTrue(SearchTerms.matches(SearchTerms.parse("-bob"), fields))
    }

    @Test
    fun `a query with no words matches everything`() {
        assertTrue(SearchTerms.matches(SearchTerms.parse("\"\""), folded(listOf("x"))))
        assertTrue(SearchTerms.matches(SearchTerms.parse("\"\""), emptyList()))
    }

    @Test
    fun `a word that folds to nothing occurs everywhere, so its negation excludes everything`() {
        assertTrue(SearchTerms.matches(SearchTerms.parse("́"), folded(listOf("x"))))
        assertFalse(SearchTerms.matches(SearchTerms.parse("-́"), folded(listOf("x"))))
    }

    @Test
    fun `accents match either way`() {
        assertTrue(SearchTerms.matches(SearchTerms.parse("cafe"), folded(listOf("Café Noir"))))
        assertTrue(SearchTerms.matches(SearchTerms.parse("CAFÉ"), folded(listOf("cafe"))))
        assertTrue(SearchTerms.matches(SearchTerms.parse("istanbul"), folded(listOf("İstanbul office"))))
    }

    private fun folded(fields: List<String>) = fields.map(SearchTerms::fold)
}
