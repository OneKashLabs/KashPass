package org.onekash.kashpass.ui.browse

import org.junit.Assert.assertEquals
import org.junit.Test
import org.onekash.kashpass.vault.index.EntryRow

class ListEntriesTest {

    private fun row(title: String?, id: String = title ?: "untitled") = EntryRow(id, title, "", null, inRecycleBin = false)

    private fun shape(entries: List<ListEntry>) = entries.map {
        when (it) {
            is ListEntry.Header -> "[${it.letter}]"
            is ListEntry.Row -> it.row.title ?: "-"
        }
    }

    @Test
    fun `a header starts each run of titles with the same first letter, in the rows' order`() {
        val rows = listOf(row("Amazon"), row("apple id"), row("Bank"), row("eMail"), row("Example"))
        assertEquals(listOf("[A]", "Amazon", "apple id", "[B]", "Bank", "[E]", "eMail", "Example"), shape(withLetterHeaders(rows)))
    }

    @Test
    fun `titles starting with a digit or symbol, and untitled entries, sit under the hash header`() {
        val rows = listOf(row("1Password import"), row("@home"), row("Zoom"), row(null))
        assertEquals(listOf("[#]", "1Password import", "@home", "[Z]", "Zoom", "[#]", "-"), shape(withLetterHeaders(rows)))
    }

    @Test
    fun `every header and row has its own key, also when a letter repeats`() {
        val entries = withLetterHeaders(listOf(row("1x"), row("Zoom"), row(null)))
        assertEquals(entries.size, entries.map { it.key }.toSet().size)
    }

    @Test
    fun `the initial is the uppercased first letter, or the hash for anything else`() {
        assertEquals("E", initialOf("example"))
        assertEquals("Ü", initialOf("über"))
        assertEquals("#", initialOf("42"))
        assertEquals("#", initialOf(null))
        assertEquals("#", initialOf("🔑 key"))
    }
}
