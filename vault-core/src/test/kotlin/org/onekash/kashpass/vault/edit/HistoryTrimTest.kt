package org.onekash.kashpass.vault.edit

import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertIs
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.onekash.kashpass.vault.edit.EditFixtures.NOW
import org.onekash.kashpass.vault.edit.EditFixtures.doc
import org.onekash.kashpass.vault.edit.EditFixtures.entry
import org.onekash.kashpass.vault.edit.EditFixtures.entryElement
import org.onekash.kashpass.vault.edit.EditFixtures.group
import org.onekash.kashpass.vault.edit.EditFixtures.id

class HistoryTrimTest {

    // History in file order: 2022, 2019, 2021 (not chronological), then the snapshot (2020).
    private fun item(title: String, year: Int) = entry(1, title, at = Instant.parse("$year-06-01T00:00:00Z")).replace("<History />", "")
    private val history = item("v2022", 2022) + item("v2019", 2019) + item("v2021", 2021)

    private fun titlesAfterEdit(meta: String): List<String> {
        val vault = doc(group(10, "General", entry(1, "current", history = history)), meta = meta)
        val draft = EntryEdits.draftOf(vault, id(1))!!
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), EntryDraft("changed", draft.userName, draft.password, "", ""), NOW)).document
        return entryElement(edited, 1).child("History")!!.children("Entry").map { e ->
            e.children("String").first { it.child("Key")!!.text() == "Title" }.child("Value")!!.text()
        }
    }

    @ParameterizedTest
    @CsvSource(
        // max items, expected history (oldest LastModificationTime removed first)
        "-1, v2022 v2019 v2021 current",
        "10, v2022 v2019 v2021 current",
        "4, v2022 v2019 v2021 current",
        "3, v2022 v2021 current",
        "2, v2022 v2021",
        "1, v2022",
        "0, ''",
    )
    fun `history is trimmed to HistoryMaxItems, oldest first`(max: Int, expected: String) {
        val meta = "<HistoryMaxItems>$max</HistoryMaxItems><HistoryMaxSize>-1</HistoryMaxSize>"
        assertEquals(expected.split(' ').filter { it.isNotEmpty() }, titlesAfterEdit(meta))
    }

    @Test
    fun `history is trimmed to HistoryMaxSize after the item limit`() {
        // Each item here is about 470 bytes: 276 + 3 * 40 + 2 * 36 characters.
        assertEquals(emptyList(), titlesAfterEdit("<HistoryMaxItems>-1</HistoryMaxItems><HistoryMaxSize>100</HistoryMaxSize>"))
        assertEquals(listOf("v2022", "v2021", "current"), titlesAfterEdit("<HistoryMaxItems>3</HistoryMaxItems><HistoryMaxSize>-1</HistoryMaxSize>"))
        assertEquals(listOf("v2022"), titlesAfterEdit("<HistoryMaxItems>-1</HistoryMaxItems><HistoryMaxSize>700</HistoryMaxSize>"))
    }

    @Test
    fun `missing limits use KeePass 2's defaults of 10 items and 6 MiB`() {
        assertEquals(listOf("v2022", "v2019", "v2021", "current"), titlesAfterEdit(""))
    }

    @Test
    fun `the size estimate follows KeePass 2's GetSize`() {
        val vault = doc(group(10, "G", "<Entry><UUID>${EditFixtures.uuid(1)}</UUID><String><Key>Title</Key><Value>ab</Value></String></Entry>"))
        // 276 fixed + 40 per string; characters: "Title" + "ab" = 7, two bytes each.
        assertEquals(276L + 40 + 14, HistoryTrim.size(vault, entryElement(vault, 1)))
        val protectedOne = doc(group(10, "G", "<Entry><UUID>${EditFixtures.uuid(1)}</UUID><String><Key>P</Key><Value Protected=\"True\">{{p:é😀}}</Value></String><Tags>a;bc</Tags></Entry>"))
        // "P" + "é😀" (3 UTF-16 units) = 4 chars; tags: 2 * 8 bytes + 3 chars.
        assertEquals(276L + 40 + 16 + 2 * (4 + 3), HistoryTrim.size(protectedOne, entryElement(protectedOne, 1)))
        val attached = doc(
            group(10, "G", "<Entry><UUID>${EditFixtures.uuid(1)}</UUID><Binary><Key>f</Key><Value Ref=\"0\" /></Binary></Entry>"),
            attachments = listOf(ByteArray(1000)),
        )
        assertEquals(276L + 65 + 1000 + 2, HistoryTrim.size(attached, entryElement(attached, 1)))
    }

    @Test
    fun `the size estimate counts each field and attachment name once, by its last Key and Value`() {
        val repeated = doc(
            group(
                10, "G",
                "<Entry><UUID>${EditFixtures.uuid(1)}</UUID><String><Key>Title</Key><Value>ab</Value></String>" +
                    "<String><Key>Title</Key><Value>abcd</Value><Value>abc</Value></String>" +
                    "<Binary><Key>f</Key><Value Ref=\"0\" /></Binary><Binary><Key>x</Key><Key>f</Key><Value Ref=\"0\" /><Value Ref=\"1\" /></Binary></Entry>",
            ),
            attachments = listOf(ByteArray(1000), ByteArray(10)),
        )
        // One field: "Title" + "abc" = 8 chars; one attachment "f" of 10 bytes, 1 char.
        assertEquals(276L + 40 + 65 + 10 + 2 * (8 + 1), HistoryTrim.size(repeated, entryElement(repeated, 1)))
    }
}
