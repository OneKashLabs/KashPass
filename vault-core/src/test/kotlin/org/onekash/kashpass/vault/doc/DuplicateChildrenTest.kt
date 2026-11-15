package org.onekash.kashpass.vault.doc

import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.edit.EditFixtures.NOW
import org.onekash.kashpass.vault.edit.EditFixtures.doc
import org.onekash.kashpass.vault.edit.EditFixtures.entry
import org.onekash.kashpass.vault.edit.EditFixtures.entryElement
import org.onekash.kashpass.vault.edit.EditFixtures.group
import org.onekash.kashpass.vault.edit.EditFixtures.id
import org.onekash.kashpass.vault.edit.EditFixtures.reopened
import org.onekash.kashpass.vault.edit.EditFixtures.times
import org.onekash.kashpass.vault.edit.EditFixtures.uuid
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.edit.HistoryTrim
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.VaultIndex
import org.onekash.kashpass.vault.keepass2.DocumentReport
import org.onekash.kashpass.vault.keepass2.KeePass2Report
import org.onekash.kashpass.vault.keepass2.KeePass2Run
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * Entry `String` and `Binary` elements with repeated `Key` or `Value` children, and entries with
 * two or more `History` blocks, read and saved by these rules: the last `Key` and the last `Value`
 * of each String and Binary, every History block's entries as one list in document order, and no
 * History inside a history entry. No known writer writes these shapes; the tests build them in
 * code.
 *
 * Separate String elements with the same Key are written as they are: both values take the inner
 * stream in order, and the last one wins.
 */
class DuplicateChildrenTest {

    private val a = "A".toByteArray()
    private val b = "B".toByteArray()

    private fun edited(document: VaultDocument, n: Int, title: String): VaultDocument {
        val draft = EntryEdits.draftOf(document, id(n))!!
        val result = EntryEdits.edit(document, id(n), EntryDraft(title, draft.userName, draft.password, draft.url, draft.notes), NOW)
        return assertIs<EditResult.Changed>(result).document
    }

    // The attachment content each of [entry]'s Binary elements names, by the last Key and the
    // last Value.
    private fun attachments(document: VaultDocument, entry: XmlElement): Map<String, String> = entry.children("Binary").associate { binary ->
        val ref = binary.children("Value").last().attribute("Ref")!!
        binary.children("Key").last().text() to String(document.attachments[parseInt32Invariant(ref)!!].data)
    }

    private fun title(document: VaultDocument, entry: XmlElement): String =
        (EntryView(entry, document).fields().last { it.key == "Title" }.value as FieldText.Plain).text

    private fun historyTitles(document: VaultDocument, n: Int): List<String> =
        entryElement(document, n).children("History").flatMap { it.children("Entry") }.map { title(document, it) }

    @Test
    fun `a stale attachment Value is not saved, so a later protected value keeps its stream`() {
        val binary = "<Binary><Key>codes.txt</Key><Value Ref=\"0\" /><Value Ref=\"1\" Protected=\"True\">AAAA</Value></Binary>"
        val document = doc(group(10, "G", entry(1, "one", extra = binary) + entry(2, "two")), attachments = listOf(a, b))
        assertEquals(Saveability.Saveable, document.saveability)
        val back = reopened(edited(document, 1, "one edited"))
        assertEquals("pass2", EntryEdits.draftOf(back, id(2))!!.password.reveal())

        assertEquals(mapOf("codes.txt" to "B"), attachments(document, entryElement(document, 1)), "KeePass 2 reads the last Value")
        assertEquals(listOf("codes.txt=B"), BinaryPool.values(document.xml.root).map { it.parent!!.child("Key")!!.text() + "=" + String(document.attachments[parseInt32Invariant(it.attribute("Ref"))!!].data) })
        assertEquals(mapOf("codes.txt" to "B"), attachments(back, entryElement(back, 1)))
        val saved = entryElement(back, 1).child("Binary")!!
        assertEquals(1, saved.children("Value").size, "the save writes one Value")
        assertEquals(listOf("codes.txt=B", "codes.txt=B"), BinaryPool.values(back.xml.root).map { it.parent!!.child("Key")!!.text() + "=" + String(back.attachments[parseInt32Invariant(it.attribute("Ref"))!!].data) })
        assertEquals(Saveability.Saveable, back.saveability)
    }

    @Test
    fun `a String with two Values shows, edits and saves the last one`() {
        val entry = "<Entry><UUID>${uuid(1)}</UUID>${times()}<String><Key>Title</Key><Value>t</Value></String>" +
            "<String><Key>Password</Key><Value Protected=\"True\">{{p:first}}</Value><Value Protected=\"True\">{{p:second}}</Value></String>" +
            "<String><Key>UserName</Key><Key>Login</Key><Value>u</Value></String>" +
            "<String><Key>Later</Key><Value Protected=\"True\">{{p:later}}</Value></String><History /></Entry>"
        val document = doc(group(10, "G", entry))
        assertEquals("second", EntryEdits.draftOf(document, id(1))!!.password.reveal())
        val fields = EntryView(entryElement(document, 1), document).fields().associate { it.key to it.value }
        assertEquals(setOf("Title", "Password", "Login", "Later"), fields.keys, "the last Key names the field")

        val back = reopened(edited(document, 1, "t2"))
        val element = entryElement(back, 1)
        assertEquals("second", EntryEdits.draftOf(back, id(1))!!.password.reveal())
        assertEquals("t2", EntryEdits.draftOf(back, id(1))!!.title)
        for (string in element.children("String")) {
            assertEquals(1, string.children("Key").size)
            assertEquals(1, string.children("Value").size)
        }
        val later = element.children("String").single { it.child("Key")!!.text() == "Later" }.child("Value")!!
        assertEquals("later", back.protectedValues[later]!!.reveal())
        val snapshot = element.child("History")!!.child("Entry")!!
        val oldPassword = snapshot.children("String").single { it.child("Key")!!.text() == "Password" }.child("Value")!!
        assertEquals("second", back.protectedValues[oldPassword]!!.reveal())
    }

    @Test
    fun `an edit sets the last Value of a String with two Values`() {
        val entry = "<Entry><UUID>${uuid(1)}</UUID>${times()}<String><Key>Title</Key><Value>first</Value><Value>second</Value></String><History /></Entry>"
        val document = doc(group(10, "G", entry))
        assertEquals("second", EntryEdits.draftOf(document, id(1))!!.title)
        val back = reopened(edited(document, 1, "third"))
        assertEquals("third", EntryEdits.draftOf(back, id(1))!!.title)
        assertEquals(listOf("second"), historyTitles(back, 1))
    }

    @Test
    fun `separate Strings with the same Key show the last and are written as they are`() {
        val entry = "<Entry><UUID>${uuid(1)}</UUID>${times()}<String><Key>Title</Key><Value>t</Value></String>" +
            "<String><Key>Password</Key><Value Protected=\"True\">{{p:first}}</Value></String>" +
            "<String><Key>Password</Key><Value Protected=\"True\">{{p:second}}</Value></String>" +
            "<String><Key>Later</Key><Value Protected=\"True\">{{p:later}}</Value></String><History /></Entry>"
        val document = doc(group(10, "G", entry))
        assertEquals("second", EntryEdits.draftOf(document, id(1))!!.password.reveal())
        val back = reopened(edited(document, 1, "t2"))
        val element = entryElement(back, 1)
        assertEquals(2, element.children("String").count { it.child("Key")!!.text() == "Password" })
        assertEquals("second", EntryEdits.draftOf(back, id(1))!!.password.reveal())
        val later = element.children("String").single { it.child("Key")!!.text() == "Later" }.child("Value")!!
        assertEquals("later", back.protectedValues[later]!!.reveal())
    }

    // History items in file order: H1 holds a (2019) and b (2020), H2 holds c (2021).
    private fun item(title: String, year: Int) = entry(1, title, at = Instant.parse("$year-06-01T00:00:00Z")).replace("<History />", "")

    private fun twoBlocks(meta: String = "<Generator>test</Generator>"): VaultDocument {
        val current = entry(1, "current", at = Instant.parse("2022-06-01T00:00:00Z"), history = item("a", 2019) + item("b", 2020))
            .replace("</History>", "</History><History>${item("c", 2021)}</History>")
        return doc(group(10, "G", current), meta = meta)
    }

    @Test
    fun `an edit appends the snapshot to the last History block, with no History of its own`() {
        val document = twoBlocks()
        assertEquals(listOf("a", "b", "c"), historyTitles(document, 1))
        val edited = edited(document, 1, "new")
        assertEquals(listOf("a", "b", "c", "current"), historyTitles(edited, 1))
        val blocks = entryElement(edited, 1).children("History")
        assertEquals(listOf(2, 2), blocks.map { it.children("Entry").size })
        assertNull(blocks.last().children("Entry").last().child("History"), "a snapshot has no history of its own")
        val back = reopened(edited)
        assertEquals(listOf("a", "b", "c", "current"), historyTitles(back, 1))
        assertTrue(entryElement(back, 1).children("History").flatMap { it.children("Entry") }.all { it.child("History") == null })
    }

    @Test
    fun `the history trim counts and removes across every History block, oldest first`() {
        val document = twoBlocks("<HistoryMaxItems>3</HistoryMaxItems><HistoryMaxSize>-1</HistoryMaxSize>")
        val edited = edited(document, 1, "new")
        assertEquals(listOf("b", "c", "current"), historyTitles(edited, 1))
        // The size estimate counts every block's items, as one History holding all three.
        val oneBlock = doc(group(10, "G", entry(1, "current", at = Instant.parse("2022-06-01T00:00:00Z"), history = item("a", 2019) + item("b", 2020) + item("c", 2021))))
        val sized = twoBlocks()
        assertEquals(HistoryTrim.size(oneBlock, entryElement(oneBlock, 1)), HistoryTrim.size(sized, entryElement(sized, 1)))
    }

    @Test
    @EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
    fun `KeePass 2 reads each corpus shape as KashPass does, before and after an edit of every entry and a save`() {
        val cases = Corpus.all.filter { it.name in SHAPES }
        assertEquals(SHAPES, cases.map { it.name }.toSet())
        val key = KeePass2Run.newKey()
        val expected = LinkedHashMap<String, KeePass2Report>()
        val files = ArrayList<VaultFile>()
        for (case in cases) {
            val file = case.file()
            val opened = VaultXmlCodec.open(file.bytes, TestFiles.credentials(file), ContainerRig.LIMITS)
            assertEquals(Saveability.Saveable, opened.saveability, case.name)
            expected[file.name] = DocumentReport.of(file, key)
            var edited = opened
            for (row in VaultIndex.from(opened).rows(Chip.All, "")) {
                val draft = EntryEdits.draftOf(edited, row.id)!!
                val result = EntryEdits.edit(edited, row.id, EntryDraft(draft.title + " edited", draft.userName, draft.password, draft.url, draft.notes), NOW)
                edited = assertIs<EditResult.Changed>(result, case.name).document
            }
            val saved = VaultFile("saved-${file.name}", VaultXmlCodec.encodeBytes(edited), file.mode, file.keyFileName, file.keyFile)
            expected[saved.name] = DocumentReport.of(edited, key)
            files += file
            files += saved
        }
        val reports = KeePass2Run.keepass2(files, key)
        val problems = expected.mapNotNull { (name, report) ->
            KeePass2Report.diff(report, reports.getValue(name)).takeIf { it.isNotEmpty() }?.let { "$name:\n  " + it.joinToString("\n  ") }
        }
        if (problems.isNotEmpty()) fail("${problems.size} files:\n" + problems.joinToString("\n"))
    }

    private companion object {
        // The corpus cases of these shapes, built from a KeePass 2 fixture.
        val SHAPES = setOf(
            "xml-string-value-twice",
            "xml-string-key-twice",
            "xml-string-same-key-twice",
            "xml-binary-value-twice",
            "xml-binary-key-twice",
            "xml-history-two-blocks",
            "xml-history-in-history-entry",
        )
    }
}
