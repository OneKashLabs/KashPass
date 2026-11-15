package org.onekash.kashpass.vault.doc

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.edit.EditFixtures
import org.onekash.kashpass.vault.edit.EditFixtures.NOW
import org.onekash.kashpass.vault.edit.EditFixtures.doc
import org.onekash.kashpass.vault.edit.EditFixtures.entry
import org.onekash.kashpass.vault.edit.EditFixtures.group
import org.onekash.kashpass.vault.edit.EditFixtures.id
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDelete
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.kdbx.Attachment
import org.onekash.kashpass.vault.xml.XmlBytes
import org.onekash.kashpass.vault.xml.XmlElement

class BinaryPoolTest {

    private val a = "A".toByteArray()
    private val b = "B".toByteArray()
    private val c = "C".toByteArray()

    private fun attachment(name: String, ref: Int) = "<Binary><Key>$name</Key><Value Ref=\"$ref\" /></Binary>"

    // Each entry attachment as name=Ref, in document order.
    private fun refs(document: VaultDocument): List<String> = BinaryPool.values(document.xml.root).map {
        it.parent!!.child("Key")!!.text() + "=" + it.attribute("Ref")
    }

    // Each entry attachment as name=content, in document order, the way the saved file names it.
    private fun named(document: VaultDocument): List<String> = BinaryPool.values(document.xml.root).map {
        it.parent!!.child("Key")!!.text() + "=" + String(document.attachments[parseInt32Invariant(it.attribute("Ref"))!!].data)
    }

    private fun contents(attachments: List<Attachment>) = attachments.map { String(it.data) }

    // The pool and each value's Ref as the save writes them.
    private fun saved(document: VaultDocument): Pair<List<String>, List<String>> {
        val rebuilt = BinaryPool.rebuild(document)
        val refs = BinaryPool.values(document.xml.root).map { it.parent!!.child("Key")!!.text() + "=" + (rebuilt.ref(it) ?: it.attribute("Ref")) }
        return contents(rebuilt.attachments) to refs
    }

    @Test
    fun `a dense pool opens with no Ref rewritten and the save keeps every number`() {
        val document = doc(group(10, "G", entry(1, "x", extra = attachment("a", 0) + attachment("b", 1))), attachments = listOf(a, b))
        assertTrue(BinaryPool.values(document.xml.root).none { it.attributesChanged })
        val rebuilt = BinaryPool.rebuild(document)
        assertEquals(document.attachments.size, rebuilt.attachments.size)
        document.attachments.zip(rebuilt.attachments).forEach { (x, y) -> assertSame(x, y) }
        assertTrue(BinaryPool.values(document.xml.root).all { rebuilt.ref(it) == null })
    }

    @Test
    fun `the shared-attachments fixture opens with no Ref rewritten and saves its XML byte for byte`() {
        val file = Fixtures.file(Fixtures.named("keepass2-shared-attachments.kdbx"))
        val read = assertIs<ContainerDecode.Result.Opened>(ContainerRig.open(file)).read
        val source = XmlBytes.text(read.xml)
        val document = VaultXmlCodec.document(read, TestFiles.credentials(file), ContainerRig.LIMITS)
        assertEquals(Saveability.Saveable, document.saveability)
        assertTrue(BinaryPool.values(document.xml.root).none { it.attributesChanged })
        val rebuilt = BinaryPool.rebuild(document)
        assertTrue(BinaryPool.values(document.xml.root).all { rebuilt.ref(it) == null })
        assertEquals(source, XmlBytes.text(document.xml))
    }

    @Test
    fun `the pool takes KeePass 2's order - entries before subgroups, names in ordinal order, then history`() {
        val inner = group(11, "Sub", entry(3, "sub", extra = attachment("z", 4)))
        val history = entry(1, "old", extra = attachment("h", 3)).replace("<History />", "")
        val entries = entry(1, "first", extra = attachment("b", 2) + attachment("B", 1), history = history) + inner + entry(2, "second", extra = attachment("a", 0))
        val document = doc(group(10, "G", entries), attachments = listOf(a, b, c, "H".toByteArray(), "Z".toByteArray()))
        // In the file the subgroup comes between the entries; the pool takes a group's entries
        // first. "B" sorts before "b" in ordinal order.
        val (pool, refs) = saved(document)
        assertEquals(listOf("B", "C", "H", "A", "Z"), pool)
        assertEquals(listOf("b=1", "B=0", "h=2", "z=4", "a=3"), refs)
        val back = EditFixtures.reopened(document)
        assertEquals(named(document), named(back))
        assertEquals(listOf("B", "C", "H", "A", "Z"), contents(back.attachments))
    }

    @Test
    fun `items equal in content and protection flag merge, and a different flag stays a separate item`() {
        val document = doc(group(10, "G", entry(1, "x", extra = attachment("a", 0) + attachment("b", 1) + attachment("c", 2) + attachment("d", 3))), attachments = listOf(a, b, c, "D".toByteArray()))
        val list = listOf(Attachment(false, a.copyOf()), Attachment(false, a.copyOf()), Attachment(true, a.copyOf()), Attachment(false, b.copyOf()))
        val rebuilt = BinaryPool.rebuild(document.xml.root, list)
        assertEquals(listOf(false to "A", true to "A", false to "B"), rebuilt.attachments.map { it.protected to String(it.data) })
        assertSame(list[0], rebuilt.attachments[0])
        val values = BinaryPool.values(document.xml.root)
        assertEquals(listOf(null, "0", "1", "2"), values.map(rebuilt::ref))
    }

    @Test
    fun `an unreferenced item is dropped and later references renumbered, only in the saved file`() {
        val document = doc(group(10, "G", entry(1, "x", extra = attachment("a", 0) + attachment("c", 2))), attachments = listOf(a, b, c))
        assertEquals(listOf("A", "B", "C"), contents(document.attachments))
        val (pool, refs) = saved(document)
        assertEquals(listOf("A", "C"), pool)
        assertEquals(listOf("a=0", "c=1"), refs)
        assertEquals(listOf("a=0", "c=2"), refs(document), "the tree is not changed")
        val back = EditFixtures.reopened(document)
        assertEquals(listOf("A", "C"), contents(back.attachments))
        assertEquals(listOf("a=A", "c=C"), named(back))
        assertEquals(Saveability.Saveable, back.saveability)
    }

    @Test
    fun `a history trim that drops the last reference to an attachment drops it at save`() {
        val old = entry(1, "old", extra = attachment("only-in-history", 1)).replace("<History />", "")
        val document = doc(
            group(10, "G", entry(1, "current", extra = attachment("kept", 0), history = old) + entry(2, "other", extra = attachment("later", 2))),
            meta = "<HistoryMaxItems>0</HistoryMaxItems>",
            attachments = listOf(a, b, c),
        )
        val draft = EntryEdits.draftOf(document, id(1))!!
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(document, id(1), EntryDraft("changed", draft.userName, draft.password, "", ""), NOW)).document
        assertSame(document.attachments, edited.attachments, "an edit keeps the list the session and an UNDO hold")
        val back = EditFixtures.reopened(edited)
        assertEquals(listOf("A", "C"), contents(back.attachments))
        assertEquals(listOf("kept=A", "later=C"), named(back))
    }

    @Test
    fun `a history snapshot of an entry with a shared attachment keeps its content`() {
        val document = doc(
            group(10, "G", entry(1, "one", extra = attachment("shared", 1)) + entry(2, "two", extra = attachment("shared", 1) + attachment("own", 0))),
            attachments = listOf(a, b),
        )
        val draft = EntryEdits.draftOf(document, id(1))!!
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(document, id(1), EntryDraft("new", draft.userName, draft.password, "", ""), NOW)).document
        val back = EditFixtures.reopened(edited)
        assertEquals(listOf("shared=B", "shared=B", "shared=B", "own=A"), named(back))
        assertEquals(listOf("B", "A"), contents(back.attachments))
    }

    @Test
    fun `two consecutive saves after a merge keep every attachment's content`() {
        val case = Corpus.all.single { it.name == "attachment-identical-pool-items" }
        val file = case.file()
        val document = VaultXmlCodec.open(case.bytes, TestFiles.credentials(file), ContainerRig.LIMITS)
        assertEquals(Saveability.Saveable, document.saveability)
        val before = named(document)
        val once = VaultXmlCodec.open(VaultXmlCodec.encodeBytes(document), TestFiles.credentials(file), ContainerRig.LIMITS)
        assertEquals(before, named(once))
        assertTrue(once.attachments.size < document.attachments.size, "identical items merged")
        val twice = VaultXmlCodec.open(VaultXmlCodec.encodeBytes(once), TestFiles.credentials(file), ContainerRig.LIMITS)
        assertEquals(before, named(twice))
        // The save zero-filled none of the first document's arrays: it reads as before.
        assertEquals(before, named(document))
    }

    @Test
    fun `a Meta Binaries item that replaces item 0 after the entries leaves each reference its original content`() {
        val case = Corpus.all.single { it.name == "spec-meta-binary-after-root-replaces-0" }
        val file = case.file()
        val read = assertIs<ContainerDecode.Result.Opened>(ContainerRig.open(file)).read
        val resolved = read.references.entries.filter { it.value != null }.map { it.key to it.value!!.data.copyOf() }
        val document = VaultXmlCodec.document(read, TestFiles.credentials(file), ContainerRig.LIMITS)
        assertEquals(Saveability.Saveable, document.saveability)
        for ((value, data) in resolved) assertContentEquals(data, document.attachments[parseInt32Invariant(value.attribute("Ref"))!!].data)
        val back = VaultXmlCodec.open(VaultXmlCodec.encodeBytes(document), TestFiles.credentials(file), ContainerRig.LIMITS)
        assertEquals(named(document), named(back))
        assertTrue(contents(back.attachments).none { it == "replaced codes" }, "the replacing item is unreferenced and dropped")
    }

    @Test
    fun `an unreferenced pool item opens editable and is dropped on save`() {
        val case = Corpus.all.single { it.name == "attachment-unreferenced-pool-item" }
        val file = case.file()
        val document = VaultXmlCodec.open(case.bytes, TestFiles.credentials(file), ContainerRig.LIMITS)
        assertEquals(Saveability.Saveable, document.saveability)
        assertTrue(contents(document.attachments).contains("unreferenced"))
        val back = VaultXmlCodec.open(VaultXmlCodec.encodeBytes(document), TestFiles.credentials(file), ContainerRig.LIMITS)
        assertTrue(contents(back.attachments).none { it == "unreferenced" })
        assertEquals(named(document), named(back))
    }

    @Test
    fun `a sparse Meta Binaries pool is renumbered at open, so Ref n names attachment n`() {
        val case = Corpus.all.single { it.name == "spec-meta-binary-sparse-id" }
        val document = VaultXmlCodec.open(case.bytes, TestFiles.credentials(case.file()), ContainerRig.LIMITS)
        assertEquals(Saveability.Saveable, document.saveability)
        val numbers = BinaryPool.values(document.xml.root).map { parseInt32Invariant(it.attribute("Ref"))!! }
        assertTrue(numbers.all { it in document.attachments.indices }, numbers.toString())
        assertTrue(BinaryPool.values(document.xml.root).any { it.attributesChanged })
    }

    @Test
    fun `a Ref that named no item when read stays read-only, and a deleted entry's attachment leaves the saved file`() {
        val dangling = Corpus.all.single { it.name == "spec-meta-binary-after-root-new-id" }
        val read = VaultXmlCodec.open(dangling.bytes, TestFiles.credentials(dangling.file()), ContainerRig.LIMITS)
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.ATTACHMENT_REF_OUT_OF_RANGE), read.saveability)
        val document = doc(group(10, "G", entry(1, "x", extra = attachment("a", 0)) + entry(2, "y", extra = attachment("b", 1))), meta = "<RecycleBinEnabled>False</RecycleBinEnabled>", attachments = listOf(a, b))
        val deleted = EntryDelete.delete(document, id(1), NOW)!!.document
        assertSame(document.attachments, deleted.attachments)
        val back = EditFixtures.reopened(deleted)
        assertEquals(listOf("B"), contents(back.attachments))
        assertEquals(listOf("b=B"), named(back))
        assertEquals("A", String(document.attachments[0].data), "the session's arrays are left as they are")
    }

    @Test
    fun `only the last Value of a Binary counts - an item only an earlier Value names is not saved`() {
        val two = "<Binary><Key>k</Key><Value Ref=\"1\" /><Value Ref=\"0\" /></Binary>"
        val document = doc(group(10, "G", entry(1, "x", extra = two)), attachments = listOf(a, b))
        assertEquals(listOf("k=A"), named(document))
        val (pool, refs) = saved(document)
        assertEquals(listOf("A"), pool)
        assertEquals(listOf("k=0"), refs)
        assertEquals(listOf("k=A"), named(EditFixtures.reopened(document)))
    }

    @Test
    fun `a Ref that named no item leaves the document read-only only in a Value the save writes`() {
        fun saveability(values: String) = doc(group(10, "G", entry(1, "x", extra = "<Binary><Key>k</Key>$values</Binary>")), attachments = listOf(a)).saveability
        assertEquals(Saveability.Saveable, saveability("<Value Ref=\"5\" /><Value Ref=\"0\" />"))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.ATTACHMENT_REF_OUT_OF_RANGE), saveability("<Value Ref=\"0\" /><Value Ref=\"5\" />"))
    }

    @Test
    fun `an inline attachment value stays inline and the document stays editable`() {
        val inline = "<Binary><Key>inline</Key><Value>${java.util.Base64.getEncoder().encodeToString(c)}</Value></Binary>"
        val document = doc(group(10, "G", entry(1, "x", extra = attachment("a", 0) + inline)), attachments = listOf(a))
        assertEquals(Saveability.Saveable, document.saveability)
        val back = EditFixtures.reopened(document)
        val value = back.xml.root.let { root ->
            fun find(e: XmlElement): XmlElement? = if (e.name == "Binary" && e.child("Key")?.text() == "inline") e else e.elements().firstNotNullOfOrNull(::find)
            find(root)!!.child("Value")!!
        }
        assertNull(value.attribute("Ref"))
        assertEquals(java.util.Base64.getEncoder().encodeToString(c), value.text())
    }
}
