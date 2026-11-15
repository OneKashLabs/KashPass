package org.onekash.kashpass.vault.edit

import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.KdbxTime
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.edit.EditFixtures.NOW
import org.onekash.kashpass.vault.edit.EditFixtures.T0
import org.onekash.kashpass.vault.edit.EditFixtures.doc
import org.onekash.kashpass.vault.edit.EditFixtures.entry
import org.onekash.kashpass.vault.edit.EditFixtures.entryElement
import org.onekash.kashpass.vault.edit.EditFixtures.group
import org.onekash.kashpass.vault.edit.EditFixtures.id
import org.onekash.kashpass.vault.edit.EditFixtures.reopened
import org.onekash.kashpass.vault.edit.EditFixtures.time
import org.onekash.kashpass.vault.edit.EditFixtures.uuid
import org.onekash.kashpass.vault.edit.EditFixtures.xml
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.xml.XmlElement

class DeleteEntryTest {

    private val binMeta = "<RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>${uuid(30)}</RecycleBinUUID><RecycleBinChanged>${EditFixtures.t(T0)}</RecycleBinChanged>"
    private val history = entry(1, "older").replace("<History />", "")

    private fun vault(meta: String = binMeta, minor: Int = 0, attachments: List<ByteArray> = emptyList(), extra: String = "") = doc(
        group(10, "General", entry(1, "Bank", history = history, extra = extra) + entry(2, "Mail")) +
            group(30, "Recycle Bin", entry(3, "Gone") + group(31, "Old", entry(4, "Older")), icon = 43),
        meta = meta,
        attachments = attachments,
        minor = minor,
    )

    private fun groupNamed(document: VaultDocument, name: String): XmlElement {
        fun find(e: XmlElement): XmlElement? = if (e.name == "Group" && e.child("Name")?.text() == name) e else e.elements().firstNotNullOfOrNull(::find)
        return find(document.xml.root)!!
    }

    private fun rootGroup(document: VaultDocument) = document.xml.root.child("Root")!!.child("Group")!!

    @Test
    fun `an entry outside the bin moves to the end of the bin with KeePass 2's times`() {
        val document = vault()
        assertEquals(DeleteKind.TO_RECYCLE_BIN, EntryDelete.kindOf(document, id(1)))
        val deleted = EntryDelete.delete(document, id(1), NOW)!!
        assertEquals(DeleteKind.TO_RECYCLE_BIN, deleted.kind)
        val bin = groupNamed(deleted.document, "Recycle Bin")
        assertEquals(listOf(uuid(3), uuid(1)), bin.children("Entry").map { it.child("UUID")!!.text() })
        val entry = entryElement(deleted.document, 1)
        assertEquals(NOW, time(entry, "LocationChanged"))
        assertEquals(NOW, time(entry, "LastAccessTime"))
        assertEquals(T0, time(entry, "LastModificationTime"))
        assertEquals("4", entry.child("Times")!!.child("UsageCount")!!.text())
        assertEquals(1, entry.child("History")!!.children("Entry").size, "no snapshot is added")
        assertNull(entry.child("PreviousParentGroup"), "a 4.0 file never gets PreviousParentGroup")
        assertEquals(NOW, time(bin, "LastAccessTime"))
        assertEquals(T0, time(bin, "LastModificationTime"))
        // The minimal test document's top-level group has no Times; Touch creates the touched ones.
        assertEquals(NOW, time(rootGroup(deleted.document), "LastAccessTime"))
        assertEquals("1", rootGroup(deleted.document).child("Times")!!.child("UsageCount")!!.text())
        assertEquals("4", bin.child("Times")!!.child("UsageCount")!!.text())
        assertEquals(T0, time(groupNamed(deleted.document, "General"), "LastAccessTime"), "the old group is untouched")
        val index = EditFixtures.index(reopened(deleted.document))
        assertEquals(listOf("Mail"), index.rows(Chip.All, "").map { it.title })
        assertTrue(index.rows(Chip.RecycleBin, "").any { it.title == "Bank" })
    }

    @Test
    fun `a 4_1 file records the previous parent group before Times`() {
        val deleted = EntryDelete.delete(vault(minor = 1), id(1), NOW)!!
        val entry = entryElement(reopened(deleted.document), 1)
        assertEquals(uuid(10), entry.child("PreviousParentGroup")!!.text())
        val names = entry.elements().map { it.name }
        assertEquals(names.indexOf("Times") - 1, names.indexOf("PreviousParentGroup"))
    }

    @Test
    fun `a 4_0 file whose content saves as 4_1 records the previous parent group`() {
        val tagged = doc(
            group(10, "General", "<Tags>work</Tags>" + entry(1, "Bank") + entry(2, "Mail")) +
                group(30, "Recycle Bin", entry(3, "Gone"), icon = 43),
            meta = binMeta,
        )
        assertEquals(0, tagged.kdbxMinor)
        val deleted = EntryDelete.delete(tagged, id(1), NOW)!!
        assertEquals(uuid(10), entryElement(reopened(deleted.document), 1).child("PreviousParentGroup")!!.text())
    }

    @Test
    fun `a missing or dangling bin is created under the top level`() {
        for (meta in listOf("<RecycleBinEnabled>True</RecycleBinEnabled>", "<RecycleBinUUID>${uuid(99)}</RecycleBinUUID><RecycleBinChanged>${EditFixtures.t(T0)}</RecycleBinChanged>")) {
            val document = doc(group(10, "General", entry(1, "Bank")), meta = meta)
            val deleted = EntryDelete.delete(document, id(1), NOW)!!
            val back = reopened(deleted.document)
            val bin = rootGroup(back).children("Group").last()
            assertEquals("Recycle Bin", bin.child("Name")!!.text())
            assertEquals("43", bin.child("IconID")!!.text())
            assertEquals("False", bin.child("EnableSearching")!!.text())
            assertEquals("False", bin.child("EnableAutoType")!!.text())
            assertEquals(bin.child("UUID")!!.text(), back.xml.root.child("Meta")!!.child("RecycleBinUUID")!!.text())
            assertEquals(back.meta.recycleBinUuid, org.onekash.kashpass.vault.doc.Uuids.parse(bin.child("UUID")!!.text()))
            if (meta.contains("RecycleBinChanged")) assertEquals(EditFixtures.t(T0), back.xml.root.child("Meta")!!.child("RecycleBinChanged")!!.text())
            assertEquals(listOf("Bank"), EditFixtures.index(back).rows(Chip.RecycleBin, "").map { it.title })
        }
    }

    @Test
    fun `with the bin disabled a delete is permanent and recorded`() {
        val document = vault(meta = "<RecycleBinEnabled>False</RecycleBinEnabled><RecycleBinUUID>${uuid(30)}</RecycleBinUUID>")
        assertEquals(DeleteKind.PERMANENT, EntryDelete.kindOf(document, id(1)))
        val deleted = EntryDelete.delete(document, id(1), NOW)!!
        val back = reopened(deleted.document)
        val objects = back.xml.root.child("Root")!!.child("DeletedObjects")!!.children("DeletedObject")
        assertEquals(listOf(uuid(1)), objects.map { it.child("UUID")!!.text() })
        assertEquals(NOW, KdbxTime.parse(objects.single().child("DeletionTime")!!.text()))
        assertTrue(EditFixtures.index(back).rows(Chip.All, "").none { it.title == "Bank" })
        assertTrue(!xml(back).contains("older"), "history goes with the entry")
    }

    @Test
    fun `entries in the bin or a group inside it are deleted permanently, keeping earlier records`() {
        val first = EntryDelete.delete(vault(), id(4), NOW)!!
        assertEquals(DeleteKind.PERMANENT, first.kind)
        val second = EntryDelete.delete(first.document, id(3), NOW)!!
        assertEquals(DeleteKind.PERMANENT, second.kind)
        val objects = second.document.xml.root.child("Root")!!.child("DeletedObjects")!!.children("DeletedObject")
        assertEquals(listOf(uuid(4), uuid(3)), objects.map { it.child("UUID")!!.text() })
    }

    @Test
    fun `a permanent delete drops attachments nothing else references`() {
        val document = vault(meta = "<RecycleBinEnabled>False</RecycleBinEnabled>", attachments = listOf("A".toByteArray()), extra = "<Binary><Key>a</Key><Value Ref=\"0\" /></Binary>")
        val deleted = EntryDelete.delete(document, id(1), NOW)!!
        assertEquals(0, deleted.document.xml.root.let { root -> generateSequence(listOf(root)) { l -> l.flatMap { it.elements() }.ifEmpty { null } }.flatten().count { it.name == "Binary" } })
        assertEquals(org.onekash.kashpass.vault.doc.Saveability.Saveable, reopened(deleted.document).saveability)
    }

    @Test
    fun `only the moved entry, the bin and group times change`() {
        val document = vault()
        val deleted = EntryDelete.delete(document, id(1), NOW)!!
        val outside = { d: VaultDocument -> xml(d) { (it.name == "Entry" && it.child("UUID")?.text() == uuid(1) && it.parent?.name == "Group") || (it.name == "Times" && it.parent?.name == "Group") } }
        assertEquals(outside(document), outside(deleted.document))
    }

    @Test
    fun `an unknown entry is null`() {
        assertNull(EntryDelete.delete(vault(), id(99), NOW))
        assertNull(EntryDelete.kindOf(vault(), id(99)))
    }
}
