package org.onekash.kashpass.vault.edit

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.edit.EditFixtures.NOW
import org.onekash.kashpass.vault.edit.EditFixtures.doc
import org.onekash.kashpass.vault.edit.EditFixtures.entry
import org.onekash.kashpass.vault.edit.EditFixtures.group
import org.onekash.kashpass.vault.edit.EditFixtures.id
import org.onekash.kashpass.vault.edit.EditFixtures.reopened
import org.onekash.kashpass.vault.edit.EditFixtures.time
import org.onekash.kashpass.vault.edit.EditFixtures.uuid
import org.onekash.kashpass.vault.edit.EditFixtures.xml
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.xml.XmlElement

class AddEntryTest {

    private val newId = java.util.UUID(0, 77)
    private val bin = "<RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>${uuid(30)}</RecycleBinUUID>"
    private val vault = doc(
        group(10, "Email", entry(1, "Mail"), icon = 25) +
            group(11, "Work", group(12, "Email", entry(2, "Work Mail"))) +
            group(30, "Recycle Bin", group(31, "Old", "") + entry(3, "Gone"), icon = 43),
        meta = "$bin<DefaultUserName>me@example.test</DefaultUserName>",
    )

    private fun draft(title: String = "New", password: String = "generated") =
        EntryDraft(title, "me@example.test", ProtectedText.of(password), "https://new", "notes")

    private fun added(groupId: String? = id(10), document: org.onekash.kashpass.vault.doc.VaultDocument = vault, d: EntryDraft = draft()) =
        EntryEdits.add(document, groupId, d, NOW, newId)

    private fun element(document: org.onekash.kashpass.vault.doc.VaultDocument): XmlElement {
        fun find(e: XmlElement): XmlElement? =
            if (e.name == "Entry" && e.child("UUID")?.text() == Uuids.format(newId)) e else e.elements().firstNotNullOfOrNull(::find)
        return find(document.xml.root)!!
    }

    @Test
    fun `a new entry has KeePass 2's fields, times and element order`() {
        val result = added()
        val back = reopened(result.document)
        val entry = element(back)
        assertEquals(
            listOf("UUID", "IconID", "ForegroundColor", "BackgroundColor", "OverrideURL", "Tags", "Times") + List(5) { "String" } + listOf("AutoType", "History"),
            entry.elements().map { it.name },
        )
        for (name in listOf("CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime", "LocationChanged")) assertEquals(NOW, time(entry, name), name)
        assertEquals("False", entry.child("Times")!!.child("Expires")!!.text())
        assertEquals("1", entry.child("Times")!!.child("UsageCount")!!.text())
        assertEquals(listOf("Notes", "Password", "Title", "URL", "UserName"), entry.children("String").map { it.child("Key")!!.text() })
        val protectedKeys = entry.children("String").filter { it.child("Value")!!.attribute("Protected") == "True" }.map { it.child("Key")!!.text() }
        assertEquals(listOf("Password"), protectedKeys)
        val values = EntryEdits.draftOf(back, result.entryId)!!
        assertEquals(listOf("New", "me@example.test", "generated", "https://new", "notes"), listOf(values.title, values.userName, values.password.reveal(), values.url, values.notes))
        assertEquals(newId.toString(), result.entryId)
    }

    @Test
    fun `fields follow the vault's memory protection`() {
        val protecting = doc(group(10, "G", ""), meta = "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectPassword>True</ProtectPassword><ProtectNotes>True</ProtectNotes></MemoryProtection>")
        val entry = element(reopened(added(document = protecting).document))
        val protectedKeys = entry.children("String").filter { it.child("Value")!!.attribute("Protected") == "True" }.map { it.child("Key")!!.text() }
        assertEquals(listOf("Notes", "Password", "Title"), protectedKeys)
    }

    @Test
    fun `an add leaves the vault's memory protection settings as they were`() {
        val protecting = doc(group(10, "G", ""), meta = org.onekash.kashpass.vault.testing.TestVaults.META_PROTECTED_META)
        fun protection(d: org.onekash.kashpass.vault.doc.VaultDocument) =
            d.xml.root.child("Meta")!!.child("MemoryProtection")!!.elements().map { it.name to it.text() }
        val before = protection(protecting)
        assertEquals(5, before.size)
        assertEquals(before, protection(reopened(added(document = protecting).document)))
    }

    @Test
    fun `control characters stay in fields written protected and leave fields written in clear`() {
        val protecting = doc(group(10, "G", ""), meta = "<MemoryProtection><ProtectNotes>True</ProtectNotes></MemoryProtection>")
        val d = EntryDraft("T\u0001", "u\u0002", org.onekash.kashpass.vault.doc.ProtectedText.of("p\u0003"), "w\u0004", "n\u0005")
        val result = added(document = protecting, d = d)
        val values = EntryEdits.draftOf(reopened(result.document), result.entryId)!!
        assertEquals(listOf("T", "u", "p\u0003", "w", "n\u0005"), listOf(values.title, values.userName, values.password.reveal(), values.url, values.notes))
    }

    @ParameterizedTest
    @CsvSource("48, 0", "49, 0", "50, 0", "25, 19", "7, 7", "0, 0", "68, 68")
    fun `the icon comes from the group as KeePass 2 maps it`(groupIcon: Int, entryIcon: Int) {
        val document = doc(group(10, "G", "", icon = groupIcon))
        assertEquals(entryIcon.toString(), element(added(document = document).document).child("IconID")!!.text())
    }

    @Test
    fun `a group's custom icon is inherited`() {
        val custom = uuid(55)
        val document = doc("<Group><UUID>${uuid(10)}</UUID><Name>G</Name><IconID>48</IconID><CustomIconUUID>$custom</CustomIconUUID></Group>")
        assertEquals(custom, element(added(document = document).document).child("CustomIconUUID")!!.text())
        assertNull(element(added(document = doc(group(10, "G", ""))).document).child("CustomIconUUID"))
    }

    @Test
    fun `the entry goes after the group's entries and before its child groups`() {
        val groupWithChildren = doc(group(10, "G", entry(1, "A") + group(11, "Child", "")))
        val g = added(document = groupWithChildren).document.xml.root.child("Root")!!.child("Group")!!.children("Group").first()
        assertEquals(listOf("Entry", "Entry", "Group"), g.elements().map { it.name }.filter { it == "Entry" || it == "Group" })
        assertEquals(Uuids.format(newId), g.children("Entry").last().child("UUID")!!.text())
    }

    @Test
    fun `the top level is used when no group is given, and the recycle bin is refused`() {
        val top = added(groupId = null).document
        assertEquals("Root", element(top).parent!!.child("Name")!!.text())
        assertFailsWith<IllegalArgumentException> { added(groupId = id(30)) }
        assertFailsWith<IllegalArgumentException> { added(groupId = id(31)) }
        assertFailsWith<IllegalArgumentException> { added(groupId = "no-such-group") }
    }

    @Test
    fun `groups lists every group but the recycle bin, top level first, with paths`() {
        assertEquals(
            listOf(GroupChoice(id(1), "Root", true), GroupChoice(id(10), "Email", false), GroupChoice(id(11), "Work", false), GroupChoice(id(12), "Work / Email", false)),
            EntryEdits.groups(vault),
        )
    }

    @Test
    fun `an empty title saves and is listed untitled`() {
        val result = added(d = draft(title = ""))
        val row = EditFixtures.index(reopened(result.document)).rows(Chip.All, "").single { it.id == result.entryId }
        assertNull(row.title)
    }

    @Test
    fun `a new draft has the vault's default user name and the given password`() {
        val d = EntryEdits.newDraft(vault, ProtectedText.of("gen"))
        assertEquals("me@example.test", d.userName)
        assertEquals("gen", d.password.reveal())
        assertEquals("", d.title)
    }

    @Test
    fun `only the new entry differs from what was read`() {
        val result = added()
        assertEquals(xml(vault), xml(result.document) { it.name == "Entry" && it.child("UUID")?.text() == Uuids.format(newId) })
        assertTrue(xml(result.document).length > xml(vault).length)
    }
}
