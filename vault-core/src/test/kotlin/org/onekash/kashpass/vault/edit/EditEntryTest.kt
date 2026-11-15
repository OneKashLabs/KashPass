package org.onekash.kashpass.vault.edit

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.edit.EditFixtures.NOW
import org.onekash.kashpass.vault.edit.EditFixtures.T0
import org.onekash.kashpass.vault.edit.EditFixtures.doc
import org.onekash.kashpass.vault.edit.EditFixtures.entry
import org.onekash.kashpass.vault.edit.EditFixtures.entryElement
import org.onekash.kashpass.vault.edit.EditFixtures.group
import org.onekash.kashpass.vault.edit.EditFixtures.id
import org.onekash.kashpass.vault.edit.EditFixtures.reopened
import org.onekash.kashpass.vault.edit.EditFixtures.time
import org.onekash.kashpass.vault.edit.EditFixtures.xml
import org.onekash.kashpass.vault.index.Chip

class EditEntryTest {

    private val customData = "<CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>"
    private val oldHistory = entry(1, "Ancient", at = java.time.Instant.parse("2019-01-01T00:00:00Z")).replace("<History />", "")
    private val vault = doc(
        group(10, "General", entry(1, "Bank", extra = "<Binary><Key>a.txt</Key><Value Ref=\"0\" /></Binary>$customData", history = oldHistory) + entry(2, "Mail")),
        attachments = listOf("attachment".toByteArray()),
    )

    private fun draft(document: org.onekash.kashpass.vault.doc.VaultDocument = vault, n: Int = 1) = EntryEdits.draftOf(document, id(n))!!

    private fun EntryDraft.with(title: String = this.title, password: ProtectedText = this.password, url: String = this.url, notes: String = this.notes) =
        EntryDraft(title, userName, password, url, notes)

    @Test
    fun `an edit keeps protected values XML can't carry as text when only another field changes`() {
        val f = EditFixtures
        val entry = "<Entry><UUID>${f.uuid(1)}</UUID><IconID>0</IconID>${f.times()}" +
            f.string("Title", "T\u0001", protected = true) + f.string("UserName", "u") +
            f.string("Password", "ab\u0001c", protected = true) + f.string("Notes", "n\u0002", protected = true) +
            "<History /></Entry>"
        val document = doc(group(10, "General", entry))
        val kept = assertIs<EditResult.Changed>(EntryEdits.edit(document, id(1), draft(document).with(url = "https://example.org"), NOW)).document
        val back = draft(reopened(kept))
        assertEquals("T\u0001", back.title)
        assertEquals("ab\u0001c", back.password.reveal())
        assertEquals("n\u0002", back.notes)
        assertEquals("https://example.org", back.url)
        // A changed value written protected keeps them too: only a value written in clear loses
        // characters XML can't carry.
        val changed = assertIs<EditResult.Changed>(
            EntryEdits.edit(document, id(1), draft(document).with(title = "X\u0003", password = ProtectedText.of("p\u0001q"), notes = "m\u0004"), NOW),
        ).document
        val back2 = draft(reopened(changed))
        assertEquals("X\u0003", back2.title)
        assertEquals("p\u0001q", back2.password.reveal())
        assertEquals("m\u0004", back2.notes)
    }

    @Test
    fun `a password typed with a control character is saved and read back with it`() {
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), draft().with(password = ProtectedText.of("a\u0001b")), NOW)).document
        assertEquals("a\u0001b", draft(reopened(edited)).password.reveal())
    }

    @Test
    fun `fields the vault's Meta protects keep control characters, Meta stays as it was`() {
        val meta = org.onekash.kashpass.vault.testing.TestVaults.META_PROTECTED_META
        val document = doc(group(10, "G", entry(1, "Bank")), meta = meta)
        fun protection(d: org.onekash.kashpass.vault.doc.VaultDocument) =
            d.xml.root.child("Meta")!!.child("MemoryProtection")!!.elements().map { it.name to it.text() }
        val before = protection(document)
        val edited = assertIs<EditResult.Changed>(
            EntryEdits.edit(document, id(1), draft(document).with(title = "T\u0001", notes = "n\u0002", url = "u\u0003"), NOW),
        ).document
        val back = reopened(edited)
        val read = draft(back)
        assertEquals("T", read.title)
        assertEquals("n\u0002", read.notes)
        assertEquals("u\u0003", read.url)
        assertEquals(5, before.size)
        assertEquals(before, protection(back))
        assertEquals(before, protection(reopened(document)))
    }

    @Test
    fun `an edit appends the previous version to the history, then touches the entry`() {
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), draft().with(title = "Bank 2"), NOW)).document
        val entry = entryElement(edited, 1)
        val history = entry.child("History")!!.children("Entry")
        assertEquals(listOf("Ancient", "Bank"), history.map { it.children("String").first { s -> s.child("Key")!!.text() == "Title" }.child("Value")!!.text() })
        val snapshot = history.last()
        assertNull(snapshot.child("History"), "a snapshot has no history of its own")
        assertEquals("a.txt", snapshot.child("Binary")!!.child("Key")!!.text())
        assertEquals("k", snapshot.child("CustomData")!!.child("Item")!!.child("Key")!!.text())
        assertEquals(T0, time(snapshot, "LastModificationTime"))
        assertEquals("3", snapshot.child("Times")!!.child("UsageCount")!!.text())
        assertEquals(NOW, time(entry, "LastModificationTime"))
        assertEquals(NOW, time(entry, "LastAccessTime"))
        assertEquals(T0, time(entry, "CreationTime"))
        assertEquals("4", entry.child("Times")!!.child("UsageCount")!!.text())
        // Touch(true, false): the parent group keeps its times.
        assertEquals(T0, time(entry.parent!!, "LastAccessTime"))
        assertEquals(T0, time(entry.parent!!, "LastModificationTime"))
    }

    @Test
    fun `the snapshot keeps protected values, and the saved file reads back`() {
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), draft().with(password = ProtectedText.of("new-pass")), NOW)).document
        val back = reopened(edited)
        val entry = entryElement(back, 1)
        val password = entry.children("String").first { it.child("Key")!!.text() == "Password" }.child("Value")!!
        assertEquals("True", password.attribute("Protected"))
        assertEquals("new-pass", back.protectedValues[password]!!.reveal())
        val snapshot = entry.child("History")!!.children("Entry").last()
        val old = snapshot.children("String").first { it.child("Key")!!.text() == "Password" }.child("Value")!!
        assertEquals("pass1", back.protectedValues[old]!!.reveal())
        assertEquals("new-pass", EntryEdits.draftOf(back, id(1))!!.password.reveal())
    }

    @Test
    fun `no change saves nothing and the input document is never edited`() {
        val before = xml(vault)
        assertSame(EditResult.Unchanged, EntryEdits.edit(vault, id(1), draft(), NOW))
        assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), draft().with(title = "Other"), NOW))
        assertEquals(before, xml(vault))
    }

    @Test
    fun `whitespace inside a field counts as a change`() {
        assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), draft().with(title = "Bank "), NOW))
        assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), draft().with(notes = "\n"), NOW))
    }

    @Test
    fun `only the edited entry differs from what was read`() {
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), draft().with(title = "Bank 2", url = "https://x"), NOW)).document
        val outside = { d: org.onekash.kashpass.vault.doc.VaultDocument -> xml(d) { it.name == "Entry" && it.parent?.name == "Group" && it.child("UUID")?.text() == EditFixtures.uuid(1) } }
        assertEquals(outside(vault), outside(edited))
        assertNotEquals(xml(vault), xml(edited))
    }

    @Test
    fun `a field the entry lacked is added after its other fields with the vault's protection`() {
        val meta = "<MemoryProtection><ProtectURL>True</ProtectURL></MemoryProtection>"
        val withMeta = doc(group(10, "General", entry(1, "Bank")), meta = meta)
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(withMeta, id(1), draft(withMeta).with(url = "https://bank"), NOW)).document
        val entry = entryElement(reopened(edited), 1)
        val keys = entry.children("String").map { it.child("Key")!!.text() }
        assertEquals(listOf("Title", "UserName", "Password", "URL"), keys)
        assertEquals("True", entry.children("String").last().child("Value")!!.attribute("Protected"))
    }

    @Test
    fun `characters XML 1_0 forbids are removed before saving`() {
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), draft().with(title = "Ba\u0001nk￾!"), NOW)).document
        assertEquals("Bank!", EntryEdits.draftOf(reopened(edited), id(1))!!.title)
    }

    @Test
    fun `protected keys come from the entry and the vault's settings`() {
        assertEquals(setOf("Password"), EntryEdits.protectedKeys(vault, id(1)))
        val notes = doc(group(10, "G", entry(1, "Bank")), meta = "<MemoryProtection><ProtectNotes>True</ProtectNotes></MemoryProtection>")
        assertEquals(setOf("Password", "Notes"), EntryEdits.protectedKeys(notes, id(1)))
        assertEquals(setOf("Password", "Notes"), EntryEdits.protectedKeys(notes, null))
        val protectedTitle = doc(group(10, "G", entry(1, "x").replace("<String><Key>Title</Key><Value>x</Value></String>", EditFixtures.string("Title", "Secret", protected = true))))
        assertEquals(setOf("Password", "Title"), EntryEdits.protectedKeys(protectedTitle, id(1)))
    }

    @Test
    fun `a missing entry is reported`() {
        assertSame(EditResult.EntryNotFound, EntryEdits.edit(vault, id(99), draft(), NOW))
        assertNull(EntryEdits.draftOf(vault, id(99)))
    }

    @Test
    fun `the index of the edited document shows the change`() {
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(vault, id(1), draft().with(title = "Savings"), NOW)).document
        assertEquals(listOf("Mail", "Savings"), EditFixtures.index(reopened(edited)).rows(Chip.All, "").map { it.title })
        assertTrue(EditFixtures.index(vault).rows(Chip.All, "").any { it.title == "Bank" })
    }
}
