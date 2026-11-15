package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.xml.XmlElement

class CompanionRigTest {

    private val file = VaultFile("browser.kdbx", TestVaults.browserVault(aesRounds = 1_000UL))
    private val now = Instant.parse("2026-10-30T12:00:00Z")

    private fun uuidOf(document: VaultDocument, title: String): String =
        Uuids.format(UUID.fromString(DocumentIds.entries(document).keys.first { EntryEdits.draftOf(document, it)!!.title == title }))

    private fun entry(document: VaultDocument, uuid: String): XmlElement? = DocumentIds.entries(document)[Uuids.parse(uuid).toString()]

    private fun saved(ops: (VaultDocument) -> List<CompanionOp>): Pair<VaultDocument, VaultDocument> {
        val before = CompanionRig.open(file).document
        val after = CompanionRig.open(CompanionRig.run(file, ops(before), now, "saved.kdbx")).document
        return before to after
    }

    @Test
    fun `an edit is saved with one more history item`() {
        val (before, after) = saved { listOf(CompanionOp.Edit(uuidOf(it, "Router"), "Title", "Router renamed")) }
        val uuid = uuidOf(before, "Router")
        assertEquals("Router renamed", EntryEdits.draftOf(after, Uuids.parse(uuid).toString())!!.title)
        val history = { d: VaultDocument -> entry(d, uuid)!!.child("History")?.children("Entry").orEmpty().size }
        assertEquals(history(before) + 1, history(after))
    }

    @Test
    fun `an add is saved under the given UUID with the vault's default user name`() {
        val uuid = Uuids.format(UUID.fromString("0f0e0d0c-0b0a-0908-0706-050403020100"))
        val (before, after) = saved { listOf(CompanionOp.Add(null, uuid, "Added", "pass", "https://added.test", "notes")) }
        val draft = EntryEdits.draftOf(after, Uuids.parse(uuid).toString())!!
        assertEquals(listOf("Added", before.meta.defaultUserName, "pass", "https://added.test", "notes"), listOf(draft.title, draft.userName, draft.password.reveal(), draft.url, draft.notes))
        assertEquals("1", entry(after, uuid)!!.child("Times")!!.child("UsageCount")!!.text())
    }

    @Test
    fun `a delete moves an entry to the bin, and a delete inside the bin removes it with a record`() {
        val (before, after) = saved { listOf(CompanionOp.Delete(uuidOf(it, "Example Mail")), CompanionOp.Delete(uuidOf(it, "Old Bank"))) }
        val mail = uuidOf(before, "Example Mail")
        val old = uuidOf(before, "Old Bank")
        val binUuid = after.meta.recycleBinUuid!!
        assertEquals(Uuids.format(binUuid), entry(after, mail)!!.parent!!.child("UUID")!!.text())
        assertNull(entry(after, old))
        val deleted = after.xml.root.child("Root")!!.child("DeletedObjects")!!.children("DeletedObject").map { it.child("UUID")!!.text() }
        assertEquals(listOf(old), deleted)
    }

    @Test
    fun `a save without an edit keeps every entry`() {
        val (before, after) = saved { listOf(CompanionOp.NoEdit) }
        assertEquals(DocumentIds.entries(before).keys, DocumentIds.entries(after).keys)
        for (id in DocumentIds.entries(before).keys) {
            val a = EntryEdits.draftOf(before, id)!!
            val b = EntryEdits.draftOf(after, id)!!
            assertEquals(listOf(a.title, a.userName, a.password.reveal(), a.url, a.notes), listOf(b.title, b.userName, b.password.reveal(), b.url, b.notes))
        }
    }

    @Test
    fun `the rig refuses a custom data delete, which KashPass does not offer`() {
        val document = CompanionRig.open(file).document
        assertFailsWith<IllegalArgumentException> { CompanionRig.apply(document, CompanionOp.DeleteCustomData(uuidOf(document, "Router"), "k"), now) }
    }

    @Test
    fun `action lines percent-encode text as the KeePassLib replay reads it`() {
        assertEquals("edit\tAAAA\tNotes\ta%20b%25%0A%C3%BC", CompanionOp.Edit("AAAA", "Notes", "a b%\nü").line)
        assertEquals("add\t-\tBBBB\tT\t%\t%\t%", CompanionOp.Add(null, "BBBB", "T", "", "", "").line)
        assertTrue(CompanionOp.NoEdit.line == "none")
    }
}
