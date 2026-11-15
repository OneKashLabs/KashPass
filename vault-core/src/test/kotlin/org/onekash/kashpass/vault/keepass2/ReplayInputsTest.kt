package org.onekash.kashpass.vault.keepass2

import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.EntryParts
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.xml.XmlElement

/** Each generated input of the differential editing test has the property its cases rely on. */
class ReplayInputsTest {

    private fun open(input: ReplayInputs.Input): VaultDocument = CompanionRig.open(input.file).document

    private fun element(document: VaultDocument, uuid: String): XmlElement? = DocumentIds.entries(document)[Uuids.parse(uuid).toString()]

    private fun group(document: VaultDocument, uuid: String): XmlElement? = DocumentIds.groups(document)[Uuids.parse(uuid).toString()]

    @Test
    fun `each input opens with its history, distinct in title and time, and an attachment in every version`() {
        for (input in ReplayInputs.all) {
            val document = open(input)
            val main = element(document, ReplayInputs.MAIN)!!
            val history = EntryParts.history(main)
            assertEquals(input.historyItems, history.size, input.name)
            val times = history.map { it.child("Times")!!.child("LastModificationTime")!!.text() }
            assertEquals(times.size, times.toSet().size, input.name)
            val titles = history.map { it.children("String").single { s -> s.child("Key")!!.text() == "Title" }.child("Value")!!.text() }
            assertEquals(titles.size, titles.toSet().size, input.name)
            assertTrue((history + main).all { it.child("Binary")?.child("Value")?.attribute("Ref") == "0" }, input.name)
        }
    }

    @Test
    fun `the history-limit inputs are at, below or above their limit as their names say`() {
        val atLimit = ReplayInputs.named("history-10-at-limit")
        assertEquals(atLimit.maxItems, atLimit.historyItems)
        assertTrue(ReplayInputs.named("history-0").historyItems > 0)
        assertTrue(ReplayInputs.named("history-unlimited").let { it.maxItems == -1 && it.historyItems > 10 })
        // KeePass 2 counts at least 276 bytes for any entry against the history size limit, so one
        // snapshot exceeds a limit of 100 bytes.
        assertTrue(ReplayInputs.named("history-size-small").maxSize < 276)
    }

    @Test
    fun `the bin inputs have the bin present, missing, dangling or off`() {
        for (input in ReplayInputs.all) {
            val document = open(input)
            val meta = document.meta
            when (input.bin) {
                ReplayInputs.Bin.PRESENT -> {
                    assertTrue(meta.recycleBinEnabled, input.name)
                    assertEquals(Uuids.parse(ReplayInputs.BIN), meta.recycleBinUuid, input.name)
                    assertEquals(Uuids.parse(ReplayInputs.BIN).toString(), DocumentIds.groups(document).entries.single { it.value === element(document, ReplayInputs.BINNED)!!.parent }.key)
                }
                ReplayInputs.Bin.MISSING -> {
                    assertTrue(meta.recycleBinEnabled, input.name)
                    assertNull(group(document, ReplayInputs.BIN), input.name)
                }
                ReplayInputs.Bin.DANGLING -> {
                    assertTrue(meta.recycleBinEnabled, input.name)
                    assertEquals(Uuids.parse(ReplayInputs.DANGLING), meta.recycleBinUuid, input.name)
                    assertNull(group(document, ReplayInputs.DANGLING), input.name)
                }
                ReplayInputs.Bin.OFF -> assertTrue(!meta.recycleBinEnabled, input.name)
            }
        }
    }

    @Test
    fun `the groups carry the icons, templates and default user name the add cases rely on`() {
        val document = open(ReplayInputs.base)
        assertEquals("48", group(document, ReplayInputs.FOLDER)!!.child("IconID")!!.text())
        assertEquals("25", group(document, ReplayInputs.MAILBOX)!!.child("IconID")!!.text())
        assertEquals(ReplayInputs.ICON, group(document, ReplayInputs.CUSTOM)!!.child("CustomIconUUID")!!.text())
        assertEquals(group(document, ReplayInputs.TEMPLATES), group(document, ReplayInputs.TEMPLATES_SUB)!!.parent)
        assertEquals("default-user", document.meta.defaultUserName)
        assertEquals("", open(ReplayInputs.named("default-user-empty")).meta.defaultUserName)
        assertEquals(1, ReplayInputs.named("kdbx41").let { open(it).savedMinor() })
        assertEquals("other", EntryEdits.draftOf(document, Uuids.parse(ReplayInputs.OTHER).toString())!!.title)
    }
}
