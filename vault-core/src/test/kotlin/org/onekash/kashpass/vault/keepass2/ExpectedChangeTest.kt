package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.jupiter.api.Test

class ExpectedChangeTest {

    private val now = Instant.parse("2026-10-30T12:00:00Z")
    private val change = ExpectedChange(ByteArray(32) { it.toByte() }, now)
    private val h = change::hash

    private val root = "Uk9PVFJPT1RST09UUk9PVA=="
    private val e1 = "RTFFMUUxRTFFMUUxRTFFMQ=="
    private val e2 = "RTJFMkUyRTJFMkUyRTJFMg=="
    private val g = "R0dHR0dHR0dHR0dHR0dHRw=="
    private val bin = "QklOMUJJTjFCSU4xQklOMQ=="

    private fun times(modified: String, usage: Int = 2) =
        "<Times><CreationTime>2026-01-01T00:00:00Z</CreationTime><LastModificationTime>$modified</LastModificationTime>" +
            "<LastAccessTime>$modified</LastAccessTime><ExpiryTime>2026-01-01T00:00:00Z</ExpiryTime><Expires>False</Expires>" +
            "<UsageCount>$usage</UsageCount><LocationChanged>2026-01-01T00:00:00Z</LocationChanged></Times>"

    private fun entry(uuid: String, title: String, modified: String = "2026-01-02T00:00:00Z", history: String? = null, attachment: Int? = null) =
        "<Entry><UUID>$uuid</UUID><IconID>0</IconID>${times(modified)}" +
            "<String><Key>Title</Key><Value>${h(title)}</Value></String>" +
            "<String><Key>Password</Key><Value ProtectInMemory=\"True\">${h("p")}</Value></String>" +
            (attachment?.let { "<Binary><Key>a.bin</Key><Value Ref=\"$it\">${h("")}</Value></Binary>" } ?: "") +
            (history?.let { "<History>$it</History>" } ?: "<History>${h("")}</History>") + "</Entry>"

    // A history item as KeePass 2 writes it: an entry without a History element.
    private fun item(uuid: String, title: String, modified: String) = entry(uuid, title, modified).replace("<History>${h("")}</History>", "")

    private fun group(uuid: String, name: String, icon: Int, content: String) =
        "<Group><UUID>$uuid</UUID><Name>${h(name)}</Name><IconID>$icon</IconID>${times("2026-01-01T00:00:00Z")}$content</Group>"

    private fun export(content: String, maxItems: Int = 10, binEnabled: Boolean = true, binUuid: String = "AAAAAAAAAAAAAAAAAAAAAA==", pool: String = "", deleted: String = "") =
        KeePassXml.parse(
            "<KeePassFile><Meta><DefaultUserName>${h("me")}</DefaultUserName><RecycleBinEnabled>${if (binEnabled) "True" else "False"}</RecycleBinEnabled>" +
                "<RecycleBinUUID>$binUuid</RecycleBinUUID><HistoryMaxItems>$maxItems</HistoryMaxItems>" +
                "<Binaries>${pool.ifEmpty { h("") }}</Binaries></Meta>" +
                "<Root>${group(root, "Root", 48, content)}<DeletedObjects>${deleted.ifEmpty { h("") }}</DeletedObjects></Root></KeePassFile>",
        )

    private fun assertSame(expected: KeePassXml, actual: KeePassXml, input: KeePassXml) {
        val normal = KeePassXml.Normal(input = input)
        assertEquals(emptyList(), KeePassXml.diff(expected.flat(normal), actual.flat(normal)))
    }

    @Test
    fun `an edit appends the entry without history, touches it and sets the hashed value`() {
        val input = export(entry(e1, "old", history = item(e1, "older", "2026-01-01T00:00:00Z")))
        val expected = change.apply(input, listOf(CompanionOp.Edit(e1, "Title", "new")))
        val snapshot = item(e1, "old", "2026-01-02T00:00:00Z")
        val want = export(
            entry(e1, "new", modified = "2026-10-30T12:00:00Z", history = item(e1, "older", "2026-01-01T00:00:00Z") + snapshot)
                .replace("<UsageCount>2</UsageCount><LocationChanged>2026-01-01T00:00:00Z</LocationChanged></Times><String><Key>Title</Key><Value>${h("new")}", "<UsageCount>3</UsageCount><LocationChanged>2026-01-01T00:00:00Z</LocationChanged></Times><String><Key>Title</Key><Value>${h("new")}"),
        )
        assertSame(want, expected, input)
    }

    @Test
    fun `an edit trims history by item count, oldest modification first`() {
        val items = listOf("2026-01-03T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z").joinToString("") { item(e1, it, it) }
        val input = export(entry(e1, "cur", history = items), maxItems = 3)
        val out = change.apply(input, listOf(CompanionOp.Edit(e1, "Title", "new")))
        val kept = KeePassXml.history(out.entries().getValue(e1)).map { it.child("Times")!!.child("LastModificationTime")!!.text() }
        assertEquals(listOf("2026-01-03T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z"), kept)
    }

    @Test
    fun `an add takes the group's icon and the default user name and counts one use`() {
        val input = export(group(g, "Mail", 25, ""))
        val out = change.apply(input, listOf(CompanionOp.Add(g, e2, "T", "P", "U", "N")))
        val added = out.entries().getValue(e2)
        assertEquals("19", added.child("IconID")!!.text())
        assertEquals("1", added.child("Times")!!.child("UsageCount")!!.text())
        val values = added.children("String").associate { it.child("Key")!!.text() to it.child("Value")!!.text() }
        assertEquals(mapOf("Notes" to h("N"), "Password" to h("P"), "Title" to h("T"), "URL" to h("U"), "UserName" to h("me")), values)
        assertEquals(g, KeePassXml.uuid(added.parent!!))
    }

    @Test
    fun `a delete creates the bin under the top level, moves the entry and touches it and its new parents`() {
        val input = export(entry(e1, "x"))
        val out = change.apply(input, listOf(CompanionOp.Delete(e1)))
        val moved = out.entries().getValue(e1)
        val binGroup = moved.parent!!
        assertEquals(ExpectedChange.BIN_PLACEHOLDER, KeePassXml.uuid(binGroup))
        assertEquals(ExpectedChange.BIN_PLACEHOLDER, out.meta().child("RecycleBinUUID")!!.text())
        assertEquals(listOf("43", "False", "False"), listOf("IconID", "EnableAutoType", "EnableSearching").map { binGroup.child(it)!!.text() })
        assertEquals(now.toString(), moved.child("Times")!!.child("LocationChanged")!!.text())
        assertEquals("3", moved.child("Times")!!.child("UsageCount")!!.text())
        assertEquals("1", binGroup.child("Times")!!.child("UsageCount")!!.text())
        assertEquals("3", out.groups().getValue(root).child("Times")!!.child("UsageCount")!!.text())
        // KDBX 4.0 content: no PreviousParentGroup.
        assertNull(moved.child("PreviousParentGroup"))
    }

    @Test
    fun `a delete inside the bin is permanent, and the pool drops what only that entry used`() {
        val pool = "<Binary ID=\"0\" Compressed=\"True\">${h("a")}</Binary><Binary ID=\"1\" Compressed=\"True\">${h("b")}</Binary>"
        val input = export(entry(e2, "keep", attachment = 1) + group(bin, "Recycle Bin", 43, entry(e1, "gone", attachment = 0)), binUuid = bin, pool = pool)
        val out = change.apply(input, listOf(CompanionOp.Delete(e1)))
        assertNull(out.entries()[e1])
        val deleted = out.root.child("Root")!!.child("DeletedObjects")!!.children("DeletedObject")
        assertEquals(listOf(e1 to now.toString()), deleted.map { it.child("UUID")!!.text() to it.child("DeletionTime")!!.text() })
        val items = out.meta().child("Binaries")!!.children("Binary")
        assertEquals(listOf("0" to h("b")), items.map { it.attribute("ID") to it.text() })
        assertEquals("0", out.entries().getValue(e2).child("Binary")!!.child("Value")!!.attribute("Ref"))
    }

    @Test
    fun `with the bin off a delete is permanent`() {
        val out = change.apply(export(entry(e1, "x"), binEnabled = false), listOf(CompanionOp.Delete(e1)))
        assertNull(out.entries()[e1])
        assertEquals(1, out.root.child("Root")!!.child("DeletedObjects")!!.children("DeletedObject").size)
    }

    @Test
    fun `KDBX 4_1 content is told by group tags, a disabled quality check, named icons or timed Meta custom data`() {
        assertEquals(false, KeePassXml.isKdbx41(export(entry(e1, "x"))))
        assertEquals(true, KeePassXml.isKdbx41(export(group(g, "G", 48, "<Tags>${h("t")}</Tags>"))))
        assertEquals(true, KeePassXml.isKdbx41(export(entry(e1, "x").replace("<IconID>0</IconID>", "<IconID>0</IconID><QualityCheck>False</QualityCheck>"))))
    }
}
