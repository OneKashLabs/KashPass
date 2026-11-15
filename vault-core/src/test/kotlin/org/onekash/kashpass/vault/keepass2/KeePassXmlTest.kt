package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class KeePassXmlTest {

    private val empty = "e".repeat(64)

    // A hashed export with one group G holding [entries] (each already an <Entry> element).
    private fun export(entries: String, deleted: String = "", groupTimes: String = time("2026-01-01T00:00:00Z")) = KeePassXml.parse(
        """
        <KeePassFile>
         <Meta><HistoryMaxItems>10</HistoryMaxItems><RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID></Meta>
         <Root>
          <Group><UUID>R0dHR0dHR0dHR0dHR0dHRw==</UUID><Name>${"a".repeat(64)}</Name><Times>$groupTimes</Times>
           $entries
          </Group>
          <DeletedObjects>$deleted</DeletedObjects>
         </Root>
        </KeePassFile>
        """.trimIndent(),
    )

    private fun time(modified: String, usage: Int = 3) =
        "<LastModificationTime>$modified</LastModificationTime><LastAccessTime>$modified</LastAccessTime><UsageCount>$usage</UsageCount>"

    private fun entry(uuid: String, title: String, modified: String = "2026-01-02T00:00:00Z", usage: Int = 3, history: String = "", notes: String? = null) =
        "<Entry><UUID>$uuid</UUID><Times>${time(modified, usage)}</Times>" +
            "<String><Key>Title</Key><Value>$title</Value></String>" +
            (notes?.let { "<String><Key>Notes</Key><Value>$it</Value></String>" } ?: "") +
            "<History>$history</History></Entry>"

    private val e1 = "RTFFMUUxRTFFMUUxRTFFMQ=="
    private val e2 = "RTJFMkUyRTJFMkUyRTJFMg=="

    @Test
    fun `equal exports have no differences and a changed value is named by its path`() {
        val a = export(entry(e1, "1".repeat(64)))
        assertEquals(emptyList(), KeePassXml.diff(a.flat(), export(entry(e1, "1".repeat(64))).flat()))
        val diff = KeePassXml.diff(a.flat(), export(entry(e1, "2".repeat(64))).flat())
        assertEquals(1, diff.size, "$diff")
        assertTrue(diff.single().startsWith("KeePassFile/Root/Group{R0dHR0dHR0dHR0dHR0dHRw==}/Entry{$e1}/String{Title}/Value:"), diff.single())
    }

    @Test
    fun `an element on one side only is a difference`() {
        val a = export(entry(e1, "1".repeat(64)))
        val b = export(entry(e1, "1".repeat(64)), deleted = "<DeletedObject><UUID>$e2</UUID><DeletionTime>2026-01-03T00:00:00Z</DeletionTime></DeletedObject>")
        val diff = KeePassXml.diff(a.flat(), b.flat())
        assertTrue(diff.any { "DeletedObject{$e2}/DeletionTime" in it && "(absent)" in it }, "$diff")
    }

    @Test
    fun `a time inside the window reads NOW, a time outside stays literal`() {
        val window = KeePassXml.Window.of(Instant.parse("2026-03-01T10:00:00.400Z"), Instant.parse("2026-03-01T10:00:05.200Z"))
        val a = export(entry(e1, "1".repeat(64), modified = "2026-03-01T10:00:00Z"))
        val b = export(entry(e1, "1".repeat(64), modified = "2026-03-01T10:00:06Z"))
        val c = export(entry(e1, "1".repeat(64), modified = "2026-03-01T10:00:07Z"))
        // The window is floored and ceiled to whole seconds, as KDBX 4 stores them.
        assertEquals(emptyList(), KeePassXml.diff(a.flat(KeePassXml.Normal(window = window)), b.flat(KeePassXml.Normal(window = window))))
        assertTrue(KeePassXml.diff(a.flat(KeePassXml.Normal(window = window)), c.flat(KeePassXml.Normal(window = window))).isNotEmpty())
        assertEquals("NOW", a.flat(KeePassXml.Normal(window = window)).getValue("KeePassFile/Root/Group{R0dHR0dHR0dHR0dHR0dHRw==}/Entry{$e1}/Times/LastModificationTime"))
    }

    @Test
    fun `removing the wrong history item is a difference though the items differ only in time`() {
        fun item(t: String) = entry(e1, "1".repeat(64), modified = t)
        val oldest = item("2026-01-01T01:00:00Z")
        val middle = item("2026-01-01T02:00:00Z")
        val newest = item("2026-01-01T03:00:00Z")
        val keptRight = export(entry(e1, "1".repeat(64), history = middle + newest))
        val keptWrong = export(entry(e1, "1".repeat(64), history = oldest + middle))
        val diff = KeePassXml.diff(keptRight.flat(), keptWrong.flat())
        assertTrue(diff.any { "History/Entry#0/Times/LastModificationTime" in it }, "$diff")
    }

    @Test
    fun `UUIDs new in the run are numbered in document order, so two random draws compare equal`() {
        val input = export(entry(e1, "1".repeat(64)))
        val a = export(entry(e1, "1".repeat(64)) + entry("TjFOMU4xTjFOMU4xTjFOMQ==", "3".repeat(64), usage = 1))
        val b = export(entry(e1, "1".repeat(64)) + entry("TjJOMk4yTjJOMk4yTjJOMg==", "3".repeat(64), usage = 1))
        val normal = KeePassXml.Normal(input = input)
        assertEquals(emptyList(), KeePassXml.diff(a.flat(normal), b.flat(normal)))
        assertTrue(a.flat(normal).keys.any { "Entry{NEW1}" in it })
    }

    @Test
    fun `UsageCount compares as a delta from the input, and absolutely for new objects`() {
        val input = export(entry(e1, "1".repeat(64), usage = 3))
        val normal = KeePassXml.Normal(input = input)
        val flat = export(entry(e1, "1".repeat(64), usage = 4) + entry(e2, "2".repeat(64), usage = 1)).flat(normal)
        assertEquals("+1", flat.getValue("KeePassFile/Root/Group{R0dHR0dHR0dHR0dHR0dHRw==}/Entry{$e1}/Times/UsageCount"))
        assertEquals("=1", flat.getValue("KeePassFile/Root/Group{R0dHR0dHR0dHR0dHR0dHRw==}/Entry{NEW1}/Times/UsageCount"))
    }

    @Test
    fun `an absent standard string equals one holding the hash of the empty text`() {
        val normal = KeePassXml.Normal(empty = empty)
        val absent = export(entry(e1, "1".repeat(64)))
        val emptyNotes = export(entry(e1, "1".repeat(64), notes = empty))
        assertEquals(emptyList(), KeePassXml.diff(absent.flat(normal), emptyNotes.flat(normal)))
        assertTrue(KeePassXml.diff(absent.flat(normal), export(entry(e1, "1".repeat(64), notes = "9".repeat(64))).flat(normal)).isNotEmpty())
    }

    @Test
    fun `the order of entries in a group is compared`() {
        val ab = export(entry(e1, "1".repeat(64)) + entry(e2, "2".repeat(64)))
        val ba = export(entry(e2, "2".repeat(64)) + entry(e1, "1".repeat(64)))
        val diff = KeePassXml.diff(ab.flat(), ba.flat())
        assertTrue(diff.any { it.startsWith("KeePassFile/Root/Group{R0dHR0dHR0dHR0dHR0dHRw==}/@order") }, "$diff")
    }

    @Test
    fun `entries and history are found by UUID with their parent group`() {
        val x = export(entry(e1, "1".repeat(64), history = entry(e1, "0".repeat(64))))
        assertEquals(setOf(e1), x.entries().keys)
        assertEquals(1, KeePassXml.history(x.entries().getValue(e1)).size)
        assertEquals("R0dHR0dHR0dHR0dHR0dHRw==", KeePassXml.uuid(x.entries().getValue(e1).parent!!))
    }
}
