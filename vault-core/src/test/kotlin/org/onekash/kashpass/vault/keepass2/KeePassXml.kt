package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import java.time.format.DateTimeParseException
import java.time.temporal.ChronoUnit
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.xml.XmlElement
import org.onekash.kashpass.vault.xml.XmlReadResult
import org.onekash.kashpass.vault.xml.XmlReader

/**
 * KeePass 2's hashed plain-XML export of one vault (`keepass2-read.sh --export`), read with
 * KashPass's own XML reader, and the flat form the parity tests compare: one line per leaf text
 * and attribute, keyed by a path in which groups and entries are named by UUID, history items by
 * position, and strings, attachments and custom data by their key. Values arrive hashed except the
 * structural ones the exporter keeps (UUIDs, times, flags, counts, colours).
 */
internal class KeePassXml(val root: XmlElement) {

    /**
     * How [flat] normalises: times inside [window] read `NOW`; UUIDs absent from [input] read
     * `NEW1`, `NEW2` in document order; UsageCount reads as a delta from [input] (`+1`), or
     * absolutely (`=1`) where the input has no such path; a standard string whose value is [empty]
     * (the hash of the empty text) is left out: an absent standard string equals an empty one.
     */
    class Normal(val input: KeePassXml? = null, val window: Window? = null, val empty: String? = null)

    /** A run's time span in whole seconds, the precision KDBX 4 stores. */
    class Window private constructor(val start: Instant, val end: Instant) {
        operator fun contains(t: Instant) = t >= start && t <= end

        companion object {
            /** Floors [start] and ceils [end] to whole seconds. */
            fun of(start: Instant, end: Instant): Window {
                val ceiled = end.truncatedTo(ChronoUnit.SECONDS).let { if (it < end) it.plusSeconds(1) else it }
                return Window(start.truncatedTo(ChronoUnit.SECONDS), ceiled)
            }
        }
    }

    /** Returns a deep copy to change, as ExpectedChange does. */
    fun copy(): KeePassXml = KeePassXml(root.deepCopy())

    /** Returns every element, depth first in document order. */
    fun all(): Sequence<XmlElement> = walk(root)

    /** Returns the current entries (history left out) by UUID. */
    fun entries(): Map<String, XmlElement> = walk(root).filter { it.name == "Entry" && it.parent?.name != "History" }.associateBy { uuid(it) }

    /** Returns the groups by UUID. */
    fun groups(): Map<String, XmlElement> = walk(root).filter { it.name == "Group" }.associateBy { uuid(it) }

    /** Returns the `Meta` element. */
    fun meta(): XmlElement = root.child("Meta")!!

    /** Returns the top-level group. */
    fun rootGroup(): XmlElement = root.child("Root")!!.child("Group")!!

    /**
     * Returns the group `Meta/RecycleBinUUID` names; null when there is none or it names the top
     * level.
     */
    fun bin(): XmlElement? = meta().child("RecycleBinUUID")?.text()?.trim()?.let { groups()[it] }?.takeIf { it !== rootGroup() }

    /** Returns the group `Meta/EntryTemplatesGroup` names, or null. */
    fun templates(): XmlElement? = meta().child("EntryTemplatesGroup")?.text()?.trim()?.let { groups()[it] }

    /** Returns the UUID of the current entry whose Title value is [titleHash], or null. */
    fun entryByTitle(titleHash: String): String? = entries().entries.firstOrNull { (_, e) -> field(e, "Title") == titleHash }?.key

    /**
     * Returns the current entries outside the recycle bin and the templates group, in document
     * order, leaving out those whose Title value is in [excludedTitles]: the entries the parity
     * tests act on.
     */
    fun eligibleEntries(excludedTitles: Set<String> = emptySet()): Map<String, XmlElement> {
        val excluded = listOfNotNull(bin(), templates())
        return entries().filter { (_, e) -> excluded.none { inside(e, it) } && field(e, "Title") !in excludedTitles }
    }

    /**
     * Returns every leaf text and attribute value by path, normalised by [normal], with an `@order`
     * line for each element holding groups, entries, deleted objects, custom icons or pool items.
     */
    fun flat(normal: Normal = Normal()): Map<String, String> {
        val inputUuids = normal.input?.let { i -> walk(i.root).filter { it.name in UUID_VALUES }.map { it.text().trim() }.toSet() }
        val fresh = LinkedHashMap<String, String>()
        fun mapUuid(v: String): String {
            if (inputUuids == null || v in inputUuids || v == ZERO_UUID || v.isEmpty()) return v
            return fresh.getOrPut(v) { "NEW${fresh.size + 1}" }
        }
        // Number new UUIDs in document order before building paths.
        walk(root).filter { it.name in UUID_VALUES }.forEach { mapUuid(it.text().trim()) }
        val inputUsage = normal.input?.flat()?.filterKeys { it.endsWith("/Times/UsageCount") }
        val out = LinkedHashMap<String, String>()
        fun visit(e: XmlElement, path: String) {
            for (a in e.attributes) out["$path/@${a.name}"] = a.value
            val kids = e.elements()
            if (kids.isEmpty()) {
                out[path] = leaf(e, path, normal, ::mapUuid, inputUsage)
                return
            }
            val keyed = kids.filter { it.name in ORDERED }
            if (keyed.isNotEmpty() && e.name != "History") out["$path/@order"] = keyed.joinToString(",") { key(it, kids, ::mapUuid) }
            for (k in kids) {
                if (normal.empty != null && isEmptyStandard(k, normal.empty)) continue
                visit(k, "$path/${key(k, kids, ::mapUuid)}")
            }
        }
        visit(root, root.name)
        return out
    }

    private fun leaf(e: XmlElement, path: String, normal: Normal, mapUuid: (String) -> String, inputUsage: Map<String, String>?): String {
        val text = e.text().trim()
        if (e.name in UUID_VALUES) return mapUuid(text)
        if (e.name == "UsageCount" && inputUsage != null) {
            val before = inputUsage[path]?.toLongOrNull() ?: return "=$text"
            val delta = (text.toLongOrNull() ?: return text) - before
            return if (delta >= 0) "+$delta" else "$delta"
        }
        if (normal.window != null && isTime(e)) {
            val t = try { Instant.parse(text) } catch (_: DateTimeParseException) { null }
            if (t != null && t in normal.window) return "NOW"
        }
        return text
    }

    private fun isEmptyStandard(e: XmlElement, empty: String): Boolean =
        e.name == "String" && e.parent?.name == "Entry" && e.child("Key")?.text() in CompanionOp.STANDARD && e.child("Value")?.text()?.trim() == empty

    companion object {
        /** Parses an export; fails the test on text KashPass's reader does not accept. */
        fun parse(text: String): KeePassXml {
            val bytes = text.encodeToByteArray()
            val read = XmlReader.read(bytes, 0, bytes.size, Int.MAX_VALUE)
            return KeePassXml((read as? XmlReadResult.Parsed ?: error("not XML: $read")).document.root)
        }

        /** Returns a detached deep copy of [e]. */
        fun copyOf(e: XmlElement): XmlElement = e.deepCopy()

        /** Returns whether [e] is [group] or lies inside it. */
        fun inside(e: XmlElement, group: XmlElement): Boolean = generateSequence(e) { it.parent }.any { it === group }

        /** Returns the value text of the String [key] of [entry], or null. */
        fun field(entry: XmlElement?, key: String): String? =
            entry?.children("String")?.firstOrNull { it.child("Key")?.text() == key }?.child("Value")?.text()?.trim()

        /**
         * Returns whether KeePass 2 writes [xml]'s content as KDBX 4.1: group tags, an entry with
         * the quality check off, a named or timed custom icon, or timed Meta custom data. KeePass 2
         * writes group Tags and QualityCheck elements only in 4.1, and only 4.1 content carries
         * PreviousParentGroup.
         */
        fun isKdbx41(xml: KeePassXml): Boolean = xml.all().any { e ->
            (e.name == "Tags" && e.parent?.name == "Group") ||
                (e.name == "QualityCheck") ||
                (e.parent?.name == "Icon" && e.name in setOf("Name", "LastModificationTime")) ||
                (e.name == "LastModificationTime" && e.parent?.name == "Item" && e.parent?.parent?.parent?.name == "Meta")
        }

        /** Returns the history items of [entry], oldest position first. */
        fun history(entry: XmlElement): List<XmlElement> = entry.child("History")?.children("Entry").orEmpty()

        /** Returns the UUID text of a group or entry. */
        fun uuid(e: XmlElement): String = e.child("UUID")?.text()?.trim().orEmpty()

        /**
         * Lists every path whose value differs between [expected] and [actual] as
         * `path: expected | actual`, `(absent)` for a missing side; empty when they are equal.
         */
        fun diff(expected: Map<String, String>, actual: Map<String, String>): List<String> =
            (expected.keys + actual.keys).toSortedSet().mapNotNull { k ->
                val a = expected[k]
                val b = actual[k]
                if (a == b) null else "$k: ${a ?: "(absent)"} | ${b ?: "(absent)"}"
            }

        /** The all-zero UUID in its Base64 form. */
        val ZERO_UUID: String = Uuids.format(Uuids.ZERO)

        // Elements whose text is a UUID or a UUID reference.
        private val UUID_VALUES = setOf(
            "UUID", "CustomIconUUID", "PreviousParentGroup", "LastTopVisibleEntry", "LastTopVisibleGroup",
            "LastSelectedGroup", "RecycleBinUUID", "EntryTemplatesGroup",
        )

        // Children whose order KeePass 2 keeps and a parent's `@order` line records.
        private val ORDERED = setOf("Group", "Entry", "DeletedObject", "Icon", "Binary")

        private val META_TIMES = setOf(
            "SettingsChanged", "DatabaseNameChanged", "DatabaseDescriptionChanged", "DefaultUserNameChanged",
            "RecycleBinChanged", "EntryTemplatesGroupChanged", "MasterKeyChanged", "DeletionTime", "LastModificationTime",
        )

        private fun isTime(e: XmlElement): Boolean =
            e.name in META_TIMES || (e.parent?.name == "Times" && e.name !in setOf("Expires", "UsageCount"))

        // The path segment of [e] among its siblings [kids].
        private fun key(e: XmlElement, kids: List<XmlElement>, mapUuid: (String) -> String): String = when {
            e.name == "Entry" && e.parent?.name == "History" -> "Entry#${kids.filter { it.name == "Entry" }.indexOf(e)}"
            e.name in setOf("Group", "Entry", "DeletedObject", "Icon") -> "${e.name}{${mapUuid(uuid(e))}}"
            e.name == "Binary" && e.parent?.name == "Binaries" -> "Binary#${e.attribute("ID")}"
            e.name in setOf("String", "Binary", "Item") -> "${e.name}{${e.child("Key")?.text()}}"
            kids.count { it.name == e.name } > 1 -> "${e.name}#${kids.filter { it.name == e.name }.indexOf(e)}"
            else -> e.name
        }

        private fun walk(e: XmlElement): Sequence<XmlElement> = sequence {
            yield(e)
            for (k in e.elements()) yieldAll(walk(k))
        }
    }
}
