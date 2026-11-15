package org.onekash.kashpass.vault.edit

import java.time.Instant
import java.util.UUID
import org.onekash.kashpass.vault.doc.BinaryPool
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.GroupView
import org.onekash.kashpass.vault.doc.KdbxTime
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.xml.XmlElement
import org.onekash.kashpass.vault.xml.XmlText

/**
 * How [EntryDelete.delete] treats an entry; the app reads it before a delete to confirm a permanent
 * one.
 */
enum class DeleteKind {
    /** Moved to the recycle bin. */
    TO_RECYCLE_BIN,

    /** Removed with its history; irreversible. */
    PERMANENT,
}

/** Outcome of [EntryDelete.delete]. */
class Deleted(val document: VaultDocument, val kind: DeleteKind)

/**
 * Deletes entries: to the recycle bin when it is enabled and the entry is outside it, permanently
 * otherwise. Works on a copy; the input document is never changed. [DeleteEntryTest] pins each
 * rule.
 */
object EntryDelete {

    private const val ICON_TRASH_BIN = 43

    /** Returns how [delete] deletes [entryId], or null when the entry is unknown. */
    fun kindOf(document: VaultDocument, entryId: String): DeleteKind? {
        val entry = DocumentIds.entries(document)[entryId] ?: return null
        val meta = document.meta
        if (!meta.recycleBinEnabled) return DeleteKind.PERMANENT
        return if (EntryEdits.inRecycleBin(document, entry.parent!!)) DeleteKind.PERMANENT else DeleteKind.TO_RECYCLE_BIN
    }

    /**
     * Deletes [entryId]. To the bin: the entry moves to the end of the recycle bin (created under
     * the top level when the vault has none, or its group is gone), LocationChanged becomes [now],
     * PreviousParentGroup records its old group when the save writes KDBX 4.1
     * ([VaultDocument.savedMinor]), and the entry's and every ancestor group's LastAccessTime
     * becomes [now] and their UsageCount goes up by one; no history snapshot, LastModificationTime
     * unchanged.
     * Permanently: the entry and its history go and one DeletedObject is added; a save drops the
     * attachments left without a reference ([BinaryPool.rebuild]). Returns null for an unknown
     * entry.
     */
    fun delete(document: VaultDocument, entryId: String, now: Instant): Deleted? {
        val kind = kindOf(document, entryId) ?: return null
        val copy = document.copy()
        val entry = DocumentIds.entries(copy).getValue(entryId)
        val parent = entry.parent!!
        val time = KdbxTime.format(now)
        if (kind == DeleteKind.PERMANENT) {
            val uuid = entry.child("UUID")?.text()
            HistoryTrim.removeSubtree(copy, parent, entry)
            // DeletedObjects goes in Root, beside the root group.
            val root = copy.rootGroup.element.parent!!
            val deleted = root.child("DeletedObjects") ?: XmlElement("DeletedObjects").also { root.append(it) }
            deleted.append(element("DeletedObject", leaf("UUID", uuid.orEmpty()), leaf("DeletionTime", time)))
            return Deleted(copy, kind)
        }
        val bin = recycleBin(copy, now)
        parent.remove(entry)
        val lastEntry = bin.children.indexOfLast { it is XmlElement && it.name == "Entry" }
        val firstGroup = bin.children.indexOfFirst { it is XmlElement && it.name == "Group" }
        bin.insert(if (lastEntry >= 0) lastEntry + 1 else if (firstGroup >= 0) firstGroup else bin.children.size, entry)
        if (copy.savedMinor() >= 1) setPreviousParent(entry, parent.child("UUID")?.text().orEmpty())
        val times = entry.child("Times") ?: XmlElement("Times").also { entry.append(it) }
        setLeaf(times, "LocationChanged", time)
        touch(entry, time)
        var group: XmlElement? = bin
        while (group != null && group.name == "Group") {
            touch(group, time)
            group = group.parent
        }
        return Deleted(copy, kind)
    }

    // The enabled recycle bin, created when it is missing.
    private fun recycleBin(document: VaultDocument, now: Instant): XmlElement {
        val root = document.rootGroup.element
        val uuid = document.meta.recycleBinUuid
        DocumentIds.groups(document).values.firstOrNull { it !== root && uuid != null && GroupView(it, document).uuid == uuid }?.let { return it }
        val time = KdbxTime.format(now)
        val id = UUID.randomUUID()
        val times = element(
            "Times",
            leaf("CreationTime", time), leaf("LastModificationTime", time), leaf("LastAccessTime", time),
            leaf("ExpiryTime", time), leaf("Expires", "False"), leaf("UsageCount", "0"), leaf("LocationChanged", time),
        )
        val bin = element(
            "Group",
            leaf("UUID", Uuids.format(id)), leaf("Name", "Recycle Bin"), XmlElement("Notes"), leaf("IconID", ICON_TRASH_BIN.toString()),
            times, leaf("IsExpanded", "True"), XmlElement("DefaultAutoTypeSequence"), leaf("EnableAutoType", "False"),
            leaf("EnableSearching", "False"), leaf("LastTopVisibleEntry", Uuids.format(Uuids.ZERO)),
        )
        root.append(bin)
        val meta = document.xml.root.child("Meta") ?: XmlElement("Meta").also { document.xml.root.insert(0, it) }
        setLeaf(meta, "RecycleBinUUID", Uuids.format(id))
        return bin
    }

    // PreviousParentGroup goes right before Times.
    private fun setPreviousParent(entry: XmlElement, parentUuid: String) {
        val existing = entry.child("PreviousParentGroup")
        if (existing != null) {
            existing.setText(parentUuid)
            return
        }
        val times = entry.children.indexOfFirst { it is XmlElement && it.name == "Times" }
        entry.insert(if (times >= 0) times else entry.children.size, leaf("PreviousParentGroup", parentUuid))
    }

    private fun touch(element: XmlElement, time: String) {
        val times = element.child("Times") ?: XmlElement("Times").also { element.append(it) }
        setLeaf(times, "LastAccessTime", time)
        val count = times.child("UsageCount")?.text()?.trim()?.toULongOrNull() ?: 0UL
        setLeaf(times, "UsageCount", (count + 1UL).toString())
    }

    private fun setLeaf(parent: XmlElement, name: String, value: String) {
        val element = parent.child(name) ?: XmlElement(name).also { parent.append(it) }
        element.setText(value)
    }

    private fun leaf(name: String, value: String) = XmlElement(name).apply { if (value.isNotEmpty()) append(XmlText(value)) }

    private fun element(name: String, vararg children: XmlElement) = XmlElement(name).apply { children.forEach(::append) }
}
