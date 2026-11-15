package org.onekash.kashpass.vault.edit

import java.time.Instant
import org.onekash.kashpass.vault.doc.EntryParts
import org.onekash.kashpass.vault.doc.KdbxTime
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * Trims an entry's history after a snapshot is added: first to HistoryMaxItems, then to
 * HistoryMaxSize, each skipped when negative, always removing the item with the oldest
 * LastModificationTime (the first one on a tie). The history is every `History` block's entries in
 * document order, read as one list ([EntryParts.history]). Sizes are the estimate of an entry's
 * memory that [size] returns.
 * [HistoryTrimTest] and [org.onekash.kashpass.vault.doc.DuplicateChildrenTest] pin it.
 */
internal object HistoryTrim {

    /**
     * Trims [entry]'s history in [document], a copy the caller owns. Returns true when it removed
     * an item.
     */
    fun maintain(document: VaultDocument, entry: XmlElement): Boolean {
        val meta = document.meta
        var removed = false
        val maxItems = meta.historyMaxItems
        if (maxItems >= 0) {
            while (EntryParts.history(entry).size > maxItems) {
                removeOldest(document, entry)
                removed = true
            }
        }
        val maxSize = meta.historyMaxSize
        if (maxSize >= 0) {
            while (true) {
                val items = EntryParts.history(entry)
                if (items.isEmpty() || items.sumOf { size(document, it) } <= maxSize) break
                removeOldest(document, entry)
                removed = true
            }
        }
        return removed
    }

    // Removes the history item of [entry] with the oldest LastModificationTime, the first in
    // document order on a tie; its History block stays.
    private fun removeOldest(document: VaultDocument, entry: XmlElement) {
        var oldest: XmlElement? = null
        var oldestTime = Instant.MAX
        for (item in EntryParts.history(entry)) {
            // An unreadable time sorts first.
            val time = item.child("Times")?.child("LastModificationTime")?.text()?.let(KdbxTime::parse) ?: Instant.MIN
            if (time < oldestTime) {
                oldest = item
                oldestTime = time
            }
        }
        oldest?.let { removeSubtree(document, it.parent!!, it) }
    }

    /**
     * Returns an estimate of an entry's memory size: fixed costs plus 2 bytes per char. Fields and
     * attachments count once per name, each read by its last `Key` and last `Value`
     * ([EntryParts]).
     */
    fun size(document: VaultDocument, entry: XmlElement): Long {
        var cb = 276L
        var cc = 0L
        val strings = byKey(entry, "String")
        cb += strings.size * 40L
        for ((key, value) in strings) {
            cc += key.length
            cc += if (value?.attribute("Protected") == "True") document.protectedValues[value]?.utf16Length ?: 0 else value?.text().orEmpty().length
        }
        val binaries = byKey(entry, "Binary")
        cb += binaries.size * 65L
        for ((key, value) in binaries) {
            cc += key.length
            val ref = value?.attribute("Ref")?.trim()?.toIntOrNull()
            cb += ref?.let(document::attachmentSize) ?: 0L
        }
        val autoType = entry.child("AutoType")
        cc += autoType?.child("DefaultSequence")?.text().orEmpty().length
        val associations = autoType?.children("Association").orEmpty()
        cb += associations.size * 24L
        for (a in associations) cc += a.child("Window")?.text().orEmpty().length + a.child("KeystrokeSequence")?.text().orEmpty().length
        val history = EntryParts.history(entry)
        cb += history.size * 8L
        for (item in history) cb += size(document, item)
        cc += entry.child("OverrideURL")?.text().orEmpty().length
        val tags = entry.child("Tags")?.text().orEmpty().split(',', ';').map { it.trim() }.filter { it.isNotEmpty() }
        cb += tags.size * 8L
        for (tag in tags) cc += tag.length
        val custom = entry.child("CustomData")?.children("Item").orEmpty()
        cb += custom.size * 16L
        for (item in custom) cc += item.child("Key")?.text().orEmpty().length + item.child("Value")?.text().orEmpty().length
        return cb + (cc shl 1)
    }

    // The last Value of each `String` or `Binary` ([name]) of [entry] by its last Key; a later
    // element with the same Key replaces an earlier one.
    private fun byKey(entry: XmlElement, name: String): Map<String, XmlElement?> {
        val out = HashMap<String, XmlElement?>()
        for (part in entry.children(name)) out[EntryParts.key(part)?.text().orEmpty()] = EntryParts.value(part)
        return out
    }

    /** Removes [node] from [parent] and drops the protected values inside it. */
    fun removeSubtree(document: VaultDocument, parent: XmlElement, node: XmlElement) {
        parent.remove(node)
        fun forget(e: XmlElement) {
            document.protectedValues.remove(e)
            e.elements().forEach(::forget)
        }
        forget(node)
    }
}
