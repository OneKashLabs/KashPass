package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import java.time.format.DateTimeFormatter
import org.onekash.kashpass.vault.xml.XmlElement
import org.onekash.kashpass.vault.xml.XmlText

/**
 * The written expectation of the export diff: applies [CompanionOp]s to KeePass 2's hashed export
 * of the input as KeePass 2's own UI steps change its model, so that the result equals KeePass 2's
 * export of the file KashPass saved. Values are hashed under the run key, as the exporter hashes
 * them. A history trim by HistoryMaxSize is not predicted: KeePass 2 sizes history by plaintext
 * lengths the export hashes, so a test leaves that entry's history out of the comparison. A new
 * entry or recycle bin gets ExpiryTime = the time of the action, as KashPass writes it; KeePass 2
 * writes the time it started instead, a listed difference
 * ([CompanionComparison.NEW_OBJECT_EXPIRY]).
 */
internal class ExpectedChange(private val key: ByteArray, private val now: Instant) {

    private val time = DateTimeFormatter.ISO_INSTANT.format(now)

    /** Returns the hex HMAC-SHA-256 the exporter writes for [value]. */
    fun hash(value: String): String = KeePass2Report.mac(key, value.encodeToByteArray())

    /** Returns a copy of [input] with [ops] applied in order. */
    fun apply(input: KeePassXml, ops: List<CompanionOp>): KeePassXml {
        val xml = input.copy()
        val kdbx41 = KeePassXml.isKdbx41(input)
        for (op in ops) {
            when (op) {
                CompanionOp.NoEdit -> Unit
                is CompanionOp.Edit -> edit(xml, op)
                is CompanionOp.Add -> add(xml, op)
                is CompanionOp.Delete -> delete(xml, op.entry, kdbx41)
                is CompanionOp.DeleteCustomData -> error("KashPass offers no custom data editing")
            }
            renumberPool(xml)
        }
        return xml
    }

    // KeePass 2's entry dialog save: a copy without History appended to the history, the field
    // set, LastModificationTime and LastAccessTime now and one more use, then the history trimmed
    // by item count, oldest LastModificationTime first.
    private fun edit(xml: KeePassXml, op: CompanionOp.Edit) {
        val entry = xml.entries()[op.entry] ?: error("no entry ${op.entry}")
        val snapshot = KeePassXml.copyOf(entry)
        snapshot.child("History")?.let { snapshot.remove(it) }
        val history = entry.child("History") ?: XmlElement("History").also { entry.append(it) }
        clearText(history)
        history.append(snapshot)
        val string = entry.children("String").firstOrNull { it.child("Key")?.text() == op.field }
            ?: XmlElement("String").also { s ->
                s.append(leaf("Key", op.field))
                s.append(XmlElement("Value").also { if (op.field == "Password") it.setAttribute("ProtectInMemory", "True") })
                entry.append(s)
            }
        string.child("Value")!!.setText(hash(op.value))
        val times = entry.child("Times")!!
        times.child("LastModificationTime")!!.setText(time)
        times.child("LastAccessTime")!!.setText(time)
        bump(times)
        val max = xml.meta().child("HistoryMaxItems")?.text()?.trim()?.toIntOrNull() ?: 10
        if (max >= 0) {
            while (KeePassXml.history(entry).size > max) {
                val oldest = KeePassXml.history(entry).minBy { Instant.parse(it.child("Times")!!.child("LastModificationTime")!!.text().trim()) }
                history.remove(oldest)
            }
        }
    }

    // KeePass 2's Add Entry: icon from the group (a key for a folder icon, an email icon for an
    // email box), its custom icon, the vault's default user name, every time now, usage count 1;
    // appended after the group's last entry.
    private fun add(xml: KeePassXml, op: CompanionOp.Add) {
        val group = op.group?.let { xml.groups()[it] ?: error("no group $it") } ?: xml.rootGroup()
        val entry = XmlElement("Entry")
        entry.append(leaf("UUID", op.uuid))
        val icon = group.child("IconID")!!.text().trim().toInt()
        entry.append(leaf("IconID", (if (icon in setOf(48, 49, 50)) 0 else if (icon == 25) 19 else icon).toString()))
        group.child("CustomIconUUID")?.let { entry.append(leaf("CustomIconUUID", it.text().trim())) }
        entry.append(leaf("ForegroundColor", ""))
        entry.append(leaf("BackgroundColor", ""))
        entry.append(leaf("OverrideURL", hash("")))
        entry.append(leaf("Tags", hash("")))
        entry.append(newTimes(usage = 1))
        val userName = xml.meta().child("DefaultUserName")!!.text().trim()
        for ((k, v) in listOf("Notes" to hash(op.notes), "Password" to hash(op.password), "Title" to hash(op.title), "URL" to hash(op.url), "UserName" to userName)) {
            val value = leaf("Value", v).also { if (k == "Password") it.setAttribute("ProtectInMemory", "True") }
            entry.append(XmlElement("String").also { it.append(leaf("Key", k)); it.append(value) })
        }
        entry.append(XmlElement("AutoType").also { it.append(leaf("Enabled", "True")); it.append(leaf("DataTransferObfuscation", "0")) })
        entry.append(leaf("History", hash("")))
        insertEntry(group, entry)
    }

    // KeePass 2's delete: to the bin when it is on and the entry is outside it (creating the bin
    // when there is none), else permanently with one DeletedObject.
    private fun delete(xml: KeePassXml, uuid: String, kdbx41: Boolean) {
        val entry = xml.entries()[uuid] ?: error("no entry $uuid")
        val parent = entry.parent!!
        val meta = xml.meta()
        val enabled = meta.child("RecycleBinEnabled")?.text()?.trim().equals("True", ignoreCase = true)
        var bin = xml.bin()
        val inBin = bin != null && KeePassXml.inside(parent, bin)
        if (!enabled || inBin) {
            parent.remove(entry)
            val root = xml.root.child("Root")!!
            val deleted = root.child("DeletedObjects") ?: XmlElement("DeletedObjects").also { root.append(it) }
            clearText(deleted)
            deleted.append(XmlElement("DeletedObject").also { it.append(leaf("UUID", uuid)); it.append(leaf("DeletionTime", time)) })
            return
        }
        if (bin == null) bin = newBin(xml)
        parent.remove(entry)
        insertEntry(bin, entry)
        val times = entry.child("Times")!!
        times.child("LocationChanged")!!.setText(time)
        if (kdbx41) setPreviousParent(entry, KeePassXml.uuid(parent))
        // The entry, then its new parent groups: LastAccessTime now and one more use.
        for (e in generateSequence(entry) { it.parent }.filter { it.name == "Entry" || it.name == "Group" }) {
            val t = e.child("Times")!!
            t.child("LastAccessTime")!!.setText(time)
            bump(t)
        }
    }

    private fun newBin(xml: KeePassXml): XmlElement {
        val bin = XmlElement("Group")
        bin.append(leaf("UUID", BIN_PLACEHOLDER))
        bin.append(leaf("Name", hash("Recycle Bin")))
        bin.append(leaf("Notes", hash("")))
        bin.append(leaf("IconID", "43"))
        bin.append(newTimes(usage = 0))
        bin.append(leaf("IsExpanded", "True"))
        bin.append(leaf("DefaultAutoTypeSequence", hash("")))
        bin.append(leaf("EnableAutoType", "False"))
        bin.append(leaf("EnableSearching", "False"))
        bin.append(leaf("LastTopVisibleEntry", KeePassXml.ZERO_UUID))
        xml.rootGroup().append(bin)
        xml.meta().child("RecycleBinUUID")!!.setText(BIN_PLACEHOLDER)
        return bin
    }

    // KeePass 2 writes PreviousParentGroup right before Times.
    private fun setPreviousParent(entry: XmlElement, uuid: String) {
        entry.child("PreviousParentGroup")?.let { it.setText(uuid); return }
        entry.insert(entry.children.indexOf(entry.child("Times")!!), leaf("PreviousParentGroup", uuid))
    }

    // KeePass 2 writes the attachment pool from the tree on every save: each entry's own
    // attachments, then its history's, groups' entries before their child groups; unreferenced
    // items are dropped and the rest numbered from 0.
    private fun renumberPool(xml: KeePassXml) {
        val binaries = xml.meta().child("Binaries") ?: return
        val pool = binaries.children("Binary").associateBy { it.attribute("ID") }
        val order = LinkedHashSet<String>()
        fun refs(e: XmlElement) = e.children("Binary").mapNotNull { it.child("Value")?.attribute("Ref") }
        fun walk(g: XmlElement) {
            for (e in g.children("Entry")) {
                order += refs(e)
                KeePassXml.history(e).forEach { order += refs(it) }
            }
            g.children("Group").forEach(::walk)
        }
        walk(xml.rootGroup())
        val newId = order.withIndex().associate { (i, old) -> old to i.toString() }
        for (b in binaries.children("Binary")) binaries.remove(b)
        clearText(binaries)
        for (old in order) {
            val item = pool[old] ?: error("no pool item $old")
            item.setAttribute("ID", newId.getValue(old))
            binaries.append(item)
        }
        if (order.isEmpty()) binaries.setText(hash(""))
        fun rewrite(e: XmlElement) {
            if (e.name == "Value" && e.parent?.name == "Binary" && e.parent?.parent?.name == "Entry") {
                e.attribute("Ref")?.let { e.setAttribute("Ref", newId.getValue(it)) }
            }
            e.elements().forEach(::rewrite)
        }
        rewrite(xml.root.child("Root")!!)
    }

    // The Times of a new object: every time now, not expiring.
    private fun newTimes(usage: Int): XmlElement {
        val times = XmlElement("Times")
        for (n in listOf("CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime")) times.append(leaf(n, time))
        times.append(leaf("Expires", "False"))
        times.append(leaf("UsageCount", usage.toString()))
        times.append(leaf("LocationChanged", time))
        return times
    }

    private fun bump(times: XmlElement) {
        val usage = times.child("UsageCount")!!
        usage.setText(((usage.text().trim().toLongOrNull() ?: 0L) + 1).toString())
    }

    // A group's entries come after its own fields and before its child groups.
    private fun insertEntry(group: XmlElement, entry: XmlElement) {
        clearText(group)
        val kids = group.children
        val lastEntry = kids.indexOfLast { it is XmlElement && it.name == "Entry" }
        val firstGroup = kids.indexOfFirst { it is XmlElement && it.name == "Group" }
        group.insert(if (lastEntry >= 0) lastEntry + 1 else if (firstGroup >= 0) firstGroup else kids.size, entry)
    }

    // An element written empty arrives as a leaf holding the hash of the empty text; drop that text
    // before it gains children.
    private fun clearText(e: XmlElement) {
        e.children.filterIsInstance<XmlText>().forEach { e.remove(it) }
    }

    private fun leaf(name: String, text: String) = XmlElement(name).also { it.setText(text) }


    companion object {
        /**
         * The UUID ExpectedChange gives a recycle bin it creates; compare with a
         * [KeePassXml.Normal] input, which maps new UUIDs.
         */
        const val BIN_PLACEHOLDER = "QklOQklOQklOQklOQklOQg=="
    }
}
