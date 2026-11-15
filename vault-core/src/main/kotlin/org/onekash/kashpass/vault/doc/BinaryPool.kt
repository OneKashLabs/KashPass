package org.onekash.kashpass.vault.doc

import java.nio.ByteBuffer
import java.util.Collections
import java.util.IdentityHashMap
import org.onekash.kashpass.vault.kdbx.Attachment
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * The attachment list of a document and the pool a save writes from it.
 *
 * At open, [opened] lists every attachment once: the pool items in ID order, then each item that
 * a reference resolved to before a later `Meta/Binaries` item replaced it. Each
 * `Entry/Binary/Value` whose `Ref` resolved is rewritten when its number differs from the item's
 * index, so from then on `Ref` n names [VaultDocument.attachments] n; a pool numbered 0 to n-1
 * with each reference naming its own item has no rewrite and writes out byte for byte. Edits
 * never change the list: a history snapshot copies the `Ref`, and a deleted reference leaves its
 * item for the save to drop.
 *
 * A save writes the pool [rebuild] computes. [BinaryPoolTest] pins both.
 *
 * Only the values a save writes count ([values]): the last `Value` of each `Binary`, the one
 * that takes effect. A `Value` the save leaves out ([EntryParts.omitted]) keeps its `Ref` as read,
 * and an item only such a `Value` names is not saved.
 */
internal object BinaryPool {

    /**
     * The pool of one save: [attachments] in inner-header order, and the `Ref` to write for each
     * value whose number changes ([ref]). The arrays are the document's; nothing here copies or
     * zero-fills them.
     */
    class Rebuilt internal constructor(val attachments: List<Attachment>, private val refs: Map<XmlElement, String>) {
        /** Returns the `Ref` to write for [value] in place of the tree's, or null to keep it. */
        fun ref(value: XmlElement): String? = refs[value]
    }

    /**
     * Returns the attachment list of [read] and rewrites, in [read]'s tree, each resolved `Ref`
     * whose number differs from its item's index. A value whose `Ref` named no item stays as read
     * (the document opens read-only); a value with no `Ref` keeps its inline content.
     */
    fun opened(read: ContainerRead): List<Attachment> {
        val list = ArrayList<Attachment>()
        val index = IdentityHashMap<Attachment, Int>()
        fun add(a: Attachment) {
            if (!index.containsKey(a)) {
                index[a] = list.size
                list += a
            }
        }
        for (a in read.pool.values) add(a)
        val values = values(read.xml.root)
        // A value outside the entry contexts of [KdbxXmlContext] is not in
        // [ContainerRead.references]; its Ref names the pool as read last.
        val resolved = values.map { v -> v to if (read.references.containsKey(v)) read.references[v] else ref(v)?.let(read.pool::get) }
        for ((_, a) in resolved) if (a != null) add(a)
        for ((value, a) in resolved) {
            if (a == null) continue
            val new = index.getValue(a)
            if (ref(value) != new) value.setAttribute("Ref", new.toString())
        }
        return list
    }

    /**
     * Returns the pool to save for [document], without changing it. The order: the root group's
     * tree in pre-order with a group's entries before its subgroups, and for each entry its
     * attachments, each `Binary` by its last `Key` and last `Value` ([EntryParts]), in ordinal
     * name order, then each history entry's, from every `History` block in order, the same way.
     * Values the walk does not reach (an entry outside the root group's tree) follow in document
     * order. An item equal to an earlier one in content and protection flag is that item; an item
     * no value names is dropped. A value whose `Ref` names no item of the list is written as it
     * is.
     */
    fun rebuild(document: VaultDocument): Rebuilt = rebuild(document.xml.root, document.attachments)

    /** [rebuild] over the tree of [root] and the attachment list [attachments]. */
    fun rebuild(root: XmlElement, attachments: List<Attachment>): Rebuilt {
        val out = ArrayList<Attachment>()
        val byIdentity = IdentityHashMap<Attachment, Int>()
        val byContent = HashMap<Pair<Boolean, ByteBuffer>, Int>()
        val refs = IdentityHashMap<XmlElement, String>()
        val seen: MutableSet<XmlElement> = Collections.newSetFromMap(IdentityHashMap())

        fun visit(value: XmlElement) {
            if (!seen.add(value)) return
            val old = ref(value) ?: return
            val item = attachments.getOrNull(old) ?: return
            val content = item.protected to ByteBuffer.wrap(item.data)
            val at = byIdentity[item] ?: byContent[content] ?: out.size.also {
                out += item
                byContent[content] = it
            }
            byIdentity[item] = at
            if (at != old) refs[value] = at.toString()
        }

        fun entry(entry: XmlElement) {
            entry.children("Binary").sortedBy { EntryParts.key(it)?.text().orEmpty() }.forEach { b -> EntryParts.value(b)?.let(::visit) }
        }

        // Depth is bounded by XmlReader.MAX_DEPTH.
        fun group(group: XmlElement) {
            for (e in group.children("Entry")) {
                entry(e)
                EntryParts.history(e).forEach(::entry)
            }
            group.children("Group").forEach(::group)
        }

        rootGroupOf(root)?.let(::group)
        values(root).forEach(::visit)
        return Rebuilt(out, refs)
    }

    /**
     * Returns every Entry/Binary/Value with a `Ref` under [root] that a save writes, in document
     * order: the last Value of each Binary, outside the elements a save leaves out
     * ([EntryParts.omitted]).
     */
    internal fun values(root: XmlElement): List<XmlElement> {
        val out = ArrayList<XmlElement>()
        val omitted = EntryParts.omitted(root)
        fun walk(element: XmlElement) {
            if (element in omitted) return
            if (element.name == "Binary" && element.parent?.name == "Entry") {
                EntryParts.value(element)?.takeIf { it.attribute("Ref") != null }?.let(out::add)
            }
            for (child in element.elements()) walk(child)
        }
        walk(root)
        return out
    }

    // The Ref of [value] read by [parseInt32Invariant]; null when absent, empty or not a number.
    private fun ref(value: XmlElement): Int? = value.attribute("Ref")?.takeIf { it.isNotEmpty() }?.let(::parseInt32Invariant)
}
