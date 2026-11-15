package org.onekash.kashpass.vault.doc

import java.util.UUID
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * Turns UUIDs into ids that are unique within one vault. A file with repeated UUIDs opens; the
 * second use of a UUID gets "<uuid>#2", so rows, chips, details and edits never collide.
 */
internal class UniqueIds {
    private val seen = HashMap<UUID, Int>()

    fun next(uuid: UUID): String {
        val n = seen.merge(uuid, 1, Int::plus)!!
        return if (n == 1) uuid.toString() else "$uuid#$n"
    }
}

/**
 * The ids the index shows for a document's entries and groups, with their elements. Both walk the
 * groups depth first, each group's entries before its child groups, as VaultIndex does, so an id
 * from the index finds the same element here. History entries have no id.
 */
internal object DocumentIds {

    fun entries(document: VaultDocument): Map<String, XmlElement> {
        val ids = UniqueIds()
        val out = LinkedHashMap<String, XmlElement>()
        walk(document.rootGroup) { group -> for (entry in group.entries()) out[ids.next(entry.uuid ?: Uuids.ZERO)] = entry.element }
        return out
    }

    fun groups(document: VaultDocument): Map<String, XmlElement> {
        val ids = UniqueIds()
        val out = LinkedHashMap<String, XmlElement>()
        walk(document.rootGroup) { group -> out[ids.next(group.uuid ?: Uuids.ZERO)] = group.element }
        return out
    }

    // Depth is bounded by XmlReader.MAX_DEPTH.
    private fun walk(group: GroupView, action: (GroupView) -> Unit) {
        action(group)
        for (child in group.groups()) walk(child, action)
    }
}
