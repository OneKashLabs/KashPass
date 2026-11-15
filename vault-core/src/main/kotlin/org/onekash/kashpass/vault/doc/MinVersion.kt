package org.onekash.kashpass.vault.doc

import java.nio.ByteBuffer
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * Computes the lowest KDBX 4 minor version that holds a document's content, checked before a
 * save. 1 when any of these is present, else 0:
 * - a group in the root group's tree, the root group included, whose `Tags` hold a tag after the
 *   split (split on ',' and ';', each part trimmed, empty parts dropped);
 * - an entry of that tree, not a history entry, whose `QualityCheck` is exactly "False" (any
 *   other text keeps the default, true);
 * - a `Meta/CustomIcons/Icon` that a reader keeps (a UUID other than zero and non-empty `Data`)
 *   with a non-empty `Name` or a `LastModificationTime`;
 * - a `Meta/CustomData/Item` with a `Key` and a `Value` whose last item for that key has a
 *   `LastModificationTime` (the last item for a key replaces the earlier ones).
 *
 * It reads element text as the tree holds it; a protected `QualityCheck` or `Tags` element (no
 * writer produces one) is read through the document's protected values. [MinVersionTest] pins
 * each rule.
 */
internal object MinVersion {

    private val FALSE = "False".encodeToByteArray()

    /** Returns 0 or 1 for the tree of [root], with [protectedValues] as the decoder read them. */
    fun of(root: XmlElement, protectedValues: Map<XmlElement, ProtectedText>): Int {
        val group = rootGroupOf(root)
        if (group != null && groupNeeds41(group, protectedValues)) return 1
        for (meta in root.children("Meta")) {
            for (icons in meta.children("CustomIcons")) {
                for (icon in icons.children("Icon")) if (iconNeeds41(icon)) return 1
            }
            val lastModified = LinkedHashMap<String, Boolean>()
            for (data in meta.children("CustomData")) {
                for (item in data.children("Item")) {
                    val key = item.child("Key") ?: continue
                    if (item.child("Value") == null) continue
                    lastModified[key.text()] = item.child("LastModificationTime") != null
                }
            }
            if (lastModified.values.any { it }) return 1
        }
        return 0
    }

    // Pre-order over [group] and its subgroups; depth is bounded by XmlReader.MAX_DEPTH.
    private fun groupNeeds41(group: XmlElement, values: Map<XmlElement, ProtectedText>): Boolean {
        val tags = group.child("Tags")
        if (tags != null && hasTag(tags, values)) return true
        for (entry in group.children("Entry")) {
            val check = entry.child("QualityCheck") ?: continue
            if (isFalse(check, values)) return true
        }
        return group.children("Group").any { groupNeeds41(it, values) }
    }

    private fun hasTag(tags: XmlElement, values: Map<XmlElement, ProtectedText>): Boolean {
        val protected = values[tags] ?: return hasTag(tags.text())
        val bytes = protected.utf8()
        val chars = Charsets.UTF_8.decode(ByteBuffer.wrap(bytes))
        return try {
            hasTag(chars)
        } finally {
            bytes.fill(0)
            chars.clear()
            while (chars.hasRemaining()) chars.put('\u0000')
        }
    }

    // A part between separators holds a character that trimming keeps.
    private fun hasTag(text: CharSequence): Boolean = text.any { it != ',' && it != ';' && !it.isWhitespace() }

    private fun isFalse(check: XmlElement, values: Map<XmlElement, ProtectedText>): Boolean {
        val protected = values[check] ?: return check.text() == "False"
        val bytes = protected.utf8()
        return try {
            bytes.contentEquals(FALSE)
        } finally {
            bytes.fill(0)
        }
    }

    private fun iconNeeds41(icon: XmlElement): Boolean {
        val uuid = Uuids.parse(icon.child("UUID")?.text())
        if (uuid == null || uuid == Uuids.ZERO) return false
        if (icon.child("Data")?.text().isNullOrEmpty()) return false
        return !icon.child("Name")?.text().isNullOrEmpty() || icon.child("LastModificationTime") != null
    }
}
