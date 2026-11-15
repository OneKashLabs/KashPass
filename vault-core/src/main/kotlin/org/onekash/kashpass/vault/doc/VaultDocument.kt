package org.onekash.kashpass.vault.doc

import java.nio.ByteBuffer
import java.time.Instant
import java.util.Base64
import java.util.Collections
import java.util.IdentityHashMap
import java.util.UUID
import org.onekash.kashpass.vault.kdbx.Attachment
import org.onekash.kashpass.vault.kdbx.SaveSettings
import org.onekash.kashpass.vault.xml.XmlDocument
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * A decrypted vault: the XML exactly as read ([xml]), the protected values decrypted in document
 * order and held masked, the outer header [settings] a save writes again, the [attachments] the
 * entries name by number ([BinaryPool]) and the session's [credentials]. Nothing outside
 * vault-core sees these parts.
 */
class VaultDocument internal constructor(
    internal val xml: XmlDocument,
    internal val settings: SaveSettings,
    /**
     * The attachments: `Ref` n of an entry attachment names item n ([BinaryPool.opened]). Every
     * [copy] shares the list, which never changes; nothing zero-fills an array a document holds.
     */
    internal val attachments: List<Attachment>,
    /** The key parts the session unlocked with; a save derives its key from them. */
    internal val credentials: VaultKey,
    /**
     * Protected values by element; elements don't override equals, so keys match by identity.
     * Mutated only on a fresh [copy], by the edit functions that own it.
     */
    internal val protectedValues: MutableMap<XmlElement, ProtectedText>,
    /** Size of the decrypted XML in bytes. */
    internal val xmlBytes: Long,
    val saveability: Saveability,
) {
    /**
     * The opened file's minor KDBX 4 version, capped at 1: 0 or 1. A save writes at least this
     * ([MinVersion]).
     */
    val kdbxMinor: Int get() = minOf(settings.openedMinor, 1)

    /**
     * Returns the minor version a save of this document writes: [MinVersion], never below
     * [kdbxMinor].
     */
    internal fun savedMinor(): Int = maxOf(MinVersion.of(xml.root, protectedValues), kdbxMinor)

    internal val meta: MetaView get() = MetaView(xml.root.child("Meta"))

    /** The top-level group ([rootGroupOf]); the decoder refuses a document without one. */
    internal val rootGroup: GroupView get() = GroupView(rootGroupOf(xml.root)!!, this)

    /**
     * Returns an independent copy for an edit: a new tree with the protected values mapped onto
     * its elements, sharing the immutable settings, attachments and credentials. The session's
     * document is never edited.
     */
    internal fun copy(): VaultDocument {
        val copied = xml.copy()
        val values = HashMap<XmlElement, ProtectedText>()
        // deepCopy keeps the structure, so the two trees line up element for element.
        fun pair(from: XmlElement, to: XmlElement) {
            protectedValues[from]?.let { values[to] = it }
            from.elements().zip(to.elements()).forEach { (a, b) -> pair(a, b) }
        }
        pair(xml.root, copied.root)
        return VaultDocument(copied, settings, attachments, credentials, values, xmlBytes, saveability)
    }

    /** Returns the size of attachment [index], or null when there is none. */
    internal fun attachmentSize(index: Int): Long? = attachments.getOrNull(index)?.data?.size?.toLong()

    /**
     * Returns this document read-only for [reason]; it shares the tree, which read-only documents
     * never change.
     */
    internal fun readOnly(reason: ReadOnlyReason) =
        VaultDocument(xml, settings, attachments, credentials, protectedValues, xmlBytes, Saveability.ReadOnly(reason))

    override fun toString() = "VaultDocument(4.$kdbxMinor)"
}

/**
 * Returns the root group of the document [root]: each `Group` in a `Root` replaces the one before,
 * so the last one, or null when there is none.
 */
internal fun rootGroupOf(root: XmlElement): XmlElement? = root.children("Root").flatMap { it.children("Group") }.lastOrNull()

/** A field value as stored: plain text, or a value marked `Protected`. */
internal sealed interface FieldText {
    data class Plain(val text: String) : FieldText
    class Protected(val value: ProtectedText) : FieldText
}

/** One `String` of an entry: its key and value. */
internal class FieldView(val key: String, val value: FieldText)

/** Read access to a `Group` element. */
internal class GroupView(val element: XmlElement, private val document: VaultDocument) {
    val uuid: UUID? get() = Uuids.parse(element.child("UUID")?.text())
    val name: String get() = element.child("Name")?.text().orEmpty()
    val iconId: Int get() = element.child("IconID")?.text()?.trim()?.toIntOrNull() ?: 0
    val customIconUuid: UUID? get() = Uuids.parse(element.child("CustomIconUUID")?.text())
    fun groups(): List<GroupView> = element.children("Group").map { GroupView(it, document) }
    fun entries(): List<EntryView> = element.children("Entry").map { EntryView(it, document) }

    /** The group's own tags (KDBX 4.1), split as [Tags.split]. */
    val tags: List<String> get() = Tags.split(element.child("Tags")?.text())
}

/** Splits tags on ',' and ';', trimmed, with no empty tags. */
internal object Tags {
    fun split(text: String?): List<String> = text.orEmpty().split(',', ';').map { it.trim() }.filter { it.isNotEmpty() }
}

/** Read access to an `Entry` element. */
internal class EntryView(val element: XmlElement, private val document: VaultDocument) {
    val uuid: UUID? get() = Uuids.parse(element.child("UUID")?.text())

    /**
     * Returns every field in file order, each `String` read by its last `Key` and last `Value`
     * ([EntryParts]). Separate Strings with the same Key are all listed; the last one is the
     * field's value, so callers key the list by [FieldView.key].
     */
    fun fields(): List<FieldView> = element.children("String").mapNotNull { string ->
        val key = EntryParts.key(string)?.text() ?: return@mapNotNull null
        val value = EntryParts.value(string)
        val text = when {
            value == null -> FieldText.Plain("")
            value.attribute("Protected") == "True" -> FieldText.Protected(document.protectedValues[value] ?: ProtectedText.of(""))
            else -> FieldText.Plain(value.text())
        }
        FieldView(key, text)
    }

    /** The entry's own tags, split as [Tags.split]. */
    val tags: List<String> get() = Tags.split(element.child("Tags")?.text())

    /** Times/CreationTime, or null when missing or unreadable. */
    val created: Instant? get() = time("CreationTime")

    /** Times/LastModificationTime, or null when missing or unreadable. */
    val modified: Instant? get() = time("LastModificationTime")

    /** Times/ExpiryTime when Times/Expires is "True", else null. */
    val expiry: Instant?
        get() = if (element.child("Times")?.child("Expires")?.text()?.trim() == "True") time("ExpiryTime") else null

    private fun time(name: String): Instant? = element.child("Times")?.child(name)?.text()?.let(KdbxTime::parse)

    /**
     * Attachment names in file order, each `Binary` by its last `Key` ([EntryParts]), a repeated
     * name once: an entry holds one attachment per name.
     */
    val attachmentNames: List<String> get() = element.children("Binary").map { EntryParts.key(it)?.text().orEmpty() }.distinct()
}

/**
 * Reads the parts of entry elements and lists the elements a save leaves out.
 *
 * An entry's `String` or `Binary` holds its last `Key` and its last `Value`. The entries of every
 * `History` block of an entry form one list in document order, and a `History` inside a history
 * entry is skipped. A save writes one Key and one Value per String and Binary and no History in a
 * history entry, so it leaves out the earlier Keys and Values and that History ([omitted]). An
 * element left out takes no inner stream on write, and no reader of the saved file takes the
 * stream for it. [DuplicateChildrenTest] pins each rule.
 */
internal object EntryParts {

    /** Returns the last `Key` of the `String` or `Binary` [part], the one that counts. */
    fun key(part: XmlElement): XmlElement? = last(part, "Key")

    /** Returns the last `Value` of the `String` or `Binary` [part], the one that counts. */
    fun value(part: XmlElement): XmlElement? = last(part, "Value")

    /**
     * Returns [entry]'s history entries: those of every `History` block in document order, or
     * none when [entry] is itself a history entry.
     */
    fun history(entry: XmlElement): List<XmlElement> =
        if (isHistoryEntry(entry)) emptyList() else entry.children("History").flatMap { it.children("Entry") }

    /**
     * Returns the elements under [root] a save leaves out, by identity, in one walk: each `Key`
     * and `Value` of an entry's `String` or `Binary` but the last of its name, and each `History`
     * of a history entry. Elements inside an omitted one are not listed ([within]).
     */
    fun omitted(root: XmlElement): Set<XmlElement> {
        val out: MutableSet<XmlElement> = Collections.newSetFromMap(IdentityHashMap())
        // Depth is bounded by XmlReader.MAX_DEPTH.
        fun walk(element: XmlElement) {
            if (element.name == "History" && element.parent?.let(::isHistoryEntry) == true) {
                out += element
                return
            }
            if ((element.name == "String" || element.name == "Binary") && element.parent?.name == "Entry") {
                val key = key(element)
                val value = value(element)
                for (child in element.elements()) {
                    if ((child.name == "Key" && child !== key) || (child.name == "Value" && child !== value)) out += child
                }
            }
            for (child in element.elements()) if (child !in out) walk(child)
        }
        walk(root)
        return out
    }

    /** Returns true when [element] or an element around it is in [omitted]. */
    fun within(element: XmlElement, omitted: Set<XmlElement>): Boolean =
        omitted.isNotEmpty() && generateSequence(element) { it.parent }.any { it in omitted }

    private fun isHistoryEntry(entry: XmlElement): Boolean =
        entry.name == "Entry" && entry.parent?.name == "History" && entry.parent?.parent?.name == "Entry"

    private fun last(parent: XmlElement, name: String): XmlElement? =
        parent.children.lastOrNull { it is XmlElement && it.name == name } as XmlElement?
}

/**
 * Read access to `Meta`, with the format's defaults for elements the file leaves out: recycle bin
 * enabled, 10 history items, 6 MiB of history, only the password protected.
 */
internal class MetaView(private val meta: XmlElement?) {
    private fun text(name: String) = meta?.child(name)?.text()
    private fun bool(name: String, default: Boolean) = when (text(name)?.trim()) {
        "True" -> true
        "False" -> false
        else -> default
    }

    val recycleBinEnabled: Boolean get() = bool("RecycleBinEnabled", true)

    /** The recycle bin's UUID, or null when unset (written as all zeros). */
    val recycleBinUuid: UUID? get() = Uuids.parse(text("RecycleBinUUID"))?.takeIf { it != Uuids.ZERO }
    val historyMaxItems: Int get() = text("HistoryMaxItems")?.trim()?.toIntOrNull() ?: 10
    val historyMaxSize: Long get() = text("HistoryMaxSize")?.trim()?.toLongOrNull() ?: (6L * 1024 * 1024)
    val defaultUserName: String get() = text("DefaultUserName").orEmpty()

    /** Whether new values of the standard field [key] are protected (MemoryProtection). */
    fun protects(key: String): Boolean {
        val protection = meta?.child("MemoryProtection")
        fun flag(name: String, default: Boolean) = when (protection?.child(name)?.text()?.trim()) {
            "True" -> true
            "False" -> false
            else -> default
        }
        return when (key) {
            "Title" -> flag("ProtectTitle", false)
            "UserName" -> flag("ProtectUserName", false)
            "Password" -> flag("ProtectPassword", true)
            "URL" -> flag("ProtectURL", false)
            "Notes" -> flag("ProtectNotes", false)
            else -> false
        }
    }
}

/** KDBX UUIDs: 16 bytes in base64, read big-endian into a [UUID]. */
internal object Uuids {
    val ZERO = UUID(0, 0)

    fun parse(text: String?): UUID? {
        if (text == null) return null
        val bytes = try {
            Base64.getDecoder().decode(text.trim())
        } catch (e: IllegalArgumentException) {
            return null
        }
        if (bytes.size != 16) return null
        val buffer = ByteBuffer.wrap(bytes)
        return UUID(buffer.long, buffer.long)
    }

    fun format(uuid: UUID): String = Base64.getEncoder().encodeToString(SaveSettings.uuidBytes(uuid))
}
