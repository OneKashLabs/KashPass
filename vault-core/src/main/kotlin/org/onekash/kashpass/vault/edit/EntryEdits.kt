package org.onekash.kashpass.vault.edit

import java.time.Instant
import java.util.UUID
import org.onekash.kashpass.vault.doc.BinaryPool
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.EntryParts
import org.onekash.kashpass.vault.doc.FieldText
import org.onekash.kashpass.vault.doc.GroupView
import org.onekash.kashpass.vault.doc.KdbxTime
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.xml.XmlChars
import org.onekash.kashpass.vault.xml.XmlElement
import org.onekash.kashpass.vault.xml.XmlText

/**
 * Edits and adds entries on a copy of the document; the input document is never changed. Entries
 * are named by the ids the index shows. [EditEntryTest] and [AddEntryTest] pin each rule.
 */
object EntryEdits {

    private val STANDARD = listOf("Title", "UserName", "Password", "URL", "Notes")

    // Standard icon numbers of the KDBX `IconID` element.
    private const val ICON_KEY = 0
    private const val ICON_EMAIL = 19
    private const val ICON_EMAIL_BOX = 25
    private val FOLDER_ICONS = setOf(48, 49, 50)

    /** Returns the entry's standard fields as a draft, or null when [entryId] is unknown. */
    fun draftOf(document: VaultDocument, entryId: String): EntryDraft? {
        val entry = DocumentIds.entries(document)[entryId] ?: return null
        val values = current(document, entry)
        return EntryDraft(
            title = values["Title"].plain(),
            userName = values["UserName"].plain(),
            password = values["Password"].protected(),
            url = values["URL"].plain(),
            notes = values["Notes"].plain(),
        )
    }

    /**
     * Returns the standard fields stored protected once [entryId] is saved: those the
     * entry already protects, and those the vault's memory protection settings protect, the same
     * rule [edit] writes and cleans by. For a new entry ([entryId] null), the vault's settings
     * alone. The editor turns off keyboard learning for them; masking and search do not use it
     * ([org.onekash.kashpass.vault.index.VaultIndex] treats the password alone as protected).
     */
    fun protectedKeys(document: VaultDocument, entryId: String?): Set<String> {
        val entry = entryId?.let { DocumentIds.entries(document)[it] }
        val stored = entry?.let { current(document, it) }.orEmpty()
        return STANDARD.filter { writtenProtected(document, stored[it] is FieldText.Protected, it) }.toSet()
    }

    // The one rule [setField] writes by and [protectedKeys] reports: a field the entry stores
    // protected, or one the vault's memory protection settings protect.
    private fun writtenProtected(document: VaultDocument, storedProtected: Boolean, key: String) =
        storedProtected || document.meta.protects(key)

    /**
     * Returns a draft for a new entry: the vault's default user name and [password], a generated
     * password.
     */
    fun newDraft(document: VaultDocument, password: ProtectedText) =
        EntryDraft("", document.meta.defaultUserName, password, "", "")

    /**
     * Saves [draft] into the entry: when a field differs (whitespace counts), the entry's previous
     * version is appended to the end of its history (its last `History` block) with every History
     * of its own left out and everything else kept; the changed fields are set, each in the last
     * `Value` of the last `String` with its key ([EntryParts]), keeping each one's protection or
     * taking the vault's setting for a field it didn't have; LastModificationTime and
     * LastAccessTime become [now] and UsageCount goes up by one, and parent groups keep their
     * times; then the history is trimmed ([HistoryTrim]); an attachment no entry references after
     * the trim stays in the list until a save drops it ([BinaryPool.rebuild]). Characters XML 1.0
     * forbids are removed from the changed fields written in clear and kept in those written
     * protected ([protectedKeys]); a field the draft leaves as it is keeps its value. The password
     * is written in clear, cleaned, only when both the entry and Meta store it in clear.
     */
    fun edit(document: VaultDocument, entryId: String, draft: EntryDraft, now: Instant): EditResult {
        if (DocumentIds.entries(document)[entryId] == null) return EditResult.EntryNotFound
        val copy = document.copy()
        val entry = DocumentIds.entries(copy).getValue(entryId)
        // Compare as entered: a protected value can hold characters XML 1.0 forbids in text
        // (it is stored as Base64), and a value the user did not edit keeps them.
        val entered = wanted(draft)
        val wanted = wanted(sanitized(draft, protectedKeys(document, entryId)))
        val current = current(copy, entry)
        val changed = STANDARD.filter { !same(current[it], entered.getValue(it)) }
        if (changed.isEmpty()) return EditResult.Unchanged
        snapshot(copy, entry)
        for (key in changed) setField(copy, entry, key, wanted.getValue(key))
        touch(entry, now)
        HistoryTrim.maintain(copy, entry)
        return EditResult.Changed(copy)
    }

    /**
     * Adds an entry built from [draft] to the group [groupId] (the top level when null): a new
     * [uuid], every time [now], not expiring, a usage count of 1, all five standard fields
     * protected by the vault's memory protection settings, the icon taken from the group (a key
     * for a folder icon, an email icon for an email box), written in the KDBX element order.
     * Characters XML 1.0 forbids are removed from the fields written in clear, as [edit] does.
     * Refuses the recycle bin.
     */
    fun add(document: VaultDocument, groupId: String?, draft: EntryDraft, now: Instant, uuid: UUID = UUID.randomUUID()): Added {
        val copy = document.copy()
        val groups = DocumentIds.groups(copy)
        val group = if (groupId == null) copy.rootGroup.element else requireNotNull(groups[groupId]) { "unknown group" }
        require(!inRecycleBin(copy, group)) { "entries are never added to the recycle bin" }
        val view = GroupView(group, copy)
        val wanted = wanted(sanitized(draft, protectedKeys(document, null)))
        val time = KdbxTime.format(now)
        val entry = XmlElement("Entry")
        entry.append(leaf("UUID", Uuids.format(uuid)))
        entry.append(leaf("IconID", entryIcon(view.iconId).toString()))
        view.customIconUuid?.takeIf { it != Uuids.ZERO }?.let { entry.append(leaf("CustomIconUUID", Uuids.format(it))) }
        for (name in listOf("ForegroundColor", "BackgroundColor", "OverrideURL", "Tags")) entry.append(XmlElement(name))
        val times = XmlElement("Times")
        for (name in listOf("CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime")) times.append(leaf(name, time))
        times.append(leaf("Expires", "False"))
        times.append(leaf("UsageCount", "1"))
        times.append(leaf("LocationChanged", time))
        entry.append(times)
        // Fields are written sorted by key; this is that order for the five keys.
        for (key in listOf("Notes", "Password", "Title", "URL", "UserName")) {
            entry.append(stringElement(copy, key, wanted.getValue(key), writtenProtected(copy, false, key)))
        }
        val autoType = XmlElement("AutoType")
        autoType.append(leaf("Enabled", "True"))
        autoType.append(leaf("DataTransferObfuscation", "0"))
        entry.append(autoType)
        entry.append(XmlElement("History"))
        // A group's entries go after its own fields and before its child groups.
        val lastEntry = group.children.indexOfLast { it is XmlElement && it.name == "Entry" }
        val firstGroup = group.children.indexOfFirst { it is XmlElement && it.name == "Group" }
        val at = when {
            lastEntry >= 0 -> lastEntry + 1
            firstGroup >= 0 -> firstGroup
            else -> group.children.size
        }
        group.insert(at, entry)
        val id = DocumentIds.entries(copy).entries.first { it.value === entry }.key
        return Added(copy, id)
    }

    /**
     * Returns the groups a new entry can go into, depth first: the top level first, never the
     * recycle bin or a group inside it. Labels are paths below the top level ("Work / Email").
     */
    fun groups(document: VaultDocument): List<GroupChoice> {
        val root = document.rootGroup.element
        val ids = DocumentIds.groups(document)
        val out = mutableListOf<GroupChoice>()
        for ((id, element) in ids) {
            if (inRecycleBin(document, element)) continue
            val path = generateSequence(element) { it.parent }.takeWhile { it !== root && it.name == "Group" }
                .map { GroupView(it, document).name }.toList().asReversed()
            out += GroupChoice(id, if (element === root) GroupView(root, document).name else path.joinToString(" / "), element === root)
        }
        return out
    }

    /** True when [group] is the recycle bin or inside it (only while the bin is enabled). */
    internal fun inRecycleBin(document: VaultDocument, group: XmlElement): Boolean {
        val meta = document.meta
        val bin = meta.recycleBinUuid?.takeIf { meta.recycleBinEnabled } ?: return false
        return generateSequence(group) { it.parent }.takeWhile { it.name == "Group" }.any { GroupView(it, document).uuid == bin }
    }

    private fun entryIcon(groupIcon: Int) = when (groupIcon) {
        in FOLDER_ICONS -> ICON_KEY
        ICON_EMAIL_BOX -> ICON_EMAIL
        else -> groupIcon
    }

    // Removes characters XML 1.0 forbids from every field not in [kept].
    private fun sanitized(draft: EntryDraft, kept: Set<String>): EntryDraft {
        fun clean(text: String): String {
            if (XmlChars.allValid(text)) return text
            val out = StringBuilder(text.length)
            var i = 0
            while (i < text.length) {
                val cp = text.codePointAt(i)
                if (XmlChars.isChar(cp)) out.appendCodePoint(cp)
                i += Character.charCount(cp)
            }
            return out.toString()
        }
        fun field(key: String, text: String) = if (key in kept) text else clean(text)
        val password = if ("Password" in kept) {
            draft.password
        } else {
            draft.password.reveal().let { if (XmlChars.allValid(it)) draft.password else ProtectedText.of(clean(it)) }
        }
        return EntryDraft(field("Title", draft.title), field("UserName", draft.userName), password, field("URL", draft.url), field("Notes", draft.notes))
    }

    private fun wanted(draft: EntryDraft): Map<String, FieldText> = mapOf(
        "Title" to FieldText.Plain(draft.title),
        "UserName" to FieldText.Plain(draft.userName),
        "Password" to FieldText.Protected(draft.password),
        "URL" to FieldText.Plain(draft.url),
        "Notes" to FieldText.Plain(draft.notes),
    )

    // A repeated key takes its last value.
    private fun current(document: VaultDocument, entry: XmlElement): Map<String, FieldText> {
        val out = HashMap<String, FieldText>()
        for (field in org.onekash.kashpass.vault.doc.EntryView(entry, document).fields()) out[field.key] = field.value
        return out
    }

    // An absent field equals an empty one.
    private fun same(current: FieldText?, wanted: FieldText): Boolean {
        val a = current?.let(::reveal).orEmpty()
        val b = reveal(wanted)
        return a == b
    }

    private fun reveal(value: FieldText) = when (value) {
        is FieldText.Plain -> value.text
        is FieldText.Protected -> value.value.reveal()
    }

    private fun FieldText?.plain() = this?.let(::reveal).orEmpty()

    private fun FieldText?.protected(): ProtectedText = when (this) {
        null -> ProtectedText.of("")
        is FieldText.Protected -> value
        is FieldText.Plain -> ProtectedText.of(text)
    }

    // Appends a copy of [entry] without any History to the end of its history: the last History
    // block, since every block is read into one list (EntryParts.history).
    private fun snapshot(document: VaultDocument, entry: XmlElement) {
        val copy = entry.deepCopy()
        fun pair(from: XmlElement, to: XmlElement) {
            document.protectedValues[from]?.let { document.protectedValues[to] = it }
            from.elements().zip(to.elements()).forEach { (a, b) -> pair(a, b) }
        }
        pair(entry, copy)
        for (block in copy.children("History")) HistoryTrim.removeSubtree(document, copy, block)
        val history = entry.children("History").lastOrNull() ?: XmlElement("History").also { entry.append(it) }
        history.append(copy)
    }

    private fun setField(document: VaultDocument, entry: XmlElement, key: String, value: FieldText) {
        // The last String with the key, and its last Value, take effect (EntryParts).
        val existing = entry.children("String").lastOrNull { EntryParts.key(it)?.text() == key }
        if (existing == null) {
            // A field the entry didn't have, at the end of its fields.
            val element = stringElement(document, key, value, writtenProtected(document, false, key))
            val lastString = entry.children.indexOfLast { it is XmlElement && it.name == "String" }
            val firstAfter = entry.children.indexOfFirst { it is XmlElement && it.name in setOf("Binary", "AutoType", "CustomData", "History") }
            val at = when {
                lastString >= 0 -> lastString + 1
                firstAfter >= 0 -> firstAfter
                else -> entry.children.size
            }
            entry.insert(at, element)
            return
        }
        val valueElement = EntryParts.value(existing) ?: XmlElement("Value").also { existing.append(it) }
        val protect = writtenProtected(document, valueElement.attribute("Protected") == "True", key)
        write(document, valueElement, value, protect)
    }

    private fun stringElement(document: VaultDocument, key: String, value: FieldText, protect: Boolean): XmlElement {
        val string = XmlElement("String")
        string.append(leaf("Key", key))
        val valueElement = XmlElement("Value")
        string.append(valueElement)
        write(document, valueElement, value, protect)
        return string
    }

    // A protected value's text is written by the codec from the protected value; the tree holds
    // none.
    private fun write(document: VaultDocument, element: XmlElement, value: FieldText, protect: Boolean) {
        if (protect) {
            if (element.attribute("Protected") != "True") element.setAttribute("Protected", "True")
            element.setText("")
            document.protectedValues[element] = when (value) {
                is FieldText.Protected -> value.value
                is FieldText.Plain -> ProtectedText.of(value.text)
            }
        } else {
            document.protectedValues.remove(element)
            element.setText(reveal(value))
        }
    }

    private fun touch(entry: XmlElement, now: Instant) {
        val times = entry.child("Times") ?: XmlElement("Times").also { entry.append(it) }
        val time = KdbxTime.format(now)
        setLeaf(times, "LastModificationTime", time)
        setLeaf(times, "LastAccessTime", time)
        val count = times.child("UsageCount")?.text()?.trim()?.toULongOrNull() ?: 0UL
        setLeaf(times, "UsageCount", (count + 1UL).toString())
    }

    private fun setLeaf(parent: XmlElement, name: String, value: String) {
        val element = parent.child(name) ?: XmlElement(name).also { parent.append(it) }
        element.setText(value)
    }

    private fun leaf(name: String, value: String) = XmlElement(name).apply { if (value.isNotEmpty()) append(XmlText(value)) }
}
