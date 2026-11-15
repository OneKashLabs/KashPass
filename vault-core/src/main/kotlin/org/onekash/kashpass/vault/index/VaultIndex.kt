package org.onekash.kashpass.vault.index

import java.util.Locale
import java.util.UUID
import org.onekash.kashpass.vault.doc.EntryView
import org.onekash.kashpass.vault.doc.FieldText
import org.onekash.kashpass.vault.doc.GroupView
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.UniqueIds
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultDocument

/**
 * The browsable, searchable view of an unlocked vault, built once per unlock.
 *
 * Search text holds titles, user names, URLs, notes, tags (the entry's own and those of every
 * group above it), the entry's group name and custom fields, but never the password field or a
 * custom field's protected value, so a query can't confirm a secret, and [matchFor] can't show
 * one. Entry history is not indexed. [VaultIndexTest] and [SearchMatchTest] pin each rule.
 *
 * Search covers no protected value and no UUID, the entry's own group name and not the full group
 * path (no group name for an entry at the top), every group including one with searching turned
 * off, and custom field names.
 *
 * Standard fields are masked and searched by a fixed protection, password only, whatever the
 * file's MemoryProtection says: a title, user name, URL or notes stored protected is shown and
 * searched, and a password stored in clear is masked. A custom field keeps its own protection.
 */
class VaultIndex private constructor(
    private val items: List<Item>,
    /** All, then groups that directly hold entries (A to Z), then the recycle bin if not empty. */
    val chips: List<Chip>,
) {
    private class Item(
        val row: EntryRow,
        val groupId: String?,
        /** The searchable fields in [matchFor]'s order; the only source of search text. */
        val fields: List<Indexed>,
        val details: EntryDetails,
    ) {
        val searchText: List<String> = fields.map { SearchTerms.fold(it.text) }
    }

    /** One searchable text, built only from what the class KDoc allows. */
    private class Indexed(val source: MatchSource, val fieldName: String?, val text: String)

    private val byId = items.associateBy { it.row.id }

    /** True when no entry exists outside the recycle bin. */
    val isEmpty: Boolean get() = items.none { !it.row.inRecycleBin }

    /**
     * Returns the rows for [chip], or, when [query] is not blank, every entry outside the recycle
     * bin that matches it ([SearchTerms]: words, quoted phrases, `-word`; case and accents
     * ignored), whatever chip is selected. A query that holds only quotes has no words and matches
     * every entry.
     */
    fun rows(chip: Chip, query: String): List<EntryRow> {
        val selected = if (query.isNotBlank()) {
            val q = SearchTerms.parse(query)
            items.filter { !it.row.inRecycleBin && SearchTerms.matches(q, it.searchText) }
        } else {
            when (chip) {
                Chip.All -> items.filter { !it.row.inRecycleBin }
                is Chip.Group -> items.filter { !it.row.inRecycleBin && it.groupId == chip.id }
                Chip.RecycleBin -> items.filter { it.row.inRecycleBin }
            }
        }
        return selected.map { it.row }
    }

    /**
     * Returns why the entry with [rowId] matches [query]: the first field holding any of the
     * query's included words, in the order title, user name, group, URL, tags (the entry's own,
     * then those it inherits from its groups), custom fields (each name before its value, in the
     * vault's order), notes; the highlight is the included word that starts first in that field.
     * Null when [query] is blank, has no included words, the entry doesn't match, or it is in the
     * recycle bin (search never returns those).
     */
    fun matchFor(rowId: String, query: String): SearchMatch? {
        if (query.isBlank()) return null
        val item = byId[rowId]?.takeIf { !it.row.inRecycleBin } ?: return null
        val q = SearchTerms.parse(query)
        if (!SearchTerms.matches(q, item.searchText)) return null
        // An empty word occurs everywhere and pins nothing, so it can't give the reason.
        val words = q.include.filter { it.isNotEmpty() }
        val at = item.searchText.indexOfFirst { text -> words.any { text.contains(it) } }
        val field = item.fields.getOrNull(at) ?: return null
        val range = words.mapNotNull { SearchText.find(field.text, it) }
            .minWithOrNull(compareBy<IntRange> { it.first }.thenByDescending { it.last }) ?: return null
        val (snippet, highlight) = SearchText.snippet(field.text, range)
        return SearchMatch(field.source, field.fieldName, range, snippet, highlight)
    }

    /** Returns the details of the entry with [id], or null if the vault has no such entry. */
    fun details(id: String): EntryDetails? = byId[id]?.details

    override fun toString() = "VaultIndex(${items.size} entries)"

    internal companion object {

        /** The standard field keys; every other key is a custom field. */
        val STANDARD = listOf("Title", "UserName", "Password", "URL", "Notes")

        /** Builds the index from a decoded document. */
        fun from(document: VaultDocument): VaultIndex {
            val meta = document.meta
            val binId = meta.recycleBinUuid?.takeIf { meta.recycleBinEnabled }
            val collector = Collector(binId)
            collector.walk(document.rootGroup, parent = null, isRoot = true, recycled = false, inherited = emptyList())
            return collector.build()
        }
    }

    private class Collector(private val binId: UUID?) {
        private val items = mutableListOf<Item>()
        private val chipGroups = mutableListOf<Triple<GroupView, GroupView?, String>>()
        private var binHasEntries = false
        private val entryIds = UniqueIds()
        private val groupIds = UniqueIds()

        // Depth is bounded by XmlReader.MAX_DEPTH.
        // [inherited] holds the tags of every group above [group]; search matches them on each
        // entry below.
        fun walk(group: GroupView, parent: GroupView?, isRoot: Boolean, recycled: Boolean, inherited: List<String>) {
            val uuid = group.uuid
            val inBin = recycled || (uuid != null && uuid == binId)
            val groupId = groupIds.next(uuid ?: Uuids.ZERO)
            val entries = group.entries()
            val groupTags = group.tags + inherited
            for (entry in entries) {
                items += item(entry, if (isRoot) null else group, groupId, inBin, groupTags)
            }
            if (inBin && entries.isNotEmpty()) binHasEntries = true
            if (!isRoot && !inBin && entries.isNotEmpty()) chipGroups += Triple(group, parent, groupId)
            for (child in group.groups()) walk(child, group, isRoot = false, recycled = inBin, inherited = groupTags)
        }

        fun build(): VaultIndex {
            val duplicates = chipGroups.groupingBy { it.first.name }.eachCount().filterValues { it > 1 }.keys
            val groupChips = chipGroups
                .map { (group, parent, id) ->
                    val label = if (group.name in duplicates && parent != null) "${parent.name} / ${group.name}" else group.name
                    Chip.Group(id, label)
                }
                .sortedWith(compareBy({ it.label.lowercase(Locale.ROOT) }, { it.label }))
            val chips = listOf(Chip.All) + groupChips + if (binHasEntries) listOf(Chip.RecycleBin) else emptyList()
            val sorted = items.sortedWith(
                compareBy<Item>({ it.row.title == null }, { it.row.title?.lowercase(Locale.ROOT) }, { it.row.title }, { it.row.id }),
            )
            return VaultIndex(sorted, chips)
        }

        private fun item(entry: EntryView, group: GroupView?, groupId: String, recycled: Boolean, groupTags: List<String>): Item {
            // A repeated key takes its last value.
            val fields = LinkedHashMap<String, FieldText>()
            for (field in entry.fields()) fields[field.key] = field.value
            val title = fields["Title"]?.let(::text)?.takeIf { it.isNotEmpty() }
            val id = entryIds.next(entry.uuid ?: Uuids.ZERO)
            val custom = fields.filterKeys { it !in STANDARD }
            val groupName = group?.name
            val row = EntryRow(
                id = id,
                title = title,
                userName = fields["UserName"]?.let(::text).orEmpty(),
                groupName = groupName,
                inRecycleBin = recycled,
                expiry = entry.expiry,
            )
            // Enforces the secret rule in the class KDoc: standard fields other than the password
            // by their text, custom fields by their plain values only.
            fun plain(value: FieldText?) = (value as? FieldText.Plain)?.text
            val indexed = buildList {
                fields["Title"]?.let(::text)?.let { add(Indexed(MatchSource.TITLE, null, it)) }
                fields["UserName"]?.let(::text)?.let { add(Indexed(MatchSource.USER_NAME, null, it)) }
                groupName?.let { add(Indexed(MatchSource.GROUP, null, it)) }
                fields["URL"]?.let(::text)?.let { add(Indexed(MatchSource.URL, null, it)) }
                for (tag in entry.tags) add(Indexed(MatchSource.TAG, null, tag))
                for (tag in groupTags) add(Indexed(MatchSource.TAG, null, tag))
                for ((name, value) in custom) {
                    add(Indexed(MatchSource.CUSTOM_NAME, name, name))
                    plain(value)?.let { add(Indexed(MatchSource.CUSTOM_VALUE, name, it)) }
                }
                fields["Notes"]?.let(::text)?.let { add(Indexed(MatchSource.NOTES, null, it)) }
            }.filter { it.text.isNotEmpty() }
            return Item(row, groupId.takeIf { group != null }, indexed, details(id, title, groupName, fields, custom, entry))
        }

        private fun details(
            id: String,
            title: String?,
            groupName: String?,
            fields: Map<String, FieldText>,
            custom: Map<String, FieldText>,
            entry: EntryView,
        ): EntryDetails {
            val list = buildList {
                standard("UserName", FieldKind.USER_NAME, fields["UserName"])
                standard("Password", FieldKind.PASSWORD, fields["Password"])
                standard("URL", FieldKind.URL, fields["URL"])
                for ((name, value) in custom) add(EntryField(name, FieldKind.CUSTOM, value.toFieldValue()))
                standard("Notes", FieldKind.NOTES, fields["Notes"])
            }
            return EntryDetails(
                id, title, groupName, list, entry.attachmentNames,
                created = entry.created, modified = entry.modified, expiry = entry.expiry, tags = entry.tags,
            )
        }

        // The password is masked and every other standard field shown, as the class KDoc states.
        private fun MutableList<EntryField>.standard(key: String, kind: FieldKind, value: FieldText?) {
            val empty = when (value) {
                null -> true
                is FieldText.Plain -> value.text.isEmpty()
                is FieldText.Protected -> value.value.isEmpty
            }
            if (empty) return
            val shown = when {
                kind == FieldKind.PASSWORD && value is FieldText.Plain -> FieldValue.Protected(ProtectedText.of(value.text))
                kind == FieldKind.PASSWORD -> value!!.toFieldValue()
                else -> FieldValue.Plain(text(value!!))
            }
            add(EntryField(key, kind, shown))
        }

        private fun text(value: FieldText): String = when (value) {
            is FieldText.Plain -> value.text
            is FieldText.Protected -> value.value.reveal()
        }

        private fun FieldText.toFieldValue(): FieldValue = when (this) {
            is FieldText.Protected -> FieldValue.Protected(value)
            is FieldText.Plain -> FieldValue.Plain(text)
        }
    }
}
