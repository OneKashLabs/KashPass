package org.onekash.kashpass.vault.index

import java.util.UUID
import org.onekash.kashpass.vault.doc.EntryView
import org.onekash.kashpass.vault.doc.FieldText
import org.onekash.kashpass.vault.doc.GroupView
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultDocument

/**
 * A field value with its `{REF:}` references resolved ([FieldRefs.resolve]). [value] is masked
 * when the input was or when it inserts a password; [insertsPassword] is true when a
 * `{REF:P@...}` was resolved at any depth, the case that needs a confirmation before an active
 * use such as copy; [keepsPlaceholders] is true when the result holds another placeholder
 * ([KeePassPlaceholders]), which KashPass leaves as stored. A `{S:name}` counts for the custom
 * fields of the entry the value belongs to; one in text a reference inserted from another entry is
 * checked against the same names, not against the target's.
 */
class ResolvedField internal constructor(
    val value: FieldValue,
    val insertsPassword: Boolean,
    val keepsPlaceholders: Boolean,
    /** Target searches this resolve ran. */
    internal val searches: Int,
    /** Entries this resolve read, in tree order. */
    internal val entriesRead: Int,
) {
    override fun toString() = "ResolvedField(insertsPassword=$insertsPassword, keepsPlaceholders=$keepsPlaceholders)"
}

/**
 * Resolves field references, `{REF:<wanted>@<search-in>:<text>}`, and no other placeholder: in
 * the text a reference inserts, other placeholders stay as stored, not filled in the target's
 * context.
 *
 * - A pass looks for `{REF:` (ignoring case) from its offset; the first `}` after it ends the
 *   reference. A pass runs at most 20 times; a reference that can't be resolved moves the offset
 *   past its start and counts as one of the 20.
 * - The body after `{REF:` must be longer than 4 characters, with `@` second and `:` fourth.
 *   Wanted T, U, P, A, N or I inserts the title, user name, password, URL, notes or UUID (32
 *   upper-case hex digits); search-in T, U, P, A, N, I or O (each field that is not a standard
 *   one) picks the field searched; codes ignore case. Anything else, or no match, leaves the
 *   reference as written.
 * - The target is the first entry, in tree order (a group's entries, then its groups), whose
 *   searched field matches the text by [SearchTerms] (words, `-word`, case and accents ignored).
 *   Every current entry counts, the recycle bin's and those in groups with searching disabled
 *   too; history does not. Protected values are searched.
 * - The inserted text is resolved one level deeper; a level of 12 or more resolves to nothing,
 *   so circular references come out empty.
 * - One cache serves every level of one [resolve]: a resolved reference replaces each of its
 *   occurrences, ignoring case, and a reference already cached keeps its first value.
 *
 * Resolved text lives only in the returned [ResolvedField]; nothing is cached between calls. The
 * entries are read from the document when a value holds a reference, so a vault without
 * references costs nothing at unlock.
 * [FieldRefsTest] pins each rule; the gated KeePass2FieldRefTest compares with KeePass 2.
 */
class FieldRefs private constructor(private val document: VaultDocument) {

    // A current entry's fields as stored, the last String of each key winning.
    private class Target(private val uuid: UUID, val fields: Map<String, FieldText>) {
        val hex: String by lazy { "%016X%016X".format(uuid.mostSignificantBits, uuid.leastSignificantBits) }
    }

    // Thrown when a resolve's text outgrows [MAX_LENGTH]; the resolve then keeps the stored text.
    private class TooLong : RuntimeException(null, null, false, false)

    /**
     * Returns [value] with its references resolved; [customNames] are the custom field names of
     * the entry [value] belongs to, for [ResolvedField.keepsPlaceholders].
     */
    fun resolve(value: FieldValue, customNames: Collection<String> = emptyList()): ResolvedField {
        val raw = value.reveal()
        if (!raw.contains(REF_START, ignoreCase = true)) {
            return ResolvedField(value, insertsPassword = false, keepsPlaceholders = KeePassPlaceholders.containsOther(raw, customNames), searches = 0, entriesRead = 0)
        }
        val run = Run()
        val text = try {
            run.compile(raw, 0)
        } catch (e: TooLong) {
            return ResolvedField(value, insertsPassword = false, keepsPlaceholders = KeePassPlaceholders.containsOther(raw, customNames), run.searches, run.entriesRead)
        }
        val masked = value is FieldValue.Protected || run.insertsPassword
        val out = if (masked) FieldValue.Protected(ProtectedText.of(text)) else FieldValue.Plain(text)
        return ResolvedField(out, run.insertsPassword, KeePassPlaceholders.containsOther(text, customNames), run.searches, run.entriesRead)
    }

    override fun toString() = "FieldRefs"

    // One top-level resolve: its cache, and what it found. Entries are read in tree order only as
    // far as a search needs, and each one's searched text is folded only when it is tested.
    private inner class Run {
        private val entries: Iterator<EntryView> = treeOrder(document).iterator()
        private val read = ArrayList<Target>()
        private val folded = HashMap<Char, ArrayList<List<String>>>()
        val cache = mutableListOf<Pair<String, String>>()
        var insertsPassword = false
        var searches = 0
        val entriesRead: Int get() = read.size

        // The entry at [index] in tree order, read on first use; null past the last one.
        private fun targetAt(index: Int): Target? {
            while (read.size <= index) {
                if (!entries.hasNext()) return null
                val entry = entries.next()
                val fields = LinkedHashMap<String, FieldText>()
                for (field in entry.fields()) fields[field.key] = field.value
                read += Target(entry.uuid ?: Uuids.ZERO, fields)
            }
            return read[index]
        }

        // The folded searched text of the entry at [index], read (by [targetAt]) before.
        private fun foldedAt(scan: Char, index: Int): List<String> {
            val list = folded.getOrPut(scan) { ArrayList() }
            while (list.size <= index) list += searched(read[list.size], scan).map(SearchTerms::fold)
            return list[index]
        }

        fun compile(text: String, level: Int): String {
            if (level >= MAX_DEPTH) return ""
            var str = text
            var offset = 0
            for (pass in 0 until MAX_PASSES) {
                str = fill(str)
                val start = str.indexOf(REF_START, offset, ignoreCase = true)
                if (start < 0) break
                val end = str.indexOf('}', start + 1)
                if (end <= start) break
                val full = str.substring(start, end + 1)
                val found = target(full)
                val inserted = found?.let { (target, wanted) -> insert(target, wanted) }
                if (inserted == null) {
                    offset = start + 1
                    continue
                }
                if (found.second == 'P') insertsPassword = true
                val inner = compile(inserted, level + 1)
                if (cache.none { it.first.equals(full, ignoreCase = true) }) cache += full to inner
                str = fill(str)
            }
            return str
        }

        // Replaces each cached reference, ignoring case, in the order cached.
        private fun fill(text: String): String {
            var str = text
            for ((ref, value) in cache) {
                var at = 0
                while (at < str.length) {
                    at = str.indexOf(ref, at, ignoreCase = true)
                    if (at < 0) break
                    if (str.length - ref.length + value.length > MAX_LENGTH) throw TooLong()
                    str = str.substring(0, at) + value + str.substring(at + ref.length)
                    at += value.length
                }
            }
            return str
        }

        // The first entry in tree order whose searched text matches, and the wanted code; or
        // null.
        private fun target(full: String): Pair<Target, Char>? {
            val body = full.substring(REF_START.length, full.length - 1)
            if (body.length <= 4 || body[1] != '@' || body[3] != ':') return null
            val scan = body[2].uppercaseChar()
            val wanted = body[0].uppercaseChar()
            if (scan !in SCAN_CODES) return null
            val query = SearchTerms.parse(body.substring(4))
            searches++
            var index = 0
            while (true) {
                val target = targetAt(index) ?: return null
                if (SearchTerms.matches(query, foldedAt(scan, index))) return target to wanted
                index++
            }
        }

        private fun insert(target: Target, wanted: Char): String? = when (wanted) {
            'I' -> target.hex
            else -> STANDARD_CODES[wanted]?.let { key -> target.fields[key]?.let(::reveal).orEmpty() }
        }
    }

    private fun searched(target: Target, scan: Char): List<String> = when (scan) {
        'I' -> listOf(target.hex)
        'O' -> target.fields.filterKeys { it !in VaultIndex.STANDARD }.values.map(::reveal)
        else -> listOfNotNull(target.fields[STANDARD_CODES.getValue(scan)]?.let(::reveal))
    }

    private fun reveal(value: FieldText): String = when (value) {
        is FieldText.Plain -> value.text
        is FieldText.Protected -> value.value.reveal()
    }

    companion object {
        private const val REF_START = "{REF:"
        private const val MAX_DEPTH = 12
        private const val MAX_PASSES = 20

        // The longest text a resolve builds, in characters. Without a bound, references whose
        // text doubles on every pass grow until memory runs out.
        private const val MAX_LENGTH = 1 shl 20

        private val STANDARD_CODES = mapOf('T' to "Title", 'U' to "UserName", 'P' to "Password", 'A' to "URL", 'N' to "Notes")
        private val SCAN_CODES = STANDARD_CODES.keys + setOf('I', 'O')

        /** Returns the resolver over the current entries of [document]. */
        fun from(document: VaultDocument): FieldRefs = FieldRefs(document)

        // Every current entry of [document] in tree order: a group's entries, then its groups.
        // Depth is bounded by XmlReader.MAX_DEPTH.
        private fun treeOrder(document: VaultDocument): Sequence<EntryView> = sequence {
            suspend fun SequenceScope<EntryView>.walk(group: GroupView) {
                yieldAll(group.entries())
                for (child in group.groups()) walk(child)
            }
            walk(document.rootGroup)
        }
    }
}
