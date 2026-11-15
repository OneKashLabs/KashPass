package org.onekash.kashpass.vault.property

import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.checkAll
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.SearchTerms
import org.onekash.kashpass.vault.index.VaultIndex
import org.onekash.kashpass.vault.index.documentOf
import org.onekash.kashpass.vault.index.from
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.VaultModel

/**
 * Search keeps its quick-search rules over any generated vault: word order does not matter, a
 * word only narrows the result, `-word` removes exactly the entries the word alone finds, the query
 * splits into terms as [splitSearchTerms] does, a password or a protected custom value is never
 * searched, and entries in an enabled recycle bin never show.
 */
class SearchProperties {

    // Words a query can use: the vault's own words, so queries find something, and four fixed
    // words; none holds a quote or starts with '-'.
    private fun words(doc: VaultModel.Doc): List<String> {
        val texts = Generators.entries(doc.root).flatMap { e -> e.fields.map { it.second.text } + e.tags } + groupNames(doc.root)
        return (texts.flatMap { it.split(' ', '\t', '\n') } + listOf("zz", "qq", "a", "é"))
            .filter { it.isNotEmpty() && '"' !in it && !it.startsWith("-") }.distinct()
    }

    private fun groupNames(g: VaultModel.Group): List<String> = listOf(g.name) + g.groups.flatMap { groupNames(it) }

    private fun ids(index: VaultIndex, query: String) = index.rows(Chip.All, query).map { it.id }.toSet()

    @Test
    fun `word order, an added word and an excluded word keep their rules`() = runBlocking<Unit> {
        var found = 0
        checkAll(PropertyRuns.config(60), Generators.doc, Arb.list(Arb.int(0..10_000), 3..3)) { doc, picks ->
            val pool = words(doc)
            val (a, b, c) = picks.map { pool[it % pool.size] }
            val index = VaultIndex.from(doc)
            if (ids(index, a).isNotEmpty()) found++
            assertEquals(ids(index, "$a $b"), ids(index, "$b $a"), "order of '$a' and '$b'")
            assertTrue(ids(index, "$a $b $c").all { it in ids(index, "$a $b") }, "adding '$c' added a result")
            assertEquals(ids(index, a) - ids(index, b), ids(index, "$a -$b"), "'$a -$b' is '$a' minus '$b'")
        }
        assertTrue(found > 0, "no query found anything, so the rules were never tested")
    }

    @Test
    fun `a query splits as KeePass 2's SplitSearchTerms does, and a quoted phrase is one term`() = runBlocking<Unit> {
        checkAll(PropertyRuns.config(400), Generators.anyText) { q ->
            assertEquals(splitSearchTerms(q), SearchTerms.split(q), q.escaped())
        }
        checkAll(PropertyRuns.config(100), Arb.list(Generators.safeText, 2..4)) { parts ->
            val words = parts.map { p -> p.filter { it != '"' && it != ' ' && it != '\t' && it != '\n' } }.filter { it.isNotEmpty() }
            if (words.size < 2) return@checkAll
            val phrase = words.joinToString(" ")
            assertEquals(listOf(phrase), SearchTerms.split("\"$phrase\""), "quoted ${phrase.escaped()}")
        }
    }

    @Test
    fun `a password or a protected custom value is never searched, and recycle-bin entries never show`() = runBlocking<Unit> {
        var binMatched = 0
        checkAll(PropertyRuns.config(60), Generators.doc, Arb.int(0..10_000)) { doc, pick ->
            // '#' is not in the generator's alphabet, so only these values hold the tokens.
            val secret = VaultModel.Entry(listOf(
                "Title" to VaultModel.Value.Plain("holder"),
                "Password" to VaultModel.Value.Protected("#999password"),
                "Secret" to VaultModel.Value.Protected("#999custom"),
            ))
            val plainPassword = VaultModel.Entry(listOf("Title" to VaultModel.Value.Plain("holder2"), "Password" to VaultModel.Value.Plain("#999plain")))
            val document = documentOf(VaultModel.write(doc.copy(root = doc.root.copy(entries = doc.root.entries + secret + plainPassword)), aesRounds = 1UL))
            val index = VaultIndex.from(document)
            assertEquals(2, ids(index, "holder").size, "the holder entries are searched")
            for (token in listOf("#999password", "#999custom", "#999plain", "#999")) assertEquals(emptySet(), ids(index, token), token)
            // The entries of an enabled recycle bin, from the document, not from the index's rows.
            val inBin = binIds(document)
            val binWords = binTitles(document).flatMap { it.split(' ', '\t', '\n') }.filter { it.isNotEmpty() && '"' !in it && !it.startsWith("-") }
            val query = if (binWords.isNotEmpty() && pick % 2 == 0) binWords[pick % binWords.size] else words(doc).let { it[pick % it.size] }
            if (query in binWords) binMatched++
            assertTrue(ids(index, query).none { it in inBin }, "'$query' shows a recycle-bin entry")
        }
        assertTrue(binMatched > 0, "no query used a recycle-bin entry's words, so the rule was never tested")
    }

    private fun binIds(document: VaultDocument): Set<String> =
        DocumentIds.entries(document).filterValues { EntryEdits.inRecycleBin(document, it.parent!!) }.keys

    private fun binTitles(document: VaultDocument): List<String> {
        val ids = binIds(document)
        return DocumentIds.entries(document).filterKeys { it in ids }.values.map { EntryEdits.draftOf(document, DocumentIds.entries(document).entries.first { e -> e.value === it }.key)!!.title }
    }

    // Splits a query into terms: outside quotes, space, tab, CR and LF end a term; a double quote
    // toggles quoting and is dropped; empty terms are skipped.
    private fun splitSearchTerms(s: String): List<String> {
        val out = mutableListOf<String>()
        val term = StringBuilder()
        var quoted = false
        for (ch in s) {
            if ((ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') && !quoted) {
                if (term.isNotEmpty()) { out += term.toString(); term.setLength(0) }
            } else if (ch == '"') quoted = !quoted
            else term.append(ch)
        }
        if (term.isNotEmpty()) out += term.toString()
        return out
    }
}
