package org.onekash.kashpass.vault.index

import java.lang.management.ManagementFactory
import java.util.UUID
import org.onekash.kashpass.vault.testing.VaultModel.Doc
import org.onekash.kashpass.vault.testing.VaultModel.Entry
import org.onekash.kashpass.vault.testing.VaultModel.Group
import org.onekash.kashpass.vault.testing.VaultModel.Value
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class SearchMatchTest {

    private fun plain(text: String) = Value.Plain(text)
    private fun secret(text: String) = Value.Protected(text)

    private fun entry(vararg fields: Pair<String, Value>, tags: List<String> = emptyList(), history: List<Entry> = emptyList()) =
        Entry(uuid = UUID.randomUUID(), fields = fields.toList(), tags = tags, history = history)

    private fun index(vararg groups: Group, rootEntries: List<Entry> = emptyList(), bin: Group? = null): VaultIndex {
        val all = groups.toList() + listOfNotNull(bin)
        return VaultIndex.from(Doc(Group("Root", entries = rootEntries, groups = all), recycleBin = bin?.uuid))
    }

    private fun group(name: String, vararg entries: Entry) = Group(name, entries = entries.toList())

    private val router = entry(
        "Title" to plain("Router"),
        "UserName" to plain("admin"),
        "Password" to secret("pw-secret"),
        "URL" to plain("https://router.example"),
        "Notes" to plain("line one\n   second line"),
        "Serial" to plain("SN-998"),
        tags = listOf("home"),
    )
    private val routerIndex by lazy { index(group("Network", router)) }

    private fun matchOf(index: VaultIndex, query: String): SearchMatch? =
        index.rows(Chip.All, query).singleOrNull()?.let { index.matchFor(it.id, query) }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(
        "router, TITLE, , Router",
        "admin, USER_NAME, , admin",
        "netw, GROUP, , Network",
        "example, URL, , https://router.example",
        "home, TAG, , home",
        "serial, CUSTOM_NAME, Serial, Serial",
        "sn-99, CUSTOM_VALUE, Serial, SN-998",
        "second, NOTES, , line one second line",
    )
    fun `each source is reported, in priority order, with its snippet`(
        query: String,
        source: MatchSource,
        fieldName: String?,
        snippet: String,
    ) {
        val match = assertNotNull(matchOf(routerIndex, query), query)
        assertEquals(source, match.source)
        assertEquals(fieldName, match.fieldName)
        assertEquals(snippet, match.snippet)
        assertEquals(query, match.snippet.substring(match.highlight).lowercase(), "highlight")
    }

    @Test
    fun `custom fields are checked in vault order, each name before its value`() {
        val e = entry("Title" to plain("Two fields"), "First" to plain("zzz-shared"), "shared-name" to plain("x"))
        val match = assertNotNull(matchOf(index(group("G", e)), "shared"))
        assertEquals(MatchSource.CUSTOM_VALUE, match.source)
        assertEquals("First", match.fieldName)
    }

    @Test
    fun `when several fields match, the first in the stated priority wins`() {
        // Each step drops the field that won the step before.
        val order = listOf(MatchSource.TITLE, MatchSource.USER_NAME, MatchSource.GROUP, MatchSource.URL, MatchSource.TAG, MatchSource.CUSTOM_NAME, MatchSource.NOTES)
        for ((step, expected) in order.withIndex()) {
            fun has(source: MatchSource) = order.indexOf(source) >= step
            val fields = buildList {
                add("Title" to plain(if (has(MatchSource.TITLE)) "zz title" else "title"))
                if (has(MatchSource.USER_NAME)) add("UserName" to plain("zz user"))
                if (has(MatchSource.URL)) add("URL" to plain("zz.example"))
                if (has(MatchSource.CUSTOM_NAME)) add("zz field" to plain("zz value"))
                add("Notes" to plain("zz notes"))
            }
            val e = entry(*fields.toTypedArray(), tags = if (has(MatchSource.TAG)) listOf("zz") else emptyList())
            val g = group(if (has(MatchSource.GROUP)) "zz group" else "group", e)
            assertEquals(expected, matchOf(index(g), "zz")?.source, "step $step")
        }
    }

    @Test
    fun `a custom field's name wins over its own value`() {
        val e = entry("Title" to plain("T"), "Account" to plain("account-1"))
        val match = assertNotNull(matchOf(index(group("G", e)), "account"))
        assertEquals(MatchSource.CUSTOM_NAME, match.source)
    }

    @Test
    fun `textRange marks the match in the field's own text`() {
        val e = entry("Title" to plain("My Router"))
        val match = assertNotNull(matchOf(index(group("G", e)), "router"))
        assertEquals(MatchSource.TITLE, match.source)
        assertEquals("Router", "My Router".substring(match.textRange))
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource("pw-secret", "plain-pw", "otp-secret", "hist-secret")
    fun `no secret is ever reported or matched`(query: String) {
        val old = entry("Title" to plain("hist-secret"), "UserName" to plain("hist-secret"))
        val e = entry(
            "Title" to secret("title"),
            "Password" to secret("pw-secret"),
            "otp" to secret("otp-secret"),
            history = listOf(old),
        )
        // A password stored in clear is a secret too: it is masked whatever the file says.
        val clear = entry("Title" to plain("other"), "Password" to plain("plain-pw"))
        val index = index(group("G", e, clear))
        assertEquals(emptyList(), index.rows(Chip.All, query))
        for (row in index.rows(Chip.All, "")) assertNull(index.matchFor(row.id, query))
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource("TITLE, title-secret", "USER_NAME, user-secret", "URL, url-secret", "NOTES, notes-secret")
    fun `standard fields stored protected are matched and reported`(source: MatchSource, query: String) {
        val e = entry(
            "Title" to secret("title-secret"),
            "UserName" to secret("user-secret"),
            "URL" to secret("url-secret"),
            "Notes" to secret("notes-secret"),
        )
        assertEquals(source, assertNotNull(matchOf(index(group("G", e)), query)).source)
    }

    @Test
    fun `spaces around words are ignored like rows, and blank or missing matches give null`() {
        val id = routerIndex.rows(Chip.All, "").single().id
        assertEquals(MatchSource.USER_NAME, routerIndex.matchFor(id, "  admin ")?.source)
        assertNull(routerIndex.matchFor(id, "   "))
        assertNull(routerIndex.matchFor(id, "nothing-like-this"))
        assertNull(routerIndex.matchFor("no-such-id", "admin"))
    }

    @Test
    fun `entries in the recycle bin have no match, as search never returns them`() {
        val old = entry("Title" to plain("Old router"))
        val bin = group("Recycle Bin", old)
        val index = index(bin = bin)
        val id = index.rows(Chip.RecycleBin, "").single().id
        assertNull(index.matchFor(id, "router"))
    }

    @Test
    fun `a match deep in a huge note gives a bounded one-line snippet that shows it`() {
        val note = "x".repeat(50_000) + "\nneedle\n" + "y".repeat(50_000)
        val match = assertNotNull(matchOf(index(group("G", entry("Title" to plain("Big"), "Notes" to plain(note)))), "needle"))
        assertTrue(match.snippet.length <= 135, "length ${match.snippet.length}")
        assertTrue(match.snippet.startsWith("…") && match.snippet.endsWith("…"), match.snippet)
        assertEquals("needle", match.snippet.substring(match.highlight))
        assertTrue('\n' !in match.snippet)
    }

    @Test
    fun `a cut snippet starts at a word boundary, not mid-word`() {
        val e = entry("Title" to plain("Form"), "URL" to plain("https://keepass.info/help/kb/testform.html"))
        val match = assertNotNull(matchOf(index(group("G", e)), "testform"))
        assertEquals("…keepass.info/help/kb/testform.html", match.snippet)
        assertEquals("testform", match.snippet.substring(match.highlight))
        // With no boundary within reach, the cut stays where it was.
        val long = entry("Title" to plain("Long"), "Notes" to plain("x".repeat(60) + "needle"))
        val cut = assertNotNull(matchOf(index(group("G", long)), "needle"))
        assertEquals("…" + "x".repeat(20) + "needle", cut.snippet)
    }

    @Test
    fun `a quoted phrase with a whitespace run highlights the collapsed match`() {
        val match = assertNotNull(matchOf(index(group("G", entry("Title" to plain("T"), "Notes" to plain("a  b c")))), "\"a  b\""))
        assertEquals("a b c", match.snippet)
        assertEquals("a b", match.snippet.substring(match.highlight))
    }

    @Test
    fun `find matches like the index, ignoring case and accents, and stays inside the text`() {
        assertEquals(6..10, SearchText.find("Hello World", "world"))
        assertNull(SearchText.find("Hello World", "planet"))
        val notes = "Recovery hint: ünïcödé"
        assertEquals("ünï", notes.substring(assertNotNull(SearchText.find(notes, SearchTerms.fold("ÜNÏ")))))
        assertEquals("ünïcödé", notes.substring(assertNotNull(SearchText.find(notes, "unicode"))))
        // Lowercasing İ adds a combining dot, which the fold drops; positions map back exactly.
        val bank = "İİİ Bank"
        assertEquals("Bank", bank.substring(assertNotNull(SearchText.find(bank, "bank"))))
        assertEquals("İİ", bank.substring(assertNotNull(SearchText.find(bank, "ii"))))
        // A decomposed accent belongs to the match of its letter.
        val decomposed = "Cafe\u0301 noir"
        assertEquals("Cafe\u0301", decomposed.substring(assertNotNull(SearchText.find(decomposed, "cafe"))))
    }

    @Test
    fun `a tag query finds the entries carrying that tag`() {
        assertEquals("home", SearchText.tagQuery("home"))
        assertEquals("\"two words\"", SearchText.tagQuery("two words"))
        assertEquals("\"urgent\"", SearchText.tagQuery("-urgent"))
        assertEquals("\" a long part\"", SearchText.tagQuery("say\" a long part\"x"))
        assertEquals("-", SearchText.tagQuery("-"))
        val tags = listOf("two words", "-urgent", "say \"hi there\"", "words")
        val entries = tags.mapIndexed { i, tag -> entry("Title" to plain("E$i"), tags = listOf(tag)) }
        val index = index(group("G", *entries.toTypedArray()))
        assertEquals(listOf("E0"), index.rows(Chip.All, SearchText.tagQuery("two words")).map { it.title })
        assertEquals(listOf("E1"), index.rows(Chip.All, SearchText.tagQuery("-urgent")).map { it.title })
        assertEquals(listOf("E2"), index.rows(Chip.All, SearchText.tagQuery("say \"hi there\"")).map { it.title })
    }

    @Test
    fun `a match followed by a long run of combining marks gives a snippet, not a crash`() {
        val title = "Zalgo" + "\u0301".repeat(1_100)
        val match = assertNotNull(matchOf(index(group("G", entry("Title" to plain(title)))), "zalgo"))
        assertEquals(MatchSource.TITLE, match.source)
        assertTrue(match.snippet.startsWith("Zalgo"))
        val long = "a" + "\u0301".repeat(1_500) + "b"
        assertEquals(0 until long.length, SearchText.find(long, "ab"))
    }

    @Test
    fun `a tag of dashes only searches for a dash, not for its absence`() {
        assertEquals("-", SearchText.tagQuery("-"))
        assertEquals("-", SearchText.tagQuery("--"))
        assertEquals("-", SearchText.tagQuery("---"))
        val entries = listOf("--", "x").mapIndexed { i, tag -> entry("Title" to plain("E$i"), tags = listOf(tag)) }
        val index = index(group("G", *entries.toTypedArray()))
        assertEquals(listOf("E0"), index.rows(Chip.All, SearchText.tagQuery("--")).map { it.title })
    }

    @Test
    fun `every sigma matches every other sigma, at its own position`() {
        assertEquals(1..1, SearchText.find("ΟΣ ΣΑ", "σ"))
        assertEquals(3..3, SearchText.find("ΟΔΟΣ", SearchTerms.fold("ς")))
        assertEquals(2..2, SearchText.find("İΟΣ", SearchTerms.fold("ς")))
    }

    @Test
    fun `a cut snippet never starts or ends between a letter and its accent`() {
        val accented = "e\u0301".repeat(15)
        val e = entry("Title" to plain("T"), "Notes" to plain("abc" + accented + "needle" + "x".repeat(97) + accented))
        val match = assertNotNull(matchOf(index(group("G", e)), "needle"))
        val afterEllipsis = match.snippet[1]
        assertTrue(Character.getType(afterEllipsis) != Character.NON_SPACING_MARK.toInt(), match.snippet)
        val beforeEllipsis = match.snippet[match.snippet.length - 2]
        assertTrue(beforeEllipsis != 'e', "the last base letter lost its accent: ${match.snippet.takeLast(5)}")
        assertEquals("needle", match.snippet.substring(match.highlight))
    }

    @Test
    fun `reasons for every result of a 1,000-entry search stay within the search budget`() {
        val entries = (1..1000).map { entry("Title" to plain("Service $it"), "UserName" to plain("user$it"), "Notes" to plain("note text $it")) }
        val index = index(group("G", *entries.toTypedArray()))
        repeat(20) { index.rows(Chip.All, "note text 9").forEach { row -> index.matchFor(row.id, "note text 9") } }
        val times = (1..9).map {
            cpuNanos { index.rows(Chip.All, "note text 9").forEach { row -> index.matchFor(row.id, "note text 9") } }
        }.sorted()
        val medianMs = times[times.size / 2] / 1_000_000.0
        assertTrue(medianMs < 100.0, "median $medianMs ms")
    }

    @Test
    fun `reasons for every result in a vault of long notes stay within the search budget`() {
        val words = "lorem ipsum dolor sit amet consectetur adipiscing elit "
        val note = words.repeat(100_000 / words.length)
        val entries = (1..200).map { entry("Title" to plain("Entry $it"), "Notes" to plain(note)) }
        val index = index(group("G", *entries.toTypedArray()))
        fun run() = index.rows(Chip.All, "ipsum").forEach { row -> index.matchFor(row.id, "ipsum") }
        repeat(5) { run() }
        val times = (1..7).map { cpuNanos { run() } }.sorted()
        val medianMs = times[times.size / 2] / 1_000_000.0
        assertTrue(medianMs < 100.0, "median $medianMs ms")
    }

    /**
     * Returns the CPU time this thread spends in [block], so tests running in parallel on other
     * threads do not count against a search budget.
     */
    private fun cpuNanos(block: () -> Unit): Long {
        val threads = ManagementFactory.getThreadMXBean()
        val start = threads.currentThreadCpuTime
        block()
        return threads.currentThreadCpuTime - start
    }
}
