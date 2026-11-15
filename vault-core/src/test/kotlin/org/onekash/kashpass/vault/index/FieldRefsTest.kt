package org.onekash.kashpass.vault.index

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.TestVaults.refHex

/**
 * Cases traced by hand over [TestVaults.referenceVault]; the gated KeePass2FieldRefTest checks
 * the same vault against KeePass 2.
 */
class FieldRefsTest {

    private val refs by lazy { FieldRefs.from(documentOf(TestVaults.referenceVault())) }

    private fun text(raw: String) = refs.resolve(FieldValue.Plain(raw)).value.reveal()

    @ParameterizedTest(name = "{0}")
    @CsvSource(
        delimiter = '|',
        value = [
            "wanted user name by title | {REF:U@T:Example Bank} | bob",
            "wanted title by user name | {REF:T@U:bob} | Example Bank",
            "wanted URL | {REF:A@T:Example Mail} | https://mail.example.test",
            "wanted notes | {REF:N@T:Example Mail} | webmail login",
            "wanted password | {REF:P@T:Example Bank} | bank-pass",
            "wanted UUID | {REF:I@U:bob} | 0000000000000000000000000000000B",
            "search in password | {REF:U@P:bank-pass} | bob",
            "search in URL | {REF:T@A:mail.example} | Example Mail",
            "search in notes | {REF:U@N:webmail} | alice@example.test",
            "search in other fields | {REF:T@O:12345} | Example Mail",
            "search in a protected other field | {REF:U@O:4711} | alice@example.test",
            "lower-case codes and prefix | {ref:u@t:example bank} | bob",
            "every word must match | {REF:U@T:Bank Example} | bob",
            "an excluded word | {REF:U@T:Example -root} | alice@example.test",
            "accents ignored | {REF:U@T:cafe} | cafeuser",
            "a recycle-bin entry is a target | {REF:P@T:Old Login} | old-pass",
            "the last of two titles counts | {REF:U@T:Second Title} | ",
            "text around a reference stays | user: {REF:U@T:Example Bank} end | user: bob end",
        ],
    )
    fun `a reference inserts the wanted field of the first match`(case: String, raw: String, expected: String?) {
        assertEquals(expected.orEmpty(), text(raw), case)
    }

    @Test
    fun `the first match is in KeePass 2's tree order, a group's entries before its groups`() {
        // Entry 2 sits after group Email in the XML but comes first in the tree.
        assertEquals("rootuser", text("{REF:U@T:Example}"))
        assertEquals("alice@example.test", text("{REF:U@T:Example Mail}"))
    }

    @Test
    fun `references by UUID match the hex in either case`() {
        assertEquals("bank-pass", text("{REF:P@I:${refHex(11)}}"))
        assertEquals("bank-pass", text("{ref:p@i:${refHex(11).lowercase()}}"))
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(
        delimiter = '|',
        value = [
            "unknown wanted code | {REF:X@T:Example Bank}",
            "custom field as wanted code | {REF:O@T:Example Bank}",
            "unknown search code | {REF:T@Z:Example}",
            "no match | {REF:T@T:nothing like this}",
            "a quoted phrase no field holds | {REF:U@T:\"Bank Example\"}",
            "history is not searched | {REF:U@T:Ancient}",
            "body of four characters | {REF:T@T:}",
            "no at sign | {REF:TxT:Example}",
            "no colon | {REF:T@TxExample}",
            "no closing brace | {REF:T@T:Example",
        ],
    )
    fun `a reference KeePass 2 can't resolve stays as written`(case: String, raw: String) {
        assertEquals(raw, text(raw), case)
    }

    @Test
    fun `search text with no words matches every entry, so the first in tree order is the target`() {
        assertEquals("Example Root", text("{REF:T@T: }"))
        assertEquals("Example Root", text("{REF:T@T:\"\"}"))
    }

    @Test
    fun `a nested reference resolves through the target's field`() {
        assertEquals("bank-pass", text("{REF:P@I:${refHex(14)}}"))
        assertEquals("bank-pass", text("{REF:U@T:Nested}"))
    }

    @Test
    fun `a circular or self reference resolves to nothing, as KeePass 2's depth limit gives`() {
        assertEquals("", text("{REF:P@T:Loop A}"))
        assertEquals("", text("{REF:P@T:Self}"))
        assertEquals("x  y", text("x {REF:P@T:Loop B} y"))
    }

    @Test
    fun `references resolve to depth 12`() {
        // Chain k is compiled one level deeper per link: from Chain 2 "end" is at level 11.
        assertEquals("end", text("{REF:U@I:${refHex(202)}}"))
        assertEquals("", text("{REF:U@I:${refHex(201)}}"))
    }

    @Test
    fun `one cache serves every level, so a value cut by depth is reused at the top`() {
        // Alone, Chain 11's reference resolves to "end"; after Chain 1's chain cached it as "" it
        // stays "".
        assertEquals("end", text("{REF:U@I:${refHex(211)}}"))
        assertEquals("|", text("{REF:U@I:${refHex(201)}}|{REF:U@I:${refHex(211)}}"))
    }

    @Test
    fun `a resolved reference fills every occurrence, ignoring case`() {
        assertEquals("bob bob", text("{REF:U@T:Example Bank} {ref:u@t:example bank}"))
    }

    @Test
    fun `a pass resolves at most 20 references, failed lookups included`() {
        val twentyOne = (1..21).joinToString(",") { "{REF:T@I:${refHex(300 + it)}}" }
        assertEquals((1..20).joinToString(",") { "Target $it" } + ",{REF:T@I:${refHex(321)}}", text(twentyOne))
        val failing = "{REF:T@T:zz}".repeat(20) + "{REF:T@I:${refHex(11)}}"
        assertEquals(failing, text(failing))
        assertEquals("{REF:T@T:zz}".repeat(19) + "Example Bank", text("{REF:T@T:zz}".repeat(19) + "{REF:T@I:${refHex(11)}}"))
    }

    @Test
    fun `a value that inserts a password, at any depth, is reported and returned masked`() {
        val direct = refs.resolve(FieldValue.Plain("{REF:P@T:Example Bank}"))
        assertTrue(direct.insertsPassword)
        assertIs<FieldValue.Protected>(direct.value)
        val nested = refs.resolve(FieldValue.Plain("{REF:U@T:Nested}"))
        assertTrue(nested.insertsPassword)
        assertEquals("bank-pass", nested.value.reveal())
        val user = refs.resolve(FieldValue.Plain("{REF:U@T:Example Bank}"))
        assertFalse(user.insertsPassword)
        assertIs<FieldValue.Plain>(user.value)
        val missing = refs.resolve(FieldValue.Plain("{REF:P@T:nothing}"))
        assertFalse(missing.insertsPassword)
    }

    @Test
    fun `a protected value stays masked, resolved or not`() {
        val resolved = refs.resolve(FieldValue.Protected(ProtectedText.of("{REF:U@T:Example Bank}")))
        assertIs<FieldValue.Protected>(resolved.value)
        assertEquals("bob", resolved.value.reveal())
        assertIs<FieldValue.Protected>(refs.resolve(FieldValue.Protected(ProtectedText.of("plain"))).value)
    }

    @Test
    fun `other placeholders stay as stored and are reported`() {
        val notes = refs.resolve(FieldValue.Plain("pw {REF:U@T:Example Bank} and {S:Account}"), customNames = listOf("Account"))
        assertEquals("pw bob and {S:Account}", notes.value.reveal())
        assertTrue(notes.keepsPlaceholders)
        // {S:} for a field the entry doesn't have stays as written.
        assertFalse(refs.resolve(FieldValue.Plain("pw {REF:U@T:Example Bank} and {S:Account}")).keepsPlaceholders)
        assertFalse(refs.resolve(FieldValue.Plain("{S:Account}")).keepsPlaceholders)
        assertTrue(refs.resolve(FieldValue.Plain("{S:account}"), customNames = listOf("Account")).keepsPlaceholders)
        assertFalse(refs.resolve(FieldValue.Plain("{REF:U@T:Example Bank}")).keepsPlaceholders)
        assertTrue(refs.resolve(FieldValue.Plain("{USERNAME}")).keepsPlaceholders)
        assertTrue(refs.resolve(FieldValue.Plain("{REF:X@T:Example Bank} {TITLE}")).keepsPlaceholders)
    }

    @Test
    fun `text without a reference comes back as it is`() {
        val value = FieldValue.Plain("no braces here")
        assertEquals(value, refs.resolve(value).value)
        assertEquals(0, refs.resolve(value).searches)
    }

    @Test
    fun `a resolve runs at most 20 target searches per pass per level, cached references not again`() {
        val twentyOne = (1..21).joinToString(",") { "{REF:T@I:${refHex(300 + it)}}" }
        assertEquals(20, refs.resolve(FieldValue.Plain(twentyOne)).searches)
        // Chain 1 to 12: one search per level, and the 12th link's text is cut without one.
        assertEquals(12, refs.resolve(FieldValue.Plain("{REF:U@I:${refHex(201)}}")).searches)
        // The second, cached reference to Chain 11 needs no search.
        assertEquals(12, refs.resolve(FieldValue.Plain("{REF:U@I:${refHex(201)}}|{REF:U@I:${refHex(211)}}")).searches)
        assertEquals(1, refs.resolve(FieldValue.Plain("{REF:U@T:Example Bank} {ref:u@t:example bank}")).searches)
    }

    @Test
    fun `a reference whose text doubles on every pass stops at the length bound and stays as stored`() {
        // Twenty failing references use up the inner pass, so the self-reference comes back
        // literal and each outer pass doubles it.
        val notes = "{REF:T@T:zz}".repeat(20) + "{REF:N@T:Doubling}{REF:N@T:Doubling}"
        val entry = "<Entry><UUID>${TestVaults.refUuid(2)}</UUID><String><Key>Title</Key><Value>Doubling</Value></String>" +
            "<String><Key>Notes</Key><Value>$notes</Value></String></Entry>"
        val doubling = FieldRefs.from(documentOf(TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry))))
        val started = System.nanoTime()
        val resolved = doubling.resolve(FieldValue.Plain("{REF:N@T:Doubling}"))
        assertEquals("{REF:N@T:Doubling}", resolved.value.reveal())
        assertFalse(resolved.insertsPassword)
        assertTrue(System.nanoTime() - started < 5_000_000_000L, "took ${(System.nanoTime() - started) / 1_000_000} ms")
    }

    @Test
    fun `a resolve reads entries only up to the first match`() {
        // Entry 2 is first in tree order.
        assertEquals(1, refs.resolve(FieldValue.Plain("{REF:U@T:Example Root}")).entriesRead)
        assertTrue(refs.resolve(FieldValue.Plain("{REF:U@T:Old Login}")).entriesRead > 40)
    }

    @Test
    fun `a released session drops its resolver`() {
        val session = kotlinx.coroutines.runBlocking { TestVaults.unlock(TestVaults.referenceVault()) }.session
        session.refs.resolve(FieldValue.Plain("{REF:U@T:Example Bank}"))
        session.release()
        kotlin.test.assertFailsWith<IllegalStateException> { session.refs }
    }

    @Test
    fun `a resolved value never shows in toString`() {
        val resolved = refs.resolve(FieldValue.Plain("{REF:P@T:Example Bank}"))
        assertFalse("bank-pass" in resolved.toString())
        assertFalse("bank-pass" in refs.toString())
        assertFalse("bob" in refs.toString())
    }

    @Test
    fun `the index never holds resolved values`() {
        val index = VaultIndex.from(documentOf(TestVaults.referenceVault()))
        val holder = index.rows(Chip.All, "Reference Holder").single()
        assertEquals("{REF:U@T:Example Bank}", holder.userName)
        // Entry 14's references resolve to "bob"; the search finds only stored text holding it.
        assertEquals(listOf("Example Bank", "Probes"), index.rows(Chip.All, "bob").map { it.title })
    }
}
