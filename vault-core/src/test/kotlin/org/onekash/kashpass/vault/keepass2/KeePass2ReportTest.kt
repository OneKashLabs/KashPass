package org.onekash.kashpass.vault.keepass2

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.keepass2.KeePass2Report.Companion.mac

class KeePass2ReportTest {

    private val key = ByteArray(32) { it.toByte() }

    private val sample = """
        version 4.0
        cipher 31c1f2e6bf714350be5805216afc5aff
        kdf c9d9f39a628a4460bf740d08c18a4fea
        compression gzip
        name Test%20vault
        group 0 Root tags=
        group 1 Email tags=work
        entry 2 00112233445566778899aabbccddeeff qualityCheck=on tags= history=1
        field Password * aaaa
        field Title - bbbb
        history 0
        field Title - cccc
    """.trimIndent()

    @Test
    fun `a report parses, keeps its lines and names each entry's path and title`() {
        val report = assertIs<KeePass2Report.Opened>(KeePass2Report.parse(sample))
        assertEquals(sample.lines(), report.lines)
        assertEquals("4.0", report.header("version"))
        assertEquals(listOf(KeePass2Report.EntryPath(listOf("Root", "Email"), "bbbb")), report.entryPaths())
    }

    @Test
    fun `a refusal parses as refused`() {
        assertIs<KeePass2Report.Refused>(KeePass2Report.parse("REFUSE InvalidCompositeKeyException: The master key is invalid!\n"))
    }

    @Test
    fun `a changed field hash is named with its entry`() {
        val changed = KeePass2Report.parse(sample.replace("field Password * aaaa", "field Password * dddd"))
        val diff = KeePass2Report.diff(KeePass2Report.parse(sample), changed)
        assertEquals(
            listOf(
                "entry Root/Email 00112233445566778899aabbccddeeff: expected field Password * aaaa",
                "entry Root/Email 00112233445566778899aabbccddeeff: actual field Password * dddd",
            ),
            diff,
        )
        assertTrue(KeePass2Report.diff(KeePass2Report.parse(sample), KeePass2Report.parse(sample)).isEmpty())
    }

    @Test
    fun `an entry moved to another group at the same depth is a difference`() {
        val two = sample.replace("group 1 Email tags=work\n", "group 1 Email tags=work\ngroup 1 Banking tags=\n")
        val moved = sample.replace("group 1 Email tags=work\n", "group 1 Banking tags=\ngroup 1 Email tags=work\n")
        // The same groups and entry lines; the entry sits under Banking in one and under Email in
        // the other.
        val diff = KeePass2Report.diff(KeePass2Report.parse(two), KeePass2Report.parse(moved))
        assertTrue(diff.any { "Root/Banking 0011" in it } && diff.any { "Root/Email 0011" in it }, diff.toString())
    }

    @Test
    fun `a changed group tag is a difference`() {
        val diff = KeePass2Report.diff(KeePass2Report.parse(sample), KeePass2Report.parse(sample.replace("tags=work", "tags=home")))
        assertTrue(diff.isNotEmpty())
    }

    @Test
    fun `the content diff ignores the container lines but not the content`() {
        val rekeyed = sample.replace("cipher 31c1f2e6bf714350be5805216afc5aff", "cipher d6038a2b8b6f4cb5a524339a31dbb59a").replace("version 4.0", "version 4.1")
        assertTrue(KeePass2Report.contentDiff(KeePass2Report.parse(sample), KeePass2Report.parse(rekeyed)).isEmpty())
        assertTrue(KeePass2Report.diff(KeePass2Report.parse(sample), KeePass2Report.parse(rekeyed)).isNotEmpty())
        assertTrue(KeePass2Report.contentDiff(KeePass2Report.parse(sample), KeePass2Report.parse(sample.replace("cccc", "eeee"))).isNotEmpty())
    }

    // A reader before 2.48 leaves out the group tags and quality check tokens and lists them in its
    // capabilities line.
    private val olderReader = sample.lines().joinToString("\n") { line ->
        when {
            line.startsWith("group ") -> line.replace(Regex(" tags=\\S*"), "")
            line.startsWith("entry ") -> line.replace(Regex(" qualityCheck=\\S+"), "")
            line.startsWith("name ") -> line + "\ncapabilities no-group-tags,no-quality-check"
            else -> line
        }
    }

    @Test
    fun `a reader's capabilities leave out exactly the tokens it cannot see`() {
        val full = KeePass2Report.parse(sample)
        val older = KeePass2Report.parse(olderReader)
        assertEquals(setOf("no-group-tags", "no-quality-check"), (older as KeePass2Report.Opened).capabilities())
        assertEquals(emptyList(), KeePass2Report.diff(full, older), "no difference in the tree, the entry lines or the header")
        assertEquals(emptyList(), KeePass2Report.diff(older, full))
    }

    @Test
    fun `a reader's capabilities hide no other difference`() {
        val full = KeePass2Report.parse(sample.replace("field Password * aaaa", "field Password * dddd").replace("tags= history=1", "tags=x history=1"))
        val diff = KeePass2Report.diff(full, KeePass2Report.parse(olderReader))
        assertTrue(diff.any { "field Password * dddd" in it }, diff.toString())
        assertTrue(diff.any { "tags=x" in it }, "entry tags stay compared: $diff")
    }

    @Test
    fun `without capabilities a group line without its tags token differs from one with empty tags`() {
        val withoutToken = KeePass2Report.parse(sample.replace("group 0 Root tags=", "group 0 Root"))
        assertTrue(KeePass2Report.diff(KeePass2Report.parse(sample), withoutToken).isNotEmpty())
    }

    @Test
    fun `without capabilities a missing tags or quality check token is a difference`() {
        val withoutTokens = KeePass2Report.parse(olderReader.lines().filterNot { it.startsWith("capabilities ") }.joinToString("\n"))
        val diff = KeePass2Report.diff(KeePass2Report.parse(sample), withoutTokens)
        assertTrue(diff.any { "tags=work" in it }, diff.toString())
        assertTrue(diff.any { "qualityCheck=on" in it }, diff.toString())
    }

    @Test
    fun `names are percent-encoded byte by byte as KeePass 2's report writes them`() {
        assertEquals("Account%20number", KeePass2Report.escape("Account number"))
        assertEquals("%C3%BC%25", KeePass2Report.escape("ü%"))
        assertEquals("%", KeePass2Report.escape(""))
    }

    @Test
    fun `KashPass's report of a KeePass 2 fixture holds every entry with keyed hashes, never values`() {
        val bytes = Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx")
        val file = VaultFile("weak.kdbx", bytes)
        val report = assertIs<KeePass2Report.Opened>(DocumentReport.of(file, key))
        assertEquals("4.0", report.header("version"))
        assertEquals("gzip", report.header("compression"))
        assertEquals("c9d9f39a628a4460bf740d08c18a4fea", report.header("kdf"))
        val bank = report.lines.dropWhile { !it.startsWith("group 1 Banking") }
        assertTrue("field Password * ${mac(key, "b@nk-p4ss".toByteArray())}" in bank, bank.toString())
        assertTrue(bank.any { it.startsWith("attachment recovery-codes.txt - 20 ") })
        // Ordinal order: upper case before lower case, so otp comes after UserName.
        val fields = bank.takeWhile { !it.startsWith("group 1") || it.startsWith("group 1 Banking") }
            .filter { it.startsWith("field ") }.map { it.split(' ')[1] }
        assertEquals(listOf("Account%20number", "Password", "Title", "UserName", "otp"), fields)
        val text = report.lines.joinToString("\n")
        for (secret in listOf("b@nk-p4ss", "current-password", "alice", "Example Bank")) assertTrue(secret !in text, secret)
        assertEquals(3, report.entryPaths().size)
    }
}
