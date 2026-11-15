package org.onekash.kashpass.vault.keepass2

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.open
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.VaultIndex
import org.onekash.kashpass.vault.testing.TestVaults

/**
 * KashPass's search box returns the entries KeePass 2's simple-mode search returns
 * for the same query (`keepass2-read.sh --search`), on a copy of each vault holding what KashPass
 * searches. The copy and KashPass's recycle-bin rule stand for the listed differences: passwords
 * and protected custom values are never searched, custom field names are, standard field names
 * are not, an entry at the top matches no group name, and the recycle bin is never searched.
 *
 * KeePass 2 compares with .NET's culture rules (IgnoreCase, IgnoreNonSpace); KashPass folds case
 * and drops combining marks. For the probes in [FOLD_PROBES] (İ, ß, ø, ł, æ, a ligature, a
 * spacing mark) the two can differ; each difference is written to the report as a listed
 * difference, and Windows KeePass 2, which uses NLS and not Mono's collation, can differ again.
 * Every other query must agree exactly. Runs with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2SearchParityTest {

    private val probeVault = VaultFile(
        "search-probes.kdbx",
        TestVaults.rawXmlVault(
            TestVaults.keePassXml(
                entries = listOf(
                    "Café Noir", "İstanbul Office", "Straße 5", "Strasse 6", "Søren", "Łódź", "Æble", "ﬁle", "कार",
                ).mapIndexed { i, title -> entry(i + 2, title) }.joinToString("") +
                    "<Group><UUID>${TestVaults.refUuid(50)}</UUID><Name>Work</Name><Tags>office; team</Tags>" +
                    "<Group><UUID>${TestVaults.refUuid(51)}</UUID><Name>Inner</Name>${entry(60, "Deep Entry")}</Group></Group>",
            ),
            minor = 1,
        ),
    )

    private fun entry(n: Int, title: String) =
        "<Entry><UUID>${TestVaults.refUuid(n)}</UUID><String><Key>Title</Key><Value>$title</Value></String></Entry>"

    private val files by lazy {
        Fixtures.kdbx4Opening.map { Fixtures.file(it) } + listOf(
            VaultFile("browser.kdbx", TestVaults.browserVault(aesRounds = 1_000UL)),
            VaultFile("meta-protected.kdbx", TestVaults.metaProtectedVault()),
            VaultFile("references.kdbx", TestVaults.referenceVault()),
            probeVault,
        )
    }

    @Test
    fun `KashPass's search returns the entries KeePass 2 returns for every query`() {
        val queries = QUERIES + FOLD_PROBES
        val keepass = KeePass2Run.keepass2Search(files, queries, KeePass2Run.newKey())
        val problems = mutableListOf<String>()
        val listed = mutableListOf<String>()
        var compared = 0
        for (f in files) {
            val index = VaultIndex.from(VaultXmlCodec.open(f.bytes, TestFiles.credentials(f), ContainerRig.LIMITS))
            val bin = index.rows(Chip.RecycleBin, "").map { hex(it.id) }.toSet()
            for ((i, q) in queries.withIndex()) {
                val ours = index.rows(Chip.All, q).map { hex(it.id) }.toSet()
                val theirs = keepass.getValue(f.name)[i] - bin
                compared++
                if (ours == theirs) continue
                val line = "${f.name} \"$q\": KashPass only ${ours - theirs}, KeePass 2 only ${theirs - ours}"
                if (f === probeVault && q in FOLD_PROBES) listed += line else problems += line
            }
        }
        KeePass2Files.writeReport(
            "search-parity",
            "Queries compared: $compared\n\nFold probes that differ (listed differences):\n" + KeePass2Files.bullets(listed) +
                "\n\nOther differences:\n" + KeePass2Files.bullets(problems) + "\n",
        )
        assertTrue(compared > 100, "only $compared comparisons")
        assertEquals(emptyList(), problems)
    }

    // The row id is the entry's UUID in its first occurrence.
    private fun hex(id: String): String {
        val plain = id.replace("-", "").uppercase()
        check(plain.length == 32) { "row id is not a UUID: $id" }
        return plain
    }

    private companion object {
        val QUERIES = listOf(
            "bank", "Example Mail", "mail -bank", "\"Example Mail\"", "\"mail example\"", "example\tmail", "-", "--", "-mail",
            "\"\"", "\" \"", "EXAMPLE", "ExAmPlE bAnK", "cafe", "CAFÉ", "café", "Café", "İstanbul",
            "money", "important", "finance", "office", "team", "deep office", "Banking", "Email", "Root", "user", "note", "url",
            "title", "otp", "Account", "4711", "12345", "mail-pass", "bank-pass", "{REF:", "Reference Holder", "bob", "Chain 1",
            "Target 2", "Old Login", "sample", "\"sample entry\" -#2", "plugin", "styled",
        )
        // Mono's collation keeps İ apart from i and matches Æ for "a"; KashPass drops İ's dot
        // and keeps Æ as itself (run 2026-10-31).
        val FOLD_PROBES = listOf("istanbul", "ISTANBUL", "a b", "ss", "strasse", "straße", "STRASSE", "soren", "søren", "lodz", "łódź", "aeble", "æble", "ae", "file", "fi", "कर", "क")
    }
}
