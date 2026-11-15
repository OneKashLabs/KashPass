package org.onekash.kashpass.vault.keepass2

import io.kotest.property.RandomSource
import io.kotest.property.arbitrary.next
import java.time.Instant
import java.util.UUID
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.index.documentOf
import org.onekash.kashpass.vault.property.KeePassText
import org.onekash.kashpass.vault.property.TextProperties
import org.onekash.kashpass.vault.property.escaped
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.VaultModel
import org.onekash.kashpass.vault.testing.VaultModel.Value

/**
 * Checks the text properties' expected values ([KeePassText]) against KeePass 2 itself: a batch
 * of strings (fixed edge cases and generated ones from one seed) is set by KashPass's editor path
 * in an entry's five fields (Title stored protected by the entry, the password from typed
 * characters), saved once, and KeePass 2's report of each field must hash to the expected value.
 * KashPass's own reading of the save must equal KeePass 2's; the result is written to
 * build/reports/keepass2/text-fidelity.md. Runs with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2TextFidelityTest {

    @Test
    fun `KeePass 2 reads every text KashPass saves as the text properties expect`() {
        val seed = PropertyRuns.seed()
        val strings = EDGES + List(GENERATED) { Generators.anyText.next(RandomSource.seeded(seed + it)) }
        val perEntry = strings.chunked(FIELDS.size).map { it + List(FIELDS.size - it.size) { "" } }
        val uuids = perEntry.indices.map { UUID(0x5445_5854L, it.toLong()) }
        val vault = VaultModel.write(
            VaultModel.Doc(VaultModel.Group("Root", entries = uuids.map { u ->
                VaultModel.Entry(listOf("Title" to Value.Protected("t"), "UserName" to Value.Plain("u"), "Password" to Value.Protected("p"), "URL" to Value.Plain("w"), "Notes" to Value.Plain("n")), uuid = u)
            })),
            aesRounds = 1UL,
        )
        var document = documentOf(vault)
        for ((i, values) in perEntry.withIndex()) {
            // DocumentIds keys an entry by its UUID's string form.
            val id = uuids[i].toString()
            val draft = EntryDraft(values[0], values[1], ProtectedText.of(values[2].toCharArray()), values[3], values[4])
            document = (EntryEdits.edit(document, id, draft, Instant.parse("2030-01-01T00:00:00Z")) as? EditResult.Changed)?.document ?: document
        }
        val save = VaultFile("text-fidelity.kdbx", VaultXmlCodec.encodeBytes(document))
        val key = KeePass2Run.newKey()
        val keePass = fields(KeePass2Run.keepass2(listOf(save), key).getValue(save.name) as? KeePass2Report.Opened ?: fail("KeePass 2 refuses the save"))
        val kashPass = fields(DocumentReport.of(save, key) as KeePass2Report.Opened)

        val problems = mutableListOf<String>()
        for ((i, values) in perEntry.withIndex()) {
            // A report names an entry by its UUID in lowercase hex without dashes.
            val entry = uuids[i].toString().replace("-", "")
            for ((f, text) in FIELDS.zip(values)) {
                val expected = if (f in PROTECTED) KeePassText.protected(text) else KeePassText.clear(text)
                val theirs = keePass[entry to f]
                val ours = kashPass[entry to f]
                if (theirs != KeePass2Report.mac(key, expected.toByteArray(Charsets.UTF_8))) problems += "$f ${text.escaped()}: KeePass 2 reads other than ${expected.escaped()}"
                if (ours != theirs) problems += "$f ${text.escaped()}: KashPass reads its save other than KeePass 2 does"
            }
        }
        val out = StringBuilder("# Text fidelity\n\n")
            .append("Seed $seed: ${EDGES.size} edge strings and $GENERATED generated ones, set by KashPass in ${FIELDS.joinToString()} and read by KeePass 2.\n\n")
            .append(if (problems.isEmpty()) "No problems: KeePass 2 reads every value as expected.\n" else "Problems (${problems.size}):\n\n" + KeePass2Files.bullets(problems) + "\n")
        KeePass2Files.writeReport("text-fidelity.md", out.toString())
        if (problems.isNotEmpty()) fail("${problems.size} problems (seed $seed):\n" + problems.take(20).joinToString("\n"))
    }

    @Test
    fun `KashPass reads hand-written whitespace in a value as KeePass 2 reads it`() {
        val key = KeePass2Run.newKey()
        // One vault per case, so a file KeePass 2 refuses doesn't hide the other cases.
        val files = WHITESPACE.mapIndexed { i, (name, xml) ->
            name to VaultFile("whitespace-$i.kdbx", TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry(xml))))
        }
        val keePass = KeePass2Run.keepass2(files.map { it.second }, key)
        val problems = mutableListOf<String>()
        val lines = mutableListOf<String>()
        for ((name, file) in files) {
            val theirs = keePass.getValue(file.name)
            val ours = DocumentReport.of(file, key)
            if (theirs !is KeePass2Report.Opened || ours !is KeePass2Report.Opened) {
                lines += "$name: KeePass 2 ${if (theirs is KeePass2Report.Opened) "opens" else "refuses"} it, KashPass ${if (ours is KeePass2Report.Opened) "opens" else "refuses"} it"
                if ((theirs is KeePass2Report.Opened) != (ours is KeePass2Report.Opened)) problems += lines.last()
                continue
            }
            val read = fields(theirs)[ENTRY to "Notes"]
            val reading = CANDIDATES.firstOrNull { KeePass2Report.mac(key, it.toByteArray(Charsets.UTF_8)) == read }?.escaped() ?: "another text"
            lines += "$name: KeePass 2 reads \"$reading\""
            if (fields(ours)[ENTRY to "Notes"] != read) problems += "$name: KashPass reads other than KeePass 2 (\"$reading\")"
        }
        KeePass2Files.writeReport(
            "text-whitespace.md",
            "# Hand-written whitespace\n\n" + KeePass2Files.bullets(lines) + "\n\n" +
                (if (problems.isEmpty()) "No problems.\n" else "Problems (${problems.size}):\n\n" + KeePass2Files.bullets(problems) + "\n"),
        )
        if (problems.isNotEmpty()) fail(problems.joinToString("\n"))
    }

    // An entry holding [value] as the raw XML of its Notes Value element.
    private fun entry(value: String) =
        "<Entry><UUID>${TestVaults.refUuid(1)}</UUID><String><Key>Title</Key><Value>w</Value></String>" +
            "<String><Key>Notes</Key>$value</String></Entry>\n"

    // Each field's HMAC in a report, by entry UUID (lowercase hex) and field key.
    private fun fields(report: KeePass2Report.Opened): Map<Pair<String, String>, String> {
        val out = HashMap<Pair<String, String>, String>()
        var entry: String? = null
        var inHistory = false
        for (line in report.lines) {
            val parts = line.split(' ')
            when (parts[0]) {
                "entry" -> { entry = parts[2]; inHistory = false }
                "history" -> inHistory = true
                "field" -> if (!inHistory && entry != null) out[entry to parts[1]] = parts[3]
            }
        }
        return out
    }

    private companion object {
        val FIELDS = TextProperties.FIELDS
        val PROTECTED = TextProperties.PROTECTED
        const val GENERATED = 60

        val ENTRY = TestVaults.refHex(1).lowercase()

        // Value elements written by hand, each in its own vault: whitespace alone, by character
        // reference, around a comment, in CDATA, and under xml:space preserve (with and without
        // padding) or default.
        val WHITESPACE = listOf(
            "spaces" to "<Value>   </Value>",
            "tab, CR by reference, LF" to "<Value>\t&#xD;\n</Value>",
            "space by reference" to "<Value>&#x20;</Value>",
            "space, comment, text" to "<Value> <!-- c --> y</Value>",
            "CDATA of spaces" to "<Value><![CDATA[  ]]></Value>",
            "spaces around CDATA" to "<Value>  <![CDATA[x]]>  </Value>",
            "xml:space preserve" to "<Value xml:space=\"preserve\">   </Value>",
            "xml:space preserve with padding" to "<Value xml:space=\" preserve \">   </Value>",
            "xml:space default" to "<Value xml:space=\"default\">   </Value>",
        )

        // Texts the whitespace cases can read as, to name KeePass 2's reading in the report.
        val CANDIDATES = listOf("", "   ", " ", "  ", "\t\r\n", " y", "  y", "y", "x", "  x  ")

        // Each class of KeePass 2's text rules at least once: whitespace alone, CR, controls, lone
        // and paired surrogates, noncharacters, XML specials.
        val EDGES = listOf(
            "   ", "\t", "\n", "\r", "\r\n", " a ", "a\rb", "a\u0001b", "\u0000", "\uD800", "\uDC00", "a😀b",
            "\uFFFE\uFFFF", "\uFFFD", "<&>\"'", "\u007F", "x\uD800y", " \u0001 ",
        )
    }
}
