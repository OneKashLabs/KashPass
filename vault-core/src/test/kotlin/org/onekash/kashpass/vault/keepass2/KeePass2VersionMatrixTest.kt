package org.onekash.kashpass.vault.keepass2

import java.io.File
import java.time.Instant
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.doc.open
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.header.UnsupportedReason
import org.onekash.kashpass.vault.open.OpenResult

/**
 * Runs the KeePass 2 versions of the scripts' version table against KashPass and requires the
 * outcome written down for each version ([KeePassVersions]): every version older than the pin
 * opens what KashPass saves, or refuses it with the predicted exception, and KashPass opens what
 * every version writes, or refuses KDBX 3.1, and saves it back to that version. Writes
 * version-matrix.md and version-matrix-written.md to [KeePass2Files.reportDir], with "Run aborted"
 * when a run stops early. Runs with -Pkashpass.matrix only (-Pkashpass.matrix=<v>,<v> limits the
 * versions).
 */
@EnabledIfSystemProperty(named = KeePass2VersionMatrixTest.PROPERTY, matches = ".+")
class KeePass2VersionMatrixTest {

    @Test
    fun `every older KeePass 2 version opens what KashPass saves, as its source predicts`() {
        val versions = selected().filter { it.name != KeePassVersions.PIN }
        val saved = KeePass2Files.saveSources.map { KeePass2Files.kashPassSave(it) }
        val kinds = saved.associate { it.name to KeePassVersions.kindOf(it) }
        val key = KeePass2Run.newKey()
        val out = StringBuilder("# KeePass 2 version matrix: KashPass's saves\n\n")
            .append("${saved.size} saves (every fixture that opens and every editable corpus case), each read by KeePass ")
            .append("${KeePassVersions.PIN} as the reference and by each version below.\n\n")
            .append("| Version | Opened | Refused as predicted | Findings | Time |\n|---|---|---|---|---|\n")
        val findings = mutableListOf<String>()
        var completed = false
        try {
            // The pin's reading is the content KashPass saved: KeePass2SaveTest checks that it
            // equals the opened file's.
            val reference = KeePass2Run.keepass2(saved, key, KeePassVersions.PIN)
            reference.filterValues { it !is KeePass2Report.Opened }.forEach { (name, r) -> findings += "$name: KeePass ${KeePassVersions.PIN} refuses it: $r" }
            for (version in versions) {
                val t0 = System.nanoTime()
                val theirs = KeePass2Run.keepass2(saved, key, version.name)
                var opened = 0
                var refused = 0
                val before = findings.size
                for (f in saved) {
                    val expected = KeePassVersions.expected(version, kinds.getValue(f.name))
                    val report = theirs.getValue(f.name)
                    when (expected) {
                        is KeePassVersions.Expected.Refuses -> when {
                            report is KeePass2Report.Refused && expected.matches(report.reason) -> refused++
                            else -> findings += "${version.name} ${f.name}: expected a refusal ($expected), got ${describe(report)}"
                        }
                        is KeePassVersions.Expected.Opens -> {
                            val ref = reference.getValue(f.name) as? KeePass2Report.Opened ?: continue
                            if (report !is KeePass2Report.Opened) {
                                findings += "${version.name} ${f.name}: expected to open, got ${describe(report)}"
                                continue
                            }
                            if (report.capabilities() != expected.unseen) {
                                findings += "${version.name} ${f.name}: reader states ${report.capabilities()}, expected ${expected.unseen}"
                            }
                            val diff = KeePass2Report.contentDiff(ref, report)
                            if (diff.isEmpty()) opened++ else findings += "${version.name} ${f.name}: reads other content:\n  " + diff.take(6).joinToString("\n  ")
                        }
                    }
                }
                out.append("| ${version.name} | $opened | $refused | ${findings.size - before} | ${(System.nanoTime() - t0) / 1_000_000_000} s |\n")
            }
            completed = true
        } finally {
            writeReport("version-matrix.md", out, findings, completed)
        }
        if (findings.isNotEmpty()) fail("${findings.size} findings, see ${File(KeePass2Files.reportDir, "version-matrix.md")}:\n" + findings.take(20).joinToString("\n"))
    }

    @Test
    fun `KashPass opens what every KeePass 2 version writes, as its source predicts, and saves it back`() {
        val versions = selected()
        val key = KeePass2Run.newKey()
        val out = StringBuilder("# KeePass 2 version matrix: what each version writes\n\n")
            .append("| Version | Configuration | Format | KashPass | Round trip |\n|---|---|---|---|---|\n")
        val findings = mutableListOf<String>()
        var completed = false
        try {
            for (version in versions) {
                val expected = KeePassVersions.written(version)
                val written = KeePass2Run.keepass2Write(version.name)
                if (written.keys != expected.keys) findings += "${version.name}: wrote ${written.keys.sorted()}, expected ${expected.keys.sorted()}"
                val theirs = KeePass2Run.keepass2(written.values.toList(), key, version.name)
                val saves = mutableListOf<Pair<String, VaultFile>>()
                val rows = LinkedHashMap<String, Array<String>>()
                for ((configuration, file) in written.toSortedMap()) {
                    val format = kdbxVersion(file.bytes)
                    val row = arrayOf(version.name, configuration, format, "", "")
                    rows[file.name] = row
                    if (format != expected[configuration]) findings += "${version.name} $configuration: wrote KDBX $format, expected ${expected[configuration]}"
                    val opened = CompanionRig.openResult(file)
                    if (format == "3.1") {
                        if (opened == OpenResult.Unsupported(UnsupportedReason.FormatVersion(3, 1))) {
                            row[3] = "refused 3.1"
                        } else {
                            row[3] = "got $opened"
                            findings += "${version.name} $configuration: KashPass gives $opened for KDBX 3.1"
                        }
                        continue
                    }
                    if (opened !is OpenResult.Unlocked) {
                        row[3] = "got $opened"
                        findings += "${version.name} $configuration: KashPass gives $opened"
                        continue
                    }
                    val diff = KeePass2Report.diff(theirs.getValue(file.name), DocumentReport.of(file, key))
                    row[3] = if (diff.isEmpty()) "opens, same content" else "opens, other content"
                    if (diff.isNotEmpty()) findings += "${version.name} $configuration: KashPass reads other content:\n  " + diff.take(6).joinToString("\n  ")
                    val document = VaultXmlCodec.open(file.bytes, TestFiles.credentials(file), ContainerRig.LIMITS)
                    val edited = EntryEdits.add(document, null, EntryDraft("Added by KashPass", "", ProtectedText.of("p"), "", ""), Instant.parse("2026-11-01T12:00:00Z")).document
                    saves += file.name to VaultFile("saved-${file.name}", VaultXmlCodec.encodeBytes(edited))
                }
                // Round trip: the version that wrote each file opens KashPass's save of it.
                val back = KeePass2Run.keepass2(saves.map { it.second }, key, version.name)
                for ((source, save) in saves) {
                    val report = back.getValue(save.name)
                    val diff = if (report is KeePass2Report.Opened) KeePass2Report.diff(report, DocumentReport.of(save, key)) else listOf("refused: $report")
                    rows.getValue(source)[4] = if (diff.isEmpty()) "opens, same content" else "differs"
                    if (diff.isNotEmpty()) findings += "${version.name} ${save.name}: the writing version reads KashPass's save differently:\n  " + diff.take(6).joinToString("\n  ")
                }
                rows.values.forEach { out.append("| " + it.joinToString(" | ") + " |\n") }
            }
            completed = true
        } finally {
            writeReport("version-matrix-written.md", out, findings, completed)
        }
        if (findings.isNotEmpty()) fail("${findings.size} findings, see ${File(KeePass2Files.reportDir, "version-matrix-written.md")}:\n" + findings.take(20).joinToString("\n"))
    }

    // A run that threw before the end is marked aborted, so a partial table never reads as a pass.
    private fun writeReport(name: String, out: StringBuilder, findings: List<String>, completed: Boolean) {
        if (!completed) out.append("\nRun aborted before every version finished; see the test output.\n")
        out.append(
            when {
                findings.isNotEmpty() -> "\nFindings (${findings.size}):\n\n" + findings.joinToString("\n") { "- $it" } + "\n"
                completed -> "\nNo finding: every version did what its source predicts.\n"
                else -> ""
            },
        )
        KeePass2Files.writeReport(name, out.toString())
    }

    // The file version a KDBX header states (bytes 8-11, minor then major, little-endian).
    private fun kdbxVersion(bytes: ByteArray): String {
        fun u16(at: Int) = (bytes[at].toInt() and 0xFF) or ((bytes[at + 1].toInt() and 0xFF) shl 8)
        return "${u16(10)}.${u16(8)}"
    }

    private fun describe(report: KeePass2Report) = when (report) {
        is KeePass2Report.Refused -> "refused: ${report.reason}"
        is KeePass2Report.Opened -> "opened"
    }

    companion object {
        /** System property set by `-Pkashpass.matrix`: "true" for every version, or a list. */
        const val PROPERTY = "kashpass.matrix"

        // The versions this run covers, each with expectations: every row of the scripts' version
        // table, or the ones -Pkashpass.matrix lists. A table row without expectations fails.
        internal fun selected(): List<KeePassVersions.Version> {
            val table = File(TestFiles.root, "scripts/fixtures/keepass2-versions.tsv")
            if (!table.isFile) fail("KeePass 2 tool missing: ${table.path} (local tooling, not in git)")
            val rows = table.readLines().filter { it.isNotBlank() && !it.startsWith("#") }.map { it.substringBefore('\t') }
            val all = rows.map { KeePassVersions.named(it) }
            val asked = System.getProperty(PROPERTY).orEmpty()
            if (asked == "true") return all
            return asked.split(',').map { it.trim() }.filter { it.isNotEmpty() }.map { v -> all.singleOrNull { it.name == v } ?: fail("KeePass $v is not in ${table.path}") }
        }
    }
}
