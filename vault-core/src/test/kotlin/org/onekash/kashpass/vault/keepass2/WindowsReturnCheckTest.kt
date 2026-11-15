package org.onekash.kashpass.vault.keepass2

import java.io.File
import java.nio.file.Files
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.EntryParts
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.index.documentOf
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.property.escaped
import org.onekash.kashpass.vault.testing.VaultModel
import org.onekash.kashpass.vault.testing.VaultModel.Value
import org.onekash.kashpass.vault.xml.XmlText

/**
 * The Windows check: KeePass 2 on Windows, which derives Argon2 with its native library, opens
 * KashPass's saves, adds one entry to each and saves; KashPass then opens every returned file with
 * its groups, database name and each entry it saved unchanged, plus the added one. One more vault
 * ([CR_VAULT]) tests how KeePass 2 on Windows reads a value of whitespace alone holding a CR
 * written as '&#xD;': KashPass reads it as empty, as KeePass 2 does under Mono, and the answer is a
 * finding for the owner ([crFinding]), not a failed check. The kit test writes the saves
 * (-Pkashpass.windowsKit=<dir>), the return test checks the returned files and writes
 * windows-return.md (-Pkashpass.windowsReturn=<dir>), and the self-check runs the check on files
 * KeePass 2 saved under Mono (-Pkashpass.keepass2).
 */
class WindowsReturnCheckTest {

    @Test
    @EnabledIfSystemProperty(named = KIT_PROPERTY, matches = ".+")
    fun `writes the Windows check kit`() {
        writeKit(dir(System.getProperty(KIT_PROPERTY)))
    }

    @Test
    @EnabledIfSystemProperty(named = RETURN_PROPERTY, matches = ".+")
    fun `KashPass opens every file KeePass 2 on Windows saved after the kit's edit`() {
        val kit = dir(System.getProperty(RETURN_PROPERTY))
        val checked = check(kit, File(kit, "returned"))
        KeePass2Files.writeReport(
            "windows-return.md",
            "# Windows return check\n\nFinding for the owner: ${checked.finding}\n\n" +
                (if (checked.problems.isEmpty()) "No problems.\n" else "Problems (${checked.problems.size}):\n\n" + KeePass2Files.bullets(checked.problems) + "\n"),
        )
        if (checked.problems.isNotEmpty()) fail("${checked.problems.size} problems:\n" + checked.problems.joinToString("\n"))
    }

    @Test
    @EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
    fun `the return check passes on files KeePassLib saved after the kit's edit, and fails without the edit`() {
        val kit = Files.createTempDirectory("windows-kit").toFile()
        try {
            val files = writeKit(kit)
            val cases = files.map { KeePass2Run.ReplayCase(it.name.removeSuffix(".kdbx"), it, listOf(EDIT)) }
            val replayed = KeePass2Run.keepass2Replay(cases, KeePass2Run.newKey())
            val returned = File(kit, "returned").apply { mkdirs() }
            for (c in cases) File(returned, c.input.name).writeBytes(replayed.getValue(c.name).file.readBytes())
            val checked = check(kit, returned)
            assertTrue(checked.problems.isEmpty(), checked.problems.joinToString("\n"))
            // KeePass 2 under Mono reads the CR value as empty; checked on the pinned version.
            if (KeePass2Run.namedVersion == null) assertEquals(CR_EMPTY, checked.finding)
            // A file saved without the edit must fail the check.
            File(returned, files.first().name).writeBytes(files.first().bytes)
            assertTrue(check(kit, returned).problems.any { it.startsWith(files.first().name) }, "an unedited file passes the check")
        } finally {
            kit.deleteRecursively()
        }
    }

    @Test
    fun `the CR finding tells a value KeePass 2 kept as text from one it read as empty`() {
        assertEquals(CR_EMPTY, crFinding(crVault("")))
        assertEquals("$CR_TEXT: \"\\u000A\"", crFinding(crVault("\n")))
        // KashPass's own save holds the CR as text, so an unedited return would be a finding too.
        assertEquals("$CR_TEXT: \"\\u0009\\u000D\\u000A\"", crFinding(whitespaceCrVault().bytes))
        assertEquals("$CR_VAULT: not returned", crFinding(null))
    }

    // KashPass's save of every fixture that opens and the CR vault (last), with key files,
    // keepass2-manifest.tsv (file, credential mode, key file), entries.tsv (file, entries before
    // the edit, recycle bin included), edit.tsv (the edit as a replay line) and edit.txt (its
    // title, then its password, for the steps run by hand on Windows).
    private fun writeKit(kit: File): List<VaultFile> {
        kit.mkdirs()
        val files = Fixtures.kdbx4Opening.map { Fixtures.file(it) }.map { KeePass2Files.kashPassSave(it, "kashpass-${it.name}") } + whitespaceCrVault()
        TestFiles.writeManifest(kit, files)
        val key = KeePass2Run.newKey()
        File(kit, "entries.tsv").writeText(files.joinToString("") { "${it.name}\t${entries(DocumentReport.of(it, key)).size}\n" })
        File(kit, "edit.tsv").writeText(EDIT.line + "\n")
        File(kit, "edit.txt").writeText(EDIT.title + "\n" + EDIT.password + "\n")
        return files
    }

    // The problems with [returned] against the kit: a file missing or not opening, a group or the
    // database name changed, an entry KashPass saved that differs or is gone, or not exactly one
    // added entry with the edit's title and password; each starts with the file name. And the
    // finding on the CR vault ([crFinding]).
    private fun check(kit: File, returned: File): Checked {
        val key = KeePass2Run.newKey()
        val problems = problemsOf(kit, returned, key)
        // A CR vault that failed the check (not re-saved after the edit, or changed) shows nothing
        // about how KeePass 2 read it.
        val finding = if (problems.any { it.startsWith(CR_VAULT) }) "$CR_VAULT: undetermined, it fails the check above" else crFinding(File(returned, CR_VAULT).takeIf { it.isFile }?.readBytes())
        return Checked(problems, finding)
    }

    private class Checked(val problems: List<String>, val finding: String)

    private fun problemsOf(kit: File, returned: File, key: ByteArray): List<String> =
        TestFiles.readManifest(kit).flatMap { m ->
            val saved = VaultFile(m.name, File(kit, m.name).readBytes(), m.mode, m.keyFileName, m.keyFile)
            val back = File(returned, m.name).takeIf { it.isFile } ?: return@flatMap listOf("${m.name}: not in ${returned.path}")
            val file = VaultFile(m.name, back.readBytes(), m.mode, m.keyFileName, m.keyFile)
            val opened = CompanionRig.openResult(file)
            if (opened !is OpenResult.Unlocked) return@flatMap listOf("${m.name}: KashPass gives $opened")
            val savedReport = DocumentReport.of(saved, key)
            val returnedReport = DocumentReport.of(file, key)
            val before = entries(savedReport)
            val after = entries(returnedReport)
            val problems = mutableListOf<String>()
            if (frame(savedReport) != frame(returnedReport)) {
                problems += "${m.name}: groups or the database name differ: saved ${frame(savedReport) - frame(returnedReport).toSet()}, returned ${frame(returnedReport) - frame(savedReport).toSet()}"
            }
            for ((uuid, lines) in before) {
                val now = after[uuid]
                if (now == null) problems += "${m.name}: entry $uuid is gone"
                else if (now != lines) problems += "${m.name}: entry $uuid differs: saved ${(lines - now.toSet()).take(3)}, returned ${(now - lines.toSet()).take(3)}"
            }
            val added = after.filterKeys { it !in before }.values
            val title = "field Title ? " + KeePass2Report.mac(key, EDIT.title.toByteArray(Charsets.UTF_8))
            val password = "field Password ? " + KeePass2Report.mac(key, EDIT.password.toByteArray(Charsets.UTF_8))
            if (added.size != 1 || title !in added.single() || password !in added.single()) {
                problems += "${m.name}: expected one added entry titled '${EDIT.title}', found ${added.size} added"
            }
            problems
        }

    // A vault with one entry whose Notes KashPass's editor set to tab, CR, LF; KashPass writes
    // them as '\t&#xD;\n' (XmlWriter.escapeText).
    private fun whitespaceCrVault(): VaultFile {
        val document = documentOf(crVault("n"), TestFiles.password)
        val id = CR_ENTRY.toString()
        val d = EntryEdits.draftOf(document, id)!!
        val draft = EntryDraft(d.title, d.userName, d.password, d.url, "\t\r\n")
        val edited = (EntryEdits.edit(document, id, draft, Instant.parse("2030-01-01T00:00:00Z")) as EditResult.Changed).document
        return VaultFile(CR_VAULT, VaultXmlCodec.encodeBytes(edited))
    }

    // A vault holding the CR vault's entry with [notes] in clear, written by the test toolkit.
    private fun crVault(notes: String): ByteArray = VaultModel.write(
        VaultModel.Doc(VaultModel.Group("Root", entries = listOf(VaultModel.Entry(
            listOf("Title" to Value.Plain("Whitespace CR"), "UserName" to Value.Plain("u"), "Password" to Value.Protected("p"), "Notes" to Value.Plain(notes)),
            uuid = CR_ENTRY,
        )))),
        password = TestFiles.password,
    )

    // How KeePass 2 read the CR vault's Notes, from the raw text of its Value in the file it saved
    // back: no text means it read the value as empty; text means it kept the value as text. The
    // code units shown are after XML line-end normalization, so a CR written back as CR LF shows
    // as LF. KashPass's own reading can't tell the two apart (XmlElement.text reads both as empty).
    private fun crFinding(returned: ByteArray?): String {
        returned ?: return "$CR_VAULT: not returned"
        val document = runCatching { documentOf(returned, TestFiles.password) }.getOrNull() ?: return "$CR_VAULT: KashPass doesn't open it"
        val entry = DocumentIds.entries(document)[CR_ENTRY.toString()] ?: return "$CR_VAULT: the CR entry is gone"
        val notes = entry.children("String").lastOrNull { EntryParts.key(it)?.text() == "Notes" }?.let(EntryParts::value)
        val raw = notes?.children.orEmpty().filterIsInstance<XmlText>().joinToString("") { it.value }
        return if (raw.isEmpty()) CR_EMPTY else "$CR_TEXT: \"${raw.escaped()}\""
    }

    // The database name and every group line, in tree order: what the edit leaves unchanged.
    private fun frame(report: KeePass2Report): List<String> =
        (report as? KeePass2Report.Opened ?: fail("KashPass's report: $report")).lines.filter { it.startsWith("name ") || it.startsWith("group ") }

    // Each entry's report lines (history included) by entry UUID. A standard field's protected flag
    // is left out: KeePass 2 resets its memory protection settings to the defaults after every load
    // and its save writes the five standard fields with them.
    private fun entries(report: KeePass2Report): Map<String, List<String>> {
        val opened = report as? KeePass2Report.Opened ?: fail("KashPass's report: $report")
        val out = LinkedHashMap<String, MutableList<String>>()
        var current: MutableList<String>? = null
        for (line in opened.lines) {
            when {
                line.startsWith("entry ") -> current = out.getOrPut(line.split(' ')[2]) { mutableListOf() }.also { it += line.substringAfter(' ').substringAfter(' ') }
                line.startsWith("group ") -> current = null
                else -> current?.add(line.replace(STANDARD_FLAG, "$1 ?"))
            }
        }
        return out
    }

    private fun dir(path: String): File = File(path).let { if (it.isAbsolute) it else File(TestFiles.root, path) }

    private companion object {
        /** System property set by `-Pkashpass.windowsKit=<dir>`. */
        const val KIT_PROPERTY = "kashpass.windowsKit"

        /** System property set by `-Pkashpass.windowsReturn=<kit dir>`; files in its returned/. */
        const val RETURN_PROPERTY = "kashpass.windowsReturn"

        val STANDARD_FLAG = Regex("^(field (?:Title|UserName|Password|URL|Notes)) [*-]")

        /** The kit's vault for the CR case, and its entry. */
        const val CR_VAULT = "kashpass-whitespace-cr.kdbx"
        val CR_ENTRY: UUID = UUID(0, 1)

        /** The finding when KeePass 2 kept the value as text, followed by its code units. */
        const val CR_TEXT = "KeePass 2 on Windows keeps a whitespace-only value with a CR as text"

        /** The finding when KeePass 2 reads the CR value as empty, as KashPass and Mono do. */
        const val CR_EMPTY = "KeePass 2 on Windows reads the CR in a whitespace-only value as empty, as KashPass does"

        /** The kit's edit: one entry at the top level, as KeePass 2's Add Entry adds it. */
        val EDIT = CompanionOp.Add(null, CompanionOp.ADDED, "Windows check", "windows-check", "", "")
    }
}
