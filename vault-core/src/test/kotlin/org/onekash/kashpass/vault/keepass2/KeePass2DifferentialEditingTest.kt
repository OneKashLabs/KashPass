package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.EntryParts
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.save.SafeSaver

/**
 * The same user action done by KashPass ([CompanionRig]: the editor and delete code, [SafeSaver])
 * and by KeePass 2 replaying its UI's own steps (`keepass2-read.sh --replay`) gives the
 * same file. Both start from the same input, saved by KeePass 2 first; both results are exported
 * by KeePass 2 as hashed plain XML and compared with times inside each side's own run reading
 * `NOW`, UUIDs new in the run numbered, UsageCount as a delta and absent standard strings equal to
 * empty. A difference is a failure unless the case lists it as [Known] with its reason, or it is
 * the new-object expiry time ([CompanionComparison.NEW_OBJECT_EXPIRY]) in its listed form; a listed
 * difference must show exactly as listed. Writes build/reports/keepass2/differential-editing.md.
 * Runs with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2DifferentialEditingTest {

    private val key = KeePass2Run.newKey()
    private val hash = { s: String -> KeePass2Report.mac(key, s.encodeToByteArray()) }
    private val hashEmpty = hash("")

    /**
     * One case. [kashPassHistory] is the history count KashPass's own reading of its save must show
     * for an entry (KeePass 2 trims again on load, so its export cannot show it). [precondition]
     * checks the input's export.
     */
    private class Case(
        val name: String,
        val input: VaultFile,
        val ops: List<CompanionOp>,
        val known: Known? = null,
        val kashPassHistory: Pair<String, Int>? = null,
        val precondition: ((KeePassXml) -> String?)? = null,
    )

    /** A listed difference: [why], and the diff lines it accounts for. */
    private class Known(val why: String, val lines: (String) -> Boolean)

    @Test
    fun `KashPass and the KeePass 2 UI steps give the same file`() {
        val started = System.nanoTime()
        val generated = KeePass2Run.keepass2ResavedFiles(ReplayInputs.all.map { it.file }).associateBy { it.name }
        fun gen(name: String) = generated.getValue(ReplayInputs.named(name).file.name)
        val fixtures = Fixtures.kdbx4Opening.map { Fixtures.file(it) }
        val timing = mutableListOf<String>()
        val inputExports = KeePass2Run.keepass2Xml(generated.values + fixtures, key)
        val inputXml = inputExports.mapValues { (name, e) -> (e as? KeePass2Run.Export.Opened)?.xml ?: fail("$name: $e") }
        timing += inputExports.map { (name, e) -> "KeePass 2 load and export of $name: ${(e as KeePass2Run.Export.Opened).millis} ms" }

        val cases = generatedCases(::gen) + fixtureCases(fixtures, inputXml)
        val problems = mutableListOf<String>()
        for (c in cases) c.precondition?.invoke(inputXml.getValue(c.input.name))?.let { problems += "${c.name}: precondition: $it" }

        // KashPass side: each case at its own time, saved and then exported by KeePass 2.
        class Saved(val file: VaultFile, val window: KeePassXml.Window)
        val kashPass = cases.associate { c ->
            val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
            c.name to Saved(CompanionRig.run(c.input, c.ops, now, "kashpass-${c.name}.kdbx"), KeePassXml.Window.of(now, now))
        }
        val kashPassXml = KeePass2Run.keepass2XmlOpened(kashPass.values.map { it.file }, key, timing)
        val t0 = System.nanoTime()
        val keePass = KeePass2Run.keepass2Replay(cases.map { KeePass2Run.ReplayCase(it.name, it.input, it.ops) } + customDataCase(inputXml), key)
        timing += "KeePass 2 replay: ${cases.size + 1} cases, ${(System.nanoTime() - t0) / 1_000_000_000} s"

        val outcomes = mutableListOf<String>()
        for (c in cases) {
            val input = inputXml.getValue(c.input.name)
            val theirs = keePass.getValue(c.name)
            val compared = CompanionComparison.compare(input, kashPassXml.getValue("kashpass-${c.name}.kdbx"), kashPass.getValue(c.name).window, theirs, hashEmpty)
            val expiry = compared.expiry
            val diff = compared.diff
            problems += compared.problems.map { "${c.name}: $it" }
            val known = c.known
            val label = "${c.name} (KeePass 2 set ${theirs.touched.size} time fields" + (if (expiry.isEmpty()) ")" else "; ${expiry.size} new-object expiry line(s))")
            when {
                known == null && diff.isEmpty() -> outcomes += "$label: same"
                known == null -> problems += "${c.name}: KashPass | KeePass 2 differ:\n    " + diff.take(12).joinToString("\n    ")
                diff.isEmpty() -> problems += "${c.name}: the listed difference (${known.why}) no longer shows"
                diff.all(known.lines) -> outcomes += "$label: known difference: ${known.why}"
                else -> problems += "${c.name}: differences beyond the listed one (${known.why}):\n    " + diff.filterNot(known.lines).take(12).joinToString("\n    ")
            }
            c.kashPassHistory?.let { (uuid, count) ->
                val document = CompanionRig.open(kashPass.getValue(c.name).file).document
                val items = DocumentIds.entries(document)[Uuids.parse(uuid).toString()]?.let { EntryParts.history(it).size }
                if (items != count) problems += "${c.name}: KashPass's own save has $items history items, not $count"
            }
        }
        checkCustomDataDelete(inputXml.getValue(Fixtures.PLUGIN_DATA), keePass.getValue(CUSTOM_DATA_CASE), problems, outcomes)

        val out = StringBuilder("# Differential editing\n\n")
        out.append("Each case is done by KashPass and by KeePassLib replaying the KeePass 2 UI's steps on the same input; ")
        out.append("KeePass 2 exports both results as hashed plain XML and they are compared.\n\n")
        out.append("Cases: ${cases.size + 1}. Run time: ${(System.nanoTime() - started) / 1_000_000_000} s.\n\n")
        out.append("Outcomes:\n\n").append(KeePass2Files.bullets(outcomes)).append("\n\n")
        out.append("Timing:\n\n").append(KeePass2Files.bullets(timing)).append("\n\n")
        out.append(if (problems.isEmpty()) "No problems.\n" else "Problems (${problems.size}):\n\n" + KeePass2Files.bullets(problems) + "\n")
        KeePass2Files.writeReport("differential-editing.md", out.toString())
        if (problems.isNotEmpty()) fail("${problems.size} problems:\n" + problems.take(30).joinToString("\n"))
    }

    private fun generatedCases(gen: (String) -> VaultFile): List<Case> {
        val base = gen("history-10-at-limit")
        val main = ReplayInputs.MAIN
        fun historyAt(n: Int): (KeePassXml) -> String? = { x ->
            val items = KeePassXml.history(x.entries().getValue(main)).size
            if (items != n) "Main has $items history items, not $n" else null
        }
        val templatesDefaults = Known("KeePass 2 skips the default user name for a new entry in the templates group; KashPass fills it") { line ->
            "/Entry{NEW1}/String{UserName}/" in line
        }
        fun add(group: String?) = CompanionOp.Add(group, CompanionOp.ADDED, "Added", "added-pass", "https://added.test", "Added\nnotes")
        return CompanionOp.STANDARD.map { field ->
            Case("edit $field at the item limit", base, listOf(CompanionOp.Edit(main, field, "Edited $field ü")), kashPassHistory = main to 10, precondition = historyAt(10))
        } + listOf(
            Case("edit without a change", base, listOf(CompanionOp.Edit(main, "Title", "main"))),
            Case("edit adding only whitespace", base, listOf(CompanionOp.Edit(main, "Title", "main "))),
            Case("edit an entry in the bin", base, listOf(CompanionOp.Edit(ReplayInputs.BINNED, "Title", "binned edited"))),
            Case("edit with HistoryMaxItems 0", gen("history-0"), listOf(CompanionOp.Edit(main, "Title", "zero")), kashPassHistory = main to 0, precondition = historyAt(0)),
            Case("edit with unlimited history", gen("history-unlimited"), listOf(CompanionOp.Edit(main, "Title", "more")), kashPassHistory = main to 13, precondition = historyAt(12)),
            Case("edit with HistoryMaxSize below one snapshot", gen("history-size-small"), listOf(CompanionOp.Edit(main, "Title", "small")), kashPassHistory = main to 0, precondition = historyAt(0)),
            Case("edit in a KDBX 4.1 file", gen("kdbx41"), listOf(CompanionOp.Edit(main, "Title", "four-one"))),
            Case("add to the top level", base, listOf(add(null))),
            Case("add to a folder-icon group", base, listOf(add(ReplayInputs.FOLDER))),
            Case("add to a mailbox-icon group", base, listOf(add(ReplayInputs.MAILBOX))),
            Case("add to a custom-icon group", base, listOf(add(ReplayInputs.CUSTOM))),
            Case("add without a default user name", gen("default-user-empty"), listOf(add(null))),
            Case("add into the templates group", base, listOf(add(ReplayInputs.TEMPLATES)), known = templatesDefaults),
            Case("add into a group inside the templates group", base, listOf(add(ReplayInputs.TEMPLATES_SUB)), known = templatesDefaults),
            Case("delete with the bin present", base, listOf(CompanionOp.Delete(ReplayInputs.OTHER))),
            Case("delete with the bin missing", gen("bin-missing"), listOf(CompanionOp.Delete(ReplayInputs.OTHER))),
            Case("delete with the bin dangling", gen("bin-dangling"), listOf(CompanionOp.Delete(ReplayInputs.OTHER))),
            Case("delete with the bin off", gen("bin-off"), listOf(CompanionOp.Delete(ReplayInputs.OTHER))),
            Case("delete inside the bin", base, listOf(CompanionOp.Delete(ReplayInputs.BINNED))),
            Case("delete in a KDBX 4.1 file", gen("kdbx41"), listOf(CompanionOp.Delete(ReplayInputs.OTHER))),
        )
    }

    // One edit, one add and one delete on every fixture, on the first eligible entry; on the
    // plugin-data fixture also the edits that trim history by count and by size, compared with the
    // history in full.
    private fun fixtureCases(fixtures: List<VaultFile>, inputXml: Map<String, KeePassXml>): List<Case> = fixtures.flatMap { f ->
        val xml = inputXml.getValue(f.name)
        val trimTitles = listOf(KeePass2XmlExportDiffTest.THREE_BACKUPS, KeePass2XmlExportDiffTest.SIZE_LIMIT)
        val target = xml.eligibleEntries(trimTitles.map(hash).toSet()).keys.firstOrNull() ?: fail("${f.name}: no entry to edit")
        listOf(
            Case("${f.name} edit", f, listOf(CompanionOp.Edit(target, "Title", "Edited by both"))),
            Case("${f.name} add", f, listOf(CompanionOp.Add(null, CompanionOp.ADDED, "Added by both", "pass", "", ""))),
            Case("${f.name} delete", f, listOf(CompanionOp.Delete(target))),
        ) + listOfNotNull(
            xml.entryByTitle(hash(KeePass2XmlExportDiffTest.THREE_BACKUPS))?.let { e ->
                Case("${f.name} edit trims history by count", f, listOf(CompanionOp.Edit(e, "Password", "three-4")), kashPassHistory = e to 3)
            },
            xml.entryByTitle(hash(KeePass2XmlExportDiffTest.SIZE_LIMIT))?.let { e ->
                Case(
                    "${f.name} edit trims history by size", f, listOf(CompanionOp.Edit(e, "Password", "size-2")), kashPassHistory = e to 1,
                    precondition = { x -> if (KeePassXml.history(x.entries().getValue(e)).size != 1) "the entry does not hold one history item" else null },
                )
            },
        )
    }

    // KeePass 2's UI deletes a plugin data item in the entry dialog; KashPass has no such action,
    // so only the replay runs and is checked against the entry dialog's save steps.
    private fun customDataCase(inputXml: Map<String, KeePassXml>): KeePass2Run.ReplayCase {
        val f = Fixtures.file(Fixtures.named(Fixtures.PLUGIN_DATA))
        return KeePass2Run.ReplayCase(CUSTOM_DATA_CASE, f, listOf(CompanionOp.DeleteCustomData(threeBackups(inputXml.getValue(f.name)), "PluginA_Entry")))
    }

    private fun threeBackups(xml: KeePassXml): String = xml.entryByTitle(hash(KeePass2XmlExportDiffTest.THREE_BACKUPS)) ?: fail("no entry Three backups")

    // The SaveEntry steps change exactly this in the entry, and nothing elsewhere: the item is
    // gone, the history moves up one place after the count trim and ends with the entry as it was
    // (item included), LastModificationTime and LastAccessTime fall in the run and UsageCount goes
    // up by one.
    private fun checkCustomDataDelete(input: KeePassXml, replayed: KeePass2Run.Replayed, problems: MutableList<String>, outcomes: MutableList<String>) {
        val uuid = threeBackups(input)
        val normal = KeePassXml.Normal(window = replayed.window, empty = hashEmpty)
        val before = input.flat(normal)
        val after = replayed.xml.flat(normal)
        val path = before.keys.first { it.endsWith("/Entry{$uuid}/UUID") }.removeSuffix("/UUID")
        val history = "$path/History/Entry#"
        val own = before.filterKeys { it.startsWith("$path/") && !it.startsWith("$path/History") }
        val expected = HashMap(before.filterKeys { !it.startsWith(history) })
        expected.remove("$path/CustomData/Item{PluginA_Entry}/Key")
        expected.remove("$path/CustomData/Item{PluginA_Entry}/Value")
        expected["$path/Times/LastModificationTime"] = "NOW"
        expected["$path/Times/LastAccessTime"] = "NOW"
        expected["$path/Times/UsageCount"] = ((before.getValue("$path/Times/UsageCount").toLong()) + 1).toString()
        val items = before.keys.filter { it.startsWith(history) }.map { it.removePrefix(history).substringBefore('/').toInt() }.toSortedSet()
        for ((k, v) in before) if (k.startsWith(history)) {
            val i = k.removePrefix(history).substringBefore('/').toInt()
            if (i > 0) expected["$history${i - 1}/" + k.removePrefix("$history$i/")] = v
        }
        for ((k, v) in own) expected["$history${items.size - 1}/" + k.removePrefix("$path/")] = v
        val diff = KeePassXml.diff(expected, after)
        if (diff.isEmpty()) outcomes += "$CUSTOM_DATA_CASE: as the SaveEntry steps say"
        else problems += "$CUSTOM_DATA_CASE: differs from the SaveEntry steps:\n    " + diff.take(12).joinToString("\n    ")
    }

    internal companion object {
        const val CUSTOM_DATA_CASE = "plugin data item deleted in the entry dialog"
    }
}
