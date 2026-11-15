package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.EntryParts
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.VaultFile

/**
 * KeePass 2's own model of a KashPass save equals its model of the opened file except the change
 * the user made. Every fixture that opens is saved by KashPass ([CompanionRig]) with no edit and
 * with each edit kind; KeePass 2 exports the input and each save as hashed plain XML
 * ([KeePass2Run.keepass2Xml]), and the save's export must equal [ExpectedChange] applied to the
 * input's. Times, Meta settings, DeletedObjects, custom data, custom icons, auto-type, colours and
 * tags are compared along with the fields.
 *
 * KeePass 2's export cannot show what its own load and save rewrite: it resets MemoryProtection on
 * load and protects the standard fields by it, rebuilds the attachment pool from the tree, trims
 * history on load and turns CR LF into LF in unprotected text. So KashPass's own reading of each
 * save is checked too: Meta/MemoryProtection as opened, each kept entry's password protection as
 * opened, as many pool items as KeePass 2 writes, and the history count after a trim. Writes
 * build/reports/keepass2/xml-export-diff.md. Runs with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2XmlExportDiffTest {

    private val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
    private val key = KeePass2Run.newKey()
    private val change = ExpectedChange(key, now)
    private val trimEntries = setOf(change.hash(THREE_BACKUPS), change.hash(SIZE_LIMIT))

    /** What the cases act on in one input, chosen from KeePass 2's export of it. */
    private class Targets(val xml: KeePassXml, val a: String?, val b: String?, val addGroup: String?, val binEntry: String?, val three: String?, val size: String?)

    /**
     * One case: its [ops] for the input's targets, or null when it does not apply there;
     * [precondition] on the input, null when it holds. [sizeTrim] names the entry whose history a
     * HistoryMaxSize trim changes; [kashPassHistory] the history count KashPass's own reading of
     * its save must show for an entry.
     */
    private class Case(
        val name: String,
        val ops: (Targets) -> List<CompanionOp>?,
        val precondition: (Targets) -> String? = { null },
        val sizeTrim: (Targets) -> String? = { null },
        val kashPassHistory: (Targets) -> Pair<String, Int>? = { null },
    )

    private fun maxItems(t: Targets) = t.xml.meta().child("HistoryMaxItems")?.text()?.trim()?.toIntOrNull() ?: 10

    private fun historyOf(t: Targets, uuid: String) = KeePassXml.history(t.xml.entries().getValue(uuid)).size

    private val cases: List<Case> = listOf(
        Case("no edit", { listOf(CompanionOp.NoEdit) }),
    ) + CompanionOp.STANDARD.map { field ->
        // The target keeps its history below the limit: the edit adds one item and trims none.
        Case(
            "edit $field",
            { t -> t.a?.let { listOf(CompanionOp.Edit(it, field, "Edited $field by KashPass ü")) } },
            precondition = { t -> if (historyOf(t, t.a!!) + 1 > maxItems(t) && maxItems(t) >= 0) "the target's history reaches the limit" else null },
        )
    } + listOf(
        Case("add to the top level", { listOf(CompanionOp.Add(null, CompanionOp.ADDED, "Added by KashPass", "added-pass", "https://added.test", "Added\nnotes")) }),
        Case("add into a group", { t -> t.addGroup?.let { listOf(CompanionOp.Add(it, CompanionOp.ADDED, "Added in a group", "group-pass", "", "")) } }),
        Case("delete to a missing bin", { t -> t.a?.takeIf { t.xml.bin() == null }?.let { listOf(CompanionOp.Delete(it)) } }),
        Case("delete A to the bin, then delete B", { t -> if (t.a != null && t.b != null) listOf(CompanionOp.Delete(t.a), CompanionOp.Delete(t.b)) else null }),
        Case("delete A to the bin, then delete A again", { t -> t.a?.let { listOf(CompanionOp.Delete(it), CompanionOp.Delete(it)) } }),
        Case("delete the entry already in the bin", { t -> t.binEntry?.let { listOf(CompanionOp.Delete(it)) } }),
        Case(
            "edit trims history by count",
            { t -> t.three?.let { listOf(CompanionOp.Edit(it, "Password", "three-4")) } },
            precondition = { t -> if (historyOf(t, t.three!!) != maxItems(t)) "the entry is not at the item limit" else null },
            kashPassHistory = { t -> t.three?.let { it to 3 } },
        ),
        Case(
            "edit trims history by size",
            { t -> t.size?.let { listOf(CompanionOp.Edit(it, "Password", "size-2")) } },
            precondition = { t -> if (historyOf(t, t.size!!) != 1) "the entry does not hold one history item" else null },
            sizeTrim = { t -> t.size },
            kashPassHistory = { t -> t.size?.let { it to 1 } },
        ),
    )

    @Test
    fun `KeePass 2's export of every KashPass save differs from the input's only by the edit`() {
        val started = System.nanoTime()
        val inputs = Fixtures.kdbx4Opening.map { Fixtures.file(it) }
        val batchTimes = mutableListOf<String>()
        val inputXml = KeePass2Run.keepass2XmlOpened(inputs, key, batchTimes)
        val problems = mutableListOf<String>()
        val notApplicable = mutableListOf<String>()
        val targetLines = mutableListOf<String>()

        class Run(val input: VaultFile, val case: Case, val targets: Targets, val ops: List<CompanionOp>, val saved: VaultFile)
        val runs = mutableListOf<Run>()
        val opened = HashMap<String, VaultDocument>()
        for (f in inputs) {
            val t = targets(inputXml.getValue(f.name))
            opened[f.name] = CompanionRig.open(f).document
            targetLines += "${f.name}: A=${t.a} B=${t.b} group=${t.addGroup} bin=${if (t.xml.bin() != null) "present" else "missing"} binEntry=${t.binEntry}"
            for (c in cases) {
                val ops = c.ops(t)
                if (ops == null) {
                    notApplicable += "${f.name}: ${c.name}"
                    continue
                }
                c.precondition(t)?.let { problems += "${f.name}: ${c.name}: precondition: $it" }
                runs += Run(f, c, t, ops, CompanionRig.run(f, ops, now, "${runs.size}-${f.name}"))
            }
        }

        val exports = KeePass2Run.keepass2XmlOpened(runs.map { it.saved }, key, batchTimes)
        val hashEmpty = change.hash("")
        for (r in runs) {
            val what = "${r.input.name}: ${r.case.name}"
            val input = r.targets.xml
            val export = exports.getValue(r.saved.name)
            val normal = KeePassXml.Normal(input = input, empty = hashEmpty)
            var expected = change.apply(input, r.ops).flat(normal)
            var actual = export.flat(normal)
            r.case.sizeTrim(r.targets)?.let { uuid ->
                expected = expected.filterKeys { "/Entry{$uuid}/History" !in it }
                actual = actual.filterKeys { "/Entry{$uuid}/History" !in it }
            }
            val diff = KeePassXml.diff(expected, actual)
            if (diff.isNotEmpty()) problems += "$what (${r.ops.map { it.line.substringBefore('\t') }}):\n    " + diff.take(12).joinToString("\n    ")
            problems += kashPassReading(what, opened.getValue(r.input.name), CompanionRig.open(r.saved).document, export, r.case.kashPassHistory(r.targets))
        }
        val out = StringBuilder("# XML export diff\n\n")
        out.append("Each fixture is saved by KashPass with no edit and with each edit kind; KeePass 2 exports the input and each save ")
        out.append("as hashed plain XML, and each save's export is compared with the expected change applied to the input's.\n\n")
        out.append("Saves: ${runs.size}. Run time: ${(System.nanoTime() - started) / 1_000_000_000} s.\n\n")
        out.append("Cases: ").append(cases.joinToString("; ") { it.name }).append("\n\n")
        out.append("Targets:\n\n").append(KeePass2Files.bullets(targetLines)).append("\n\n")
        out.append("Not applicable (${notApplicable.size}):\n\n").append(KeePass2Files.bullets(notApplicable)).append("\n\n")
        out.append("KeePass 2 batches:\n\n").append(KeePass2Files.bullets(batchTimes)).append("\n\n")
        out.append(if (problems.isEmpty()) "No differences.\n" else "Differences (${problems.size}):\n\n" + KeePass2Files.bullets(problems) + "\n")
        KeePass2Files.writeReport("xml-export-diff.md", out.toString())
        if (problems.isNotEmpty()) fail("${problems.size} differences:\n" + problems.take(30).joinToString("\n"))
    }

    // Checks KashPass's own reading of its save against what the export cannot show.
    private fun kashPassReading(what: String, before: VaultDocument, after: VaultDocument, export: KeePassXml, history: Pair<String, Int>?): List<String> {
        val found = mutableListOf<String>()
        fun protection(d: VaultDocument) = d.xml.root.child("Meta")?.child("MemoryProtection")?.elements().orEmpty().map { it.name to it.text().trim() }
        if (protection(before) != protection(after)) found += "$what: Meta/MemoryProtection changed: ${protection(before)} -> ${protection(after)}"
        fun passwordProtected(d: VaultDocument): Map<String, Boolean> = DocumentIds.entries(d).mapValues { (_, e) ->
            val value = e.children("String").lastOrNull { it.child("Key")?.text() == "Password" }?.children("Value")?.lastOrNull()
            value != null && value in d.protectedValues
        }
        val was = passwordProtected(before)
        for ((id, now) in passwordProtected(after)) {
            val expected = was[id] ?: after.meta.protects("Password")
            if (now != expected) found += "$what: entry $id password protected=$now, expected $expected"
        }
        val pool = export.meta().child("Binaries")?.children("Binary").orEmpty().size
        if (after.attachments.size != pool) found += "$what: KashPass's save holds ${after.attachments.size} attachments, KeePass 2 writes $pool"
        history?.let { (uuid, count) ->
            val items = DocumentIds.entries(after)[Uuids.parse(uuid).toString()]?.let { EntryParts.history(it).size }
            if (items != count) found += "$what: KashPass's own save has $items history items, not $count"
        }
        return found
    }

    // Edit target A: the first eligible entry with history, else the first eligible entry; B the
    // next eligible entry. The add group is the first group below the top level outside the bin
    // and the templates group.
    private fun targets(xml: KeePassXml): Targets {
        val eligible = xml.eligibleEntries(trimEntries)
        val a = eligible.entries.firstOrNull { KeePassXml.history(it.value).isNotEmpty() }?.key ?: eligible.keys.firstOrNull()
        val b = eligible.keys.firstOrNull { it != a }
        val excluded = listOfNotNull(xml.bin(), xml.templates())
        val addGroup = xml.groups().values.firstOrNull { g -> g !== xml.rootGroup() && excluded.none { KeePassXml.inside(g, it) } }?.let(KeePassXml::uuid)
        val binEntry = xml.bin()?.children("Entry")?.firstOrNull()?.let(KeePassXml::uuid)
        return Targets(xml, a, b, addGroup, binEntry, xml.entryByTitle(change.hash(THREE_BACKUPS)), xml.entryByTitle(change.hash(SIZE_LIMIT)))
    }

    internal companion object {
        /** The plugin-data fixture's entries at the item limit and at the size limit. */
        const val THREE_BACKUPS = "Three backups"
        const val SIZE_LIMIT = "Size limit"
    }
}
