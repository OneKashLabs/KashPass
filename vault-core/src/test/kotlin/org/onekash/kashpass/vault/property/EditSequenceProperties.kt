package org.onekash.kashpass.vault.property

import io.kotest.property.Arb
import io.kotest.property.arbitrary.arbitrary
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.checkAll
import java.time.Instant
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.EntryParts
import org.onekash.kashpass.vault.doc.EntryView
import org.onekash.kashpass.vault.doc.GroupView
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.edit.DeleteKind
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDelete
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.edit.HistoryTrim
import org.onekash.kashpass.vault.index.documentOf
import org.onekash.kashpass.vault.keepass2.DocumentReport
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.VaultModel
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * Random sequences of add, edit, delete and save-and-reopen leave the vault matching a model: the
 * entries in and outside the recycle bin, each entry's group and five standard fields, and each
 * edited entry's history trimmed by HistoryMaxItems, then HistoryMaxSize, oldest
 * LastModificationTime first. Entry and group UUIDs stay unique, a delete moves the entry to the
 * recycle bin (created when missing) while the bin is enabled and the entry is outside it, and
 * deletes it for good otherwise, with PreviousParentGroup only in a KDBX 4.1 save, and every save
 * reopens with the same content in KashPass and in the test toolkit.
 */
class EditSequenceProperties {

    /** One user action. Picks are indexes into the current choices, taken modulo their count. */
    sealed interface Command {
        data class Add(val group: Int, val values: List<String>) : Command
        data object AddToRecycleBin : Command
        data class Edit(val entry: Int, val changed: Int, val values: List<String>) : Command
        data class Delete(val entry: Int) : Command
        data object SaveAndReopen : Command
    }

    private val command: Arb<Command> = arbitrary { rs ->
        val r = rs.random
        when (r.nextInt(10)) {
            0, 1 -> Command.Add(r.nextInt(100), values(r))
            2 -> Command.AddToRecycleBin
            3, 4, 5, 6 -> Command.Edit(r.nextInt(100), r.nextInt(32), values(r))
            7, 8 -> Command.Delete(r.nextInt(100))
            else -> Command.SaveAndReopen
        }
    }

    // Five field values from an XML-safe alphabet, never whitespace alone, so they read back as
    // set.
    private fun values(r: Random) = List(5) { List(r.nextInt(0, 12)) { "abcdefgh &<é漢\t".random(r) }.joinToString("").let { if (it.isNotBlank()) it else "v$it" } }

    // How often each rule was reached, so a pass shows the sequences exercised it.
    private val seen = mutableMapOf<String, Int>()

    private fun saw(case: String) {
        seen.merge(case, 1, Int::plus)
    }

    @Test
    fun `random edit sequences keep the vault matching the model`() = runBlocking<Unit> {
        checkAll(PropertyRuns.config(60), Generators.doc, Arb.list(command, 1..30), Arb.int(0..3)) { doc, commands, sizeChoice ->
            run(start(doc, sizeChoice), commands)
        }
        val cases = listOf(
            "add", "refused in bin", "unchanged", "changed", "trimmed by count", "trimmed by size", "trimmed out of order",
            "to bin", "bin created", "permanent", "previous parent", "saved",
        )
        assertTrue(cases.all { (seen[it] ?: 0) > 0 }, "a rule was never reached: $seen")
    }

    // Opens [doc] with a HistoryMaxSize that is unlimited, the default (6 MiB), or as small as
    // the starting history allows, so edits trim by size too.
    private fun start(doc: VaultModel.Doc, sizeChoice: Int): VaultDocument {
        val opened = documentOf(VaultModel.write(doc, aesRounds = 1UL))
        if (sizeChoice != 0) return opened
        val largest = DocumentIds.entries(opened).values.maxOfOrNull { e -> EntryParts.history(e).sumOf { HistoryTrim.size(opened, it) } } ?: 0L
        return documentOf(VaultModel.write(doc.copy(historyMaxSize = maxOf(largest, 1_500L)), aesRounds = 1UL))
    }

    private class Snapshot(val fields: List<String>, val time: Instant?, val size: Long)

    private class Model(var fields: List<String>, var group: String, var modified: Instant?, val history: MutableList<Snapshot>, var edited: Boolean = false)

    private fun run(initial: VaultDocument, commands: List<Command>) {
        var document = initial
        val model = LinkedHashMap<String, Model>()
        for ((_, e) in DocumentIds.entries(document)) {
            model[uuid(e)] = Model(fields(document, e), uuid(e.parent!!), EntryView(e, document).modified, EntryParts.history(e).map { snapshotOf(document, it) }.toMutableList())
        }
        val deleted = mutableSetOf<String>()
        var clock = Instant.parse("2030-01-01T00:00:00Z")
        for ((step, cmd) in commands.withIndex()) {
            clock = clock.plusSeconds(60)
            val at = "step $step $cmd"
            when (cmd) {
                is Command.Add -> {
                    val choices = EntryEdits.groups(document)
                    // The model's bin: the group Meta names, while the bin is enabled.
                    val bin = binUuid(document).takeIf { document.meta.recycleBinEnabled }
                    for (c in choices) {
                        val ancestors = generateSequence(DocumentIds.groups(document).getValue(c.id)) { it.parent }.takeWhile { it.name == "Group" }
                        assertTrue(ancestors.none { uuid(it) == bin }, "$at: a choice is in the recycle bin")
                    }
                    val choice = choices[cmd.group % choices.size]
                    val added = EntryEdits.add(document, choice.id, draft(cmd.values), clock)
                    document = added.document
                    val e = DocumentIds.entries(document).getValue(added.entryId)
                    model[uuid(e)] = Model(cmd.values, uuid(DocumentIds.groups(document).getValue(choice.id)), clock, mutableListOf())
                    saw("add")
                }
                Command.AddToRecycleBin -> {
                    val binId = binUuid(document).takeIf { document.meta.recycleBinEnabled } ?: continue
                    val bin = DocumentIds.groups(document).entries.first { (_, g) -> uuid(g) == binId }
                    assertFailsWith<IllegalArgumentException>(at) { EntryEdits.add(document, bin.key, draft(List(5) { "x" }), clock) }
                    saw("refused in bin")
                }
                is Command.Edit -> {
                    val ids = DocumentIds.entries(document).entries.toList()
                    if (ids.isEmpty()) continue
                    val (id, element) = ids[cmd.entry % ids.size]
                    val m = model.getValue(uuid(element))
                    val wanted = m.fields.mapIndexed { i, v -> if (cmd.changed and (1 shl i) != 0) cmd.values[i] else v }
                    // The snapshot's size by KashPass's own estimate (HistoryTrim.size, which
                    // counts 8 bytes per history item plus each item's size), taken as given here.
                    val snapshotSize = HistoryTrim.size(document, element) - EntryParts.history(element).let { h -> 8L * h.size + h.sumOf { HistoryTrim.size(document, it) } }
                    when (val result = EntryEdits.edit(document, id, draft(wanted), clock)) {
                        EditResult.Unchanged -> assertEquals(m.fields, wanted, "$at: Unchanged though a field differs").also { saw("unchanged") }
                        EditResult.EntryNotFound -> fail("$at: entry not found")
                        is EditResult.Changed -> {
                            assertTrue(m.fields != wanted, "$at: Changed though no field differs")
                            m.history += Snapshot(m.fields, m.modified, snapshotSize)
                            trim(m.history, document.meta.historyMaxItems, document.meta.historyMaxSize)
                            saw("changed")
                            m.fields = wanted
                            m.modified = clock
                            m.edited = true
                            document = result.document
                        }
                    }
                }
                is Command.Delete -> {
                    val ids = DocumentIds.entries(document).entries.toList()
                    if (ids.isEmpty()) continue
                    val (id, element) = ids[cmd.entry % ids.size]
                    val key = uuid(element)
                    val wasIn = uuid(element.parent!!)
                    val binBefore = binUuid(document)
                    val expected = if (document.meta.recycleBinEnabled && !EntryEdits.inRecycleBin(document, element.parent!!)) DeleteKind.TO_RECYCLE_BIN else DeleteKind.PERMANENT
                    val result = EntryDelete.delete(document, id, clock) ?: fail("$at: unknown entry")
                    assertEquals(expected, result.kind, at)
                    document = result.document
                    saw(if (expected == DeleteKind.PERMANENT) "permanent" else "to bin")
                    if (expected == DeleteKind.PERMANENT) {
                        model.remove(key)
                        deleted += key
                    } else {
                        val moved = DocumentIds.entries(document).values.single { uuid(it) == key }
                        model.getValue(key).group = binUuid(document) ?: fail("$at: no recycle bin after a delete to it")
                        if (binBefore == null) saw("bin created")
                        val previous = moved.child("PreviousParentGroup")?.text()
                        if (document.savedMinor() >= 1) assertEquals(wasIn, previous, "$at: PreviousParentGroup in a KDBX 4.1 save").also { saw("previous parent") }
                        else assertEquals(null, previous, "$at: PreviousParentGroup in a KDBX 4.0 save")
                    }
                }
                Command.SaveAndReopen -> {
                    val key = ByteArray(32) { it.toByte() }
                    val bytes = VaultXmlCodec.encodeBytes(document)
                    KdbxToolkit.open(bytes, KdbxToolkit.Key(TestVaults.PASSWORD))
                    val reopened = documentOf(bytes)
                    assertEquals(DocumentReport.of(document, key), DocumentReport.of(reopened, key), "$at: the save reads back other content")
                    document = reopened
                    saw("saved")
                }
            }
            check(document, model, deleted, at)
        }
    }

    // Trims by count, then by size, removing the oldest LastModificationTime (the first in order
    // on a tie) each time.
    private fun trim(history: MutableList<Snapshot>, maxItems: Int, maxSize: Long) {
        fun removeOldest() = history.indices.minBy { history[it].time ?: Instant.MIN }.let { i ->
            if (i != 0) saw("trimmed out of order")
            history.removeAt(i)
        }
        if (maxItems >= 0) while (history.size > maxItems) removeOldest().also { saw("trimmed by count") }
        if (maxSize >= 0) while (history.isNotEmpty() && history.sumOf { it.size } > maxSize) removeOldest().also { saw("trimmed by size") }
    }

    private fun check(document: VaultDocument, model: Map<String, Model>, deleted: Set<String>, at: String) {
        val entries = DocumentIds.entries(document).values.toList()
        assertEquals(entries.size, entries.map { uuid(it) }.toSet().size, "$at: entry UUIDs repeat")
        val groups = DocumentIds.groups(document).values.toList()
        assertEquals(groups.size, groups.map { uuid(it) }.toSet().size, "$at: group UUIDs repeat")
        assertEquals(model.keys, entries.map { uuid(it) }.toSet(), "$at: the entries differ from the model")
        val deletedObjects = document.rootGroup.element.parent!!.child("DeletedObjects")?.children("DeletedObject").orEmpty().map { it.child("UUID")?.text() }.toSet()
        for (d in deleted) assertTrue(d in deletedObjects, "$at: no DeletedObject for $d")
        for (e in entries) {
            val m = model.getValue(uuid(e))
            assertEquals(m.fields, fields(document, e), "$at: fields of ${uuid(e)}")
            assertEquals(m.group, uuid(e.parent!!), "$at: group of ${uuid(e)}")
            if (m.edited) {
                val actual = EntryParts.history(e).map { snapshotOf(document, it) }
                assertEquals(m.history.map { it.fields to it.time }, actual.map { it.fields to it.time }, "$at: history of ${uuid(e)}")
            }
        }
    }

    private fun snapshotOf(document: VaultDocument, e: XmlElement) = Snapshot(fields(document, e), EntryView(e, document).modified, HistoryTrim.size(document, e))

    private fun fields(document: VaultDocument, e: XmlElement): List<String> = Generators.STANDARD.map { TextProperties.fieldText(document, e, it) }

    // The editor builds the password from the characters typed (ProtectedText.of(CharArray)).
    private fun draft(v: List<String>) = EntryDraft(v[0], v[1], ProtectedText.of(v[2].toCharArray()), v[3], v[4])

    // The recycle bin group's UUID as stored, or null when Meta names no group the vault holds.
    private fun binUuid(document: VaultDocument): String? =
        document.meta.recycleBinUuid?.let { u -> DocumentIds.groups(document).values.firstOrNull { GroupView(it, document).uuid == u }?.let(::uuid) }

    private fun uuid(e: XmlElement): String = e.child("UUID")?.text() ?: fail("no UUID")
}
