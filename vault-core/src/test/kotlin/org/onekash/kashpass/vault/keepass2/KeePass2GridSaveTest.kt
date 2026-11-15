package org.onekash.kashpass.vault.keepass2

import java.io.File
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.fail
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.VaultIndex
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage

/**
 * Every KDBX 4 file of the reader grid ([GridWriters]), every KDBX 4 fixture and every corpus
 * case that opens editable is opened through [VaultOpener], edited (an entry added, a title
 * changed), saved with [SafeSaver] and KashPass's own encoder, reopened, edited and saved again.
 * KeePass 2 reads each save with the content of the edited document ([DocumentReport.of]),
 * and KashPass reopens each save with the edit.
 *
 * KeePass 2 refusing a save fails the test. A content difference KeePass 2 also reports between
 * the opened file and KashPass's reading of it (such as the history it trims on load) is listed,
 * not a failure. Writes build/reports/keepass2/grid-save.md. Runs with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2GridSaveTest {

    private val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)

    /** One file to save, with the folder or set it comes from. */
    private class Source(val set: String, val file: VaultFile)

    /**
     * One save of [source]: the [file] written, the report of the document it was saved from and
     * the [title] the save gave the added entry.
     */
    private class Save(val source: VaultFile, val file: VaultFile, val expected: KeePass2Report, val title: String)

    /** What the run found, for the report. */
    private class Outcome {
        val opened = sortedMapOf<String, Int>()
        val saved = sortedMapOf<String, Int>()
        val resaved = sortedMapOf<String, Int>()
        val notOpened = mutableListOf<String>()
        val readOnly = mutableListOf<String>()
        val inherited = mutableListOf<String>()
        val problems = mutableListOf<String>()
    }

    @Test
    fun `every grid file, fixture and editable corpus case saves twice and opens in KeePass 2`() {
        val sources = mutableListOf<Source>()
        GridWriters.written(GRID, "the KeePass 2 grid script").forEach { sources += Source(GRID, it) }
        Fixtures.kdbx4Opening.forEach { sources += Source("fixture", Fixtures.file(it)) }
        // KeePass 2 gives an entry with an empty UUID a new random one on every read, so no two
        // reads of the same content compare equal.
        val randomOnRead = setOf("xml-uuid-empty")
        Corpus.all.filter { it.spec == Spec.OPENS && it.name !in randomOnRead }.forEach { sources += Source("corpus", it.file()) }
        val key = KeePass2Run.newKey()
        val outcome = Outcome()
        // In chunks, so no more than a few dozen 2 MiB vaults and their saves are in memory at
        // once.
        for (chunk in sources.chunked(48)) check(chunk, key, outcome)
        report(outcome)
        if (outcome.problems.isNotEmpty()) fail("${outcome.problems.size} problems:\n" + outcome.problems.take(40).joinToString("\n"))
    }

    private fun check(chunk: List<Source>, key: ByteArray, outcome: Outcome) {
        val sources = chunk.map { if (it.set == GRID) Source(it.set, GridWriters.load(it.set, it.file)) else it }
        val saves = sources.flatMap { save(it, key, outcome) }
        val originals = sources.map { it.file }.filter { f -> saves.any { it.source === f } }
        val kp2 = KeePass2Run.keepass2(originals + saves.map { it.file }, key)
        for (s in saves) {
            val name = s.file.name
            val theirs = kp2.getValue(name)
            if (theirs !is KeePass2Report.Opened) {
                outcome.problems += "$name: KeePass 2 refuses the save: $theirs"
            } else {
                // A difference KeePass 2 makes on the opened file too is how it reads the content,
                // not what the save wrote.
                val opened = kp2.getValue(s.source.name)
                val before = if (opened is KeePass2Report.Opened) KeePass2Report.diff(DocumentReport.of(s.source, key), opened).toSet() else emptySet()
                val (known, unexplained) = KeePass2Report.diff(s.expected, theirs).partition { it in before }
                if (unexplained.isNotEmpty()) outcome.problems += "$name: KeePass 2 reads other content than was saved:\n  " + unexplained.take(8).joinToString("\n  ")
                if (known.isNotEmpty()) outcome.inherited += "$name: KeePass 2 reads the opened file the same way: " + known.take(3).joinToString("; ")
            }
        }
    }

    // Opens [source], edits and saves it, reopens the save, edits and saves it again; returns
    // both saves, or none when the file does not open editable.
    private fun save(source: Source, key: ByteArray, outcome: Outcome): List<Save> = runBlocking {
        val f = source.file
        val storage = FakeVaultStorage().apply { put(LOCATION, f.bytes) }
        val state = FakeVaultStateStore()
        val opener = VaultOpener.create(storage, state, Dispatchers.IO)
        val writers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val saver = SafeSaver.create(storage, FakeBackupStore { now }, FakeSaveMarkerStore(), state, Dispatchers.IO, writers)
        suspend fun open(): OpenResult = opener.open(LOCATION, (TestFiles.password(f.mode) ?: "").toCharArray(), keyFile = f.keyFile?.copyOf())
        try {
            val opened = open()
            if (opened !is OpenResult.Unlocked) {
                outcome.notOpened += "${f.name}: $opened"
                if (source.set != "corpus") outcome.problems += "${f.name}: the opener gives $opened"
                return@runBlocking emptyList()
            }
            outcome.opened.merge(source.set, 1, Int::plus)
            val vault = opened.session.opened
            opened.session.release()
            if (vault.saveability != Saveability.Saveable) {
                outcome.readOnly += "${f.name}: ${vault.saveability}"
                if (source.set != "corpus") outcome.problems += "${f.name}: opens read-only: ${vault.saveability}"
                return@runBlocking emptyList()
            }
            val first = firstEdit(vault.document)
            val saved = saver.save(LOCATION, vault.withDocument(first))
            if (saved !is SaveResult.Saved) {
                outcome.problems += "${f.name}: the first save gives $saved"
                return@runBlocking emptyList()
            }
            outcome.saved.merge(source.set, 1, Int::plus)
            val firstSave = Save(f, f.copy("save1-", storage.bytes(LOCATION)!!), DocumentReport.of(first, key), TITLE)
            val reopened = open()
            if (reopened !is OpenResult.Unlocked) {
                outcome.problems += "${f.name}: KashPass does not reopen its save: $reopened"
                return@runBlocking listOf(firstSave)
            }
            val back = reopened.session.opened
            reopened.session.release()
            val drift = KeePass2Report.diff(firstSave.expected, DocumentReport.of(back.document, key))
            if (drift.isNotEmpty()) outcome.problems += "${f.name}: KashPass reopens its save with other content:\n  " + drift.take(8).joinToString("\n  ")
            val second = secondEdit(back.document) ?: run {
                outcome.problems += "${f.name}: the reopened save has no entry titled $TITLE"
                return@runBlocking listOf(firstSave)
            }
            val resaved = saver.save(LOCATION, back.withDocument(second))
            if (resaved !is SaveResult.Saved) {
                outcome.problems += "${f.name}: the second save gives $resaved"
                return@runBlocking listOf(firstSave)
            }
            outcome.resaved.merge(source.set, 1, Int::plus)
            val secondSave = Save(f, f.copy("save2-", storage.bytes(LOCATION)!!), DocumentReport.of(second, key), TITLE_AGAIN)
            when (val again = open()) {
                is OpenResult.Unlocked -> {
                    val document = again.session.opened.document
                    again.session.release()
                    val diff = KeePass2Report.diff(secondSave.expected, DocumentReport.of(document, key))
                    if (diff.isNotEmpty()) outcome.problems += "${f.name}: KashPass reopens its second save with other content:\n  " + diff.take(8).joinToString("\n  ")
                }
                else -> outcome.problems += "${f.name}: KashPass does not reopen its second save: $again"
            }
            listOf(firstSave, secondSave)
        } finally {
            writers.cancel()
        }
    }

    // Adds an entry and changes the title of the first other entry, when there is one.
    private fun firstEdit(document: VaultDocument): VaultDocument {
        var edited = EntryEdits.add(document, null, EntryDraft(TITLE, "user", ProtectedText.of("pass"), "", "Line one\nünïcödé"), now).document
        val row = VaultIndex.from(edited).rows(Chip.All, "").firstOrNull { it.title != TITLE } ?: return edited
        val draft = EntryEdits.draftOf(edited, row.id) ?: return edited
        val result = EntryEdits.edit(edited, row.id, EntryDraft(draft.title + " edited", draft.userName, draft.password, draft.url, draft.notes), now)
        if (result is EditResult.Changed) edited = result.document
        return edited
    }

    // Renames the entry the first edit added; null when the document has none.
    private fun secondEdit(document: VaultDocument): VaultDocument? {
        val row = VaultIndex.from(document).rows(Chip.All, "").firstOrNull { it.title == TITLE } ?: return null
        val draft = EntryEdits.draftOf(document, row.id) ?: return null
        val result = EntryEdits.edit(document, row.id, EntryDraft(TITLE_AGAIN, draft.userName, ProtectedText.of("pass again"), draft.url, draft.notes), now)
        return (result as? EditResult.Changed)?.document
    }

    private fun VaultFile.copy(prefix: String, bytes: ByteArray) = VaultFile(prefix + name, bytes, mode, keyFileName, keyFile)

    private fun report(o: Outcome) {
        val out = StringBuilder("# Save grid\n\n")
        out.append("Each file is opened, edited and saved with KashPass's own encoder, reopened, edited and saved again; ")
        out.append("KeePass 2 reads each save.\n\n")
        out.append("| Set | Opened | Saved | Saved again |\n|---|---|---|---|\n")
        for (set in o.opened.keys) out.append("| $set | ${o.opened[set]} | ${o.saved[set] ?: 0} | ${o.resaved[set] ?: 0} |\n")
        out.append("| total | ${o.opened.values.sum()} | ${o.saved.values.sum()} | ${o.resaved.values.sum()} |\n\n")
        out.append("Files that do not open (${o.notOpened.size}):\n\n").append(o.notOpened.joinToString("\n") { "- $it" }).append("\n\n")
        out.append("Files that open read-only (${o.readOnly.size}):\n\n").append(o.readOnly.joinToString("\n") { "- $it" }).append("\n\n")
        out.append("Differences KeePass 2 makes on the opened file too (${o.inherited.size}):\n\n").append(o.inherited.joinToString("\n") { "- $it" }).append("\n\n")
        out.append(if (o.problems.isEmpty()) "Every save opens in KeePass 2 with the saved content.\n" else "Problems (${o.problems.size}):\n\n" + o.problems.joinToString("\n") { "- $it" } + "\n")
        KeePass2Files.writeReport("grid-save.md", out.toString())
    }

    private companion object {
        const val LOCATION = "content://fake/grid-save.kdbx"
        const val TITLE = "Saved by KashPass"
        const val TITLE_AGAIN = "Saved by KashPass again"
        const val GRID = "keepass2"
    }
}
