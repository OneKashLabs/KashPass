package org.onekash.kashpass.vault.keepass2

import kotlin.test.fail
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage

/**
 * Every grid file KeePass 2 writes ([GridWriters]) gets KeePass 2's outcome through
 * KashPass's opener with its own container: what KeePass 2 opens opens, with the content KeePass 2
 * reports, and what it refuses is refused. Writes build/reports/keepass2/grid.md. Runs with
 * -Pkashpass.keepass2 only, over a grid written before the run.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2GridTest {

    private fun open(file: VaultFile): OpenResult = runBlocking {
        val storage = FakeVaultStorage().apply { put(LOCATION, file.bytes) }
        val opener = VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO)
        opener.open(LOCATION, (TestFiles.password(file.mode) ?: "").toCharArray(), keyFile = file.keyFile?.copyOf())
    }

    @Test
    fun `every grid file opens through KashPass's container with KeePass 2's content`() {
        val grids = linkedMapOf("keepass2" to GridWriters.written("keepass2", "the KeePass 2 grid script"))
        val key = KeePass2Run.newKey()
        val problems = mutableListOf<String>()
        val refusals = mutableListOf<String>()
        // In chunks, so no more than a few dozen 2 MiB vaults are in memory at once.
        for ((writer, cells) in grids) for (chunk in cells.chunked(48)) {
            val files = chunk.map { GridWriters.load(writer, it) }
            val kp2 = KeePass2Run.keepass2(files, key)
            for (f in files) {
                val theirs = kp2.getValue(f.name)
                val opened = open(f)
                (opened as? OpenResult.Unlocked)?.session?.release()
                if (theirs !is KeePass2Report.Opened) {
                    // A file KeePass 2 refuses, the opener refuses too.
                    refusals += "${f.name}: KeePass 2 ${theirs}; the opener gives $opened"
                    if (opened is OpenResult.Unlocked) problems += "${f.name}: KeePass 2 refuses it, the opener opens it"
                    continue
                }
                if (opened !is OpenResult.Unlocked) {
                    problems += "${f.name}: KeePass 2 opens it, the opener gives $opened"
                    continue
                }
                val diff = KeePass2Report.diff(theirs, DocumentReport.of(f, key))
                if (diff.isNotEmpty()) problems += "${f.name}: content differs from KeePass 2:\n  " + diff.take(6).joinToString("\n  ")
            }
        }
        val report = StringBuilder("# Reader grid\n\n")
        for ((writer, cells) in grids) report.append("- written by $writer: ${cells.size} files\n")
        report.append("\nSkipped cells:\n\n").append(GridWriters.SKIPPED.joinToString("\n") { "- $it" }).append("\n\n")
        report.append("Files KeePass 2 refuses (${refusals.size}):\n\n").append(refusals.joinToString("\n") { "- $it" }).append("\n\n")
        report.append(if (problems.isEmpty()) "Every other file opens through the opener with KeePass 2's content.\n" else problems.joinToString("\n"))
        KeePass2Files.writeReport("grid.md", report.toString())
        if (problems.isNotEmpty()) fail("${problems.size} problems:\n" + problems.take(40).joinToString("\n"))
    }

    private companion object {
        const val LOCATION = "content://fake/grid.kdbx"
    }
}
