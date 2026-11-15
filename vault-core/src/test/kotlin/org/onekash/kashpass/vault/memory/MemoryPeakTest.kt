package org.onekash.kashpass.vault.memory

import java.io.File
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.memory.MemoryRun.MIB
import org.onekash.kashpass.vault.memory.MemoryVaults.Shape
import org.onekash.kashpass.vault.memory.MemoryVaults.Spec

/**
 * Records what open and save cost in heap for attachment-heavy and node-dense vaults, gzip and
 * not, and the performance vault, in child JVMs:
 * - the heap pools' peak at 256 MiB and 512 MiB (`build/memory/peaks.tsv`);
 * - the smallest heap each vault opens in, and opens and saves in, over the platform-like disk
 *   storage and over the shared fake; the difference is the fake's extra copies of the file
 *   (`build/memory/smallest-heap.tsv`);
 * - the smallest heap that opens, edits and saves each vault, the edits growing its XML past
 *   what was read (`build/memory/smallest-heap-edited.tsv`).
 *
 * The opener and saver get limits for an 8 GiB heap, so no limit refuses a vault before its cost
 * is measured. [org.onekash.kashpass.vault.doc.VaultXmlCodec.Limits.forHeap] and the read limit
 * are set from the disk numbers; [FixedHeapLimitTest] checks them. These tests assert nothing, so
 * they run only with -Pkashpass.memory.
 */
@EnabledIfSystemProperty(named = "kashpass.memory", matches = "true")
class MemoryPeakTest {

    @Test
    fun `records the heap peak of open and save per vault and heap`() {
        val specs = listOf(
            listOf(16, 32, 48, 64, 96).flatMap { listOf(Spec.mib(Shape.ATTACHMENTS, true, it), Spec.mib(Shape.ATTACHMENTS, false, it)) },
            listOf(32, 64, 128).map { Spec.mib(Shape.TEXT_ATTACHMENTS, true, it) },
            listOf(16, 32, 64, 128).map { Spec.mib(Shape.ENTRIES, true, it) },
            listOf(16, 32).map { Spec.mib(Shape.ENTRIES, false, it) },
            listOf(8, 16, 32, 64).map { Spec.mib(Shape.FIELDS, true, it) },
            listOf(8, 16).map { Spec.mib(Shape.FIELDS, false, it) },
        ).flatten()
        MemoryRun.generate(specs)
        val vaults = specs.map { File(MemoryRun.dir, it.name) } + listOfNotNull(MemoryRun.performance.takeIf { it.isFile })
        val runs = vaults.flatMap { v -> listOf("256m", "512m").map { xmx -> { MemoryRun.measure(v, xmx, 8192 * MIB, FLAGS) } } }
        val results = MemoryRun.parallel(3, runs)
        val table = StringBuilder("vault\tfile\txmx\tstep\toutcome\tpeak\tmillis\txml\tdecompressed\tretainedAfterOpen\n")
        for (m in results) {
            if (m.steps.isEmpty()) table.append("${m.vault.name}\t${m.vault.length()}\t${m.xmx}\tnone\t${m.log.lines().lastOrNull { it.isNotBlank() }}\n")
            val save = m.step("save")
            for (s in m.steps) {
                table.append("${m.vault.name}\t${m.vault.length()}\t${m.xmx}\t${s.step}\t${s.outcome}\t${s.peak}\t${s.millis}\t${save?.values?.get("xml") ?: ""}\t${save?.values?.get("decompressed") ?: ""}\t${save?.values?.get("retainedAfterOpen") ?: ""}\n")
            }
        }
        File(MemoryRun.dir, "peaks.tsv").writeText(table.toString())
        println(table)
    }

    @Test
    fun `records the smallest heap that opens and saves each vault`() {
        val specs = listOf(
            listOf(16, 32, 63).flatMap { listOf(Spec.mib(Shape.ATTACHMENTS, true, it), Spec.mib(Shape.ATTACHMENTS, false, it)) },
            listOf(16, 32, 64).map { Spec.mib(Shape.TEXT_ATTACHMENTS, true, it) },
            listOf(4, 8, 16).map { Spec.mib(Shape.ENTRIES, true, it) },
            listOf(2, 4, 8).map { Spec.mib(Shape.FIELDS, true, it) },
        ).flatten()
        MemoryRun.generate(specs)
        val vaults = specs.map { File(MemoryRun.dir, it.name) } + listOfNotNull(MemoryRun.performance.takeIf { it.isFile })
        val runs = vaults.flatMap { v ->
            listOf(true, false).flatMap { disk ->
                listOf(true, false).map { openOnly -> { listOf(v.name, v.length(), if (disk) "disk" else "fake", if (openOnly) "open" else "open+save", MemoryRun.smallestHeapMib(v, 8192 * MIB, 32, 1536, openOnly = openOnly, disk = disk) ?: "over 1536") } }
            }
        }
        val table = StringBuilder("vault\tfile\tstorage\tsteps\tsmallestHeapMib\n")
        for (row in MemoryRun.parallel(4, runs)) table.append(row.joinToString("\t")).append('\n')
        File(MemoryRun.dir, "smallest-heap.tsv").writeText(table.toString())
        println(table)
    }

    @Test
    fun `records the smallest heap that opens, edits and saves each vault`() {
        val specs = listOf(
            listOf(32, 63).flatMap { listOf(Spec.mib(Shape.ATTACHMENTS, true, it), Spec.mib(Shape.ATTACHMENTS, false, it)) },
            listOf(Spec.mib(Shape.TEXT_ATTACHMENTS, true, 32), Spec.mib(Shape.ENTRIES, true, 8), Spec.mib(Shape.FIELDS, true, 4)),
        ).flatten()
        MemoryRun.generate(specs)
        val vaults = specs.map { File(MemoryRun.dir, it.name) } + listOfNotNull(MemoryRun.performance.takeIf { it.isFile })
        val runs = vaults.flatMap { v ->
            listOf(0, EDITS).map { edits -> { listOf(v.name, v.length(), edits, MemoryRun.smallestHeapMib(v, 8192 * MIB, 32, 1536, disk = true, edits = edits) ?: "over 1536") } }
        }
        val table = StringBuilder("vault\tfile\tedits\tsmallestHeapMib\n")
        for (row in MemoryRun.parallel(4, runs)) table.append(row.joinToString("\t")).append('\n')
        File(MemoryRun.dir, "smallest-heap-edited.tsv").writeText(table.toString())
        println(table)
    }

    private companion object {
        // Entry edits before the save: each adds a history snapshot and 4 KiB of notes.
        const val EDITS = 16

        // A small young generation keeps short-lived garbage out of the peak.
        val FLAGS = listOf("-XX:+UseSerialGC", "-Xmn16m")
    }
}
