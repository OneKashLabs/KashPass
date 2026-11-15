package org.onekash.kashpass.vault.memory

import java.io.File
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.kdbx.VariantDictionary
import org.onekash.kashpass.vault.memory.MemoryRun.MIB
import org.onekash.kashpass.vault.memory.MemoryVaults.Shape
import org.onekash.kashpass.vault.memory.MemoryVaults.Spec
import org.onekash.kashpass.vault.keepass2.KeePass2Run
import org.onekash.kashpass.vault.storage.maxVaultBytes
import org.onekash.kashpass.vault.testing.HeaderDictionaries

/**
 * Opens and saves (encode, backup copy, read-back) vaults near the limits in child JVMs over the
 * platform-like disk storage ([MemoryProbe]), the limits computed for the heap under test:
 * - vaults generated from [VaultXmlCodec.Limits.forHeap]: node-dense XML just under the open cap
 *   opens, XML just under the save cap and attachments just under the payload save cap open and
 *   save, in a heap of that size and in one two thirds of it (the margin of 1.5); the attachment
 *   vault also after [EDITS] entry edits, each adding a history snapshot and 4 KiB of notes, and
 *   the XML vaults under the save cap after the same edits either save or stop before the write
 *   ([allowed]): the edits can grow their XML past the save cap;
 * - a vault of attachments gzip can't shrink at the read limit ([maxVaultBytes]) and a vault of
 *   entries whose XML is a quarter of the heap end in one of the outcomes [allowed] lists; none
 *   writes the file and then fails to read it back;
 * - the performance vault (`make-fixtures.sh --performance`) and the largest fixture open and
 *   save on a 256 MiB heap: a smaller heap moves the caps, not these vaults;
 * - a file at the read limit whose outer header field 11 or 12 holds a dictionary of tiny entries
 *   is NotEnoughMemory on check, never an OutOfMemoryError, and a read dictionary keeps at most
 *   [VariantDictionary.ENTRY_HEAP_BYTES] / 1.5 per entry beyond its bytes.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class FixedHeapLimitTest {

    @ParameterizedTest
    @ValueSource(ints = [256, 512])
    fun `vaults just under the caps open, and save where the save caps allow, with a margin of 1_5`(heapMib: Int) {
        val heap = heapMib * MIB
        val limits = VaultXmlCodec.Limits.forHeap(heap)
        // 5% below a cap leaves room for the protected passwords, which grow from a one-character
        // placeholder to Base64 when the vault is built, and the last entry past the target.
        fun under(cap: Long) = (cap / 1024 * 95 / 100).toInt()
        val underOpen = listOf(Shape.ENTRIES, Shape.FIELDS).map { Spec(it, gzip = true, kib = under(limits.open.toLong())) }
        val attachments = Spec(Shape.ATTACHMENTS, gzip = true, kib = (minOf(limits.payloadSave, maxVaultBytes(heap).toLong()) / 1024 - 1024).toInt())
        val underSave = listOf(Shape.ENTRIES, Shape.FIELDS).map { Spec(it, gzip = true, kib = under(limits.save)) } + attachments
        MemoryRun.generate(underOpen + underSave)
        // The attachment vault also saves after edits whose XML outgrows what was read.
        val rows = underOpen.map { Triple(it, false, 0) } + underSave.map { Triple(it, true, 0) } + Triple(attachments, true, EDITS)
        val editedXml = underSave.filter { it.shape != Shape.ATTACHMENTS }
        val failures = rows.flatMap { (spec, saves, edits) ->
            listOf("${heapMib}m", "${heapMib * 2 / 3}m").mapNotNull { xmx ->
                val m = MemoryRun.measure(File(MemoryRun.dir, spec.name), xmx, heap, disk = true, edits = edits)
                val open = m.step("open")
                val save = m.step("save")
                val ok = open?.ok == true && if (saves) save?.ok == true else save?.outcome in setOf("Saved", "ReadOnly")
                if (ok) null else "${spec.name} ($edits edits) at -Xmx$xmx: ${describe(m)}"
            }
        } + editedXml.flatMap { spec ->
            listOf("${heapMib}m", "${heapMib * 2 / 3}m").mapNotNull { xmx ->
                val m = MemoryRun.measure(File(MemoryRun.dir, spec.name), xmx, heap, disk = true, edits = EDITS)
                if (allowed(m) && m.step("save")?.outcome != "ReadOnly") null else "${spec.name} ($EDITS edits) at -Xmx$xmx: ${describe(m)}"
            }
        }
        if (failures.isNotEmpty()) fail("limits for a $heapMib MiB heap $limits:\n" + failures.joinToString("\n"))
    }

    @ParameterizedTest
    @ValueSource(ints = [256, 512])
    fun `a vault at the read limit and XML of a quarter of the heap end in an allowed outcome`(heapMib: Int) {
        val heap = heapMib * MIB
        // The generated content leaves 1 MiB for the XML, headers and blocks around it.
        val specs = listOf(
            Spec.mib(Shape.ATTACHMENTS, gzip = true, mib = (maxVaultBytes(heap) / MIB - 1).toInt()),
            Spec.mib(Shape.ENTRIES, gzip = true, mib = (heap / 4 / MIB - 1).toInt()),
        )
        MemoryRun.generate(specs)
        val failures = specs.mapNotNull { spec ->
            val m = MemoryRun.measure(File(MemoryRun.dir, spec.name), "${heapMib}m", heap, disk = true)
            if (allowed(m)) null else "${spec.name}: ${describe(m)}"
        }
        if (failures.isNotEmpty()) fail("outcomes on a $heapMib MiB heap:\n" + failures.joinToString("\n"))
    }

    @Test
    fun `the performance vault and the largest fixture open and save on a 256 MiB heap`() {
        val vaults = listOf(MemoryRun.performance, File(TestFiles.root, "vault-core/src/test/resources/fixtures/keepass2-multiblock-attachment.kdbx"))
        val missing = vaults.filterNot { it.isFile }
        if (missing.isNotEmpty()) fail("missing: $missing (make-fixtures.sh --performance writes the performance vault)")
        val failures = vaults.mapNotNull { v ->
            val m = MemoryRun.measure(v, "256m", 256 * MIB, disk = true)
            if (m.step("open")?.ok == true && m.step("save")?.ok == true) null else "${v.name}: ${describe(m)}"
        }
        if (failures.isNotEmpty()) fail(failures.joinToString("\n"))
    }

    @ParameterizedTest
    @ValueSource(ints = [256, 512])
    fun `a header dictionary of tiny entries at the read limit is NotEnoughMemory, never an OutOfMemoryError`(heapMib: Int) {
        val failures = listOf(HeaderDictionaries.KDF, HeaderDictionaries.PUBLIC_CUSTOM_DATA).mapNotNull { field ->
            val m = MemoryRun.header(field, "${heapMib}m")
            if (m.step("check")?.outcome == "NotEnoughMemory") null else "field $field: ${describe(m)}"
        }
        if (failures.isNotEmpty()) fail("on a $heapMib MiB heap:\n" + failures.joinToString("\n"))
    }

    @ParameterizedTest
    @ValueSource(ints = [256, 512])
    fun `a key file of tiny elements is too large or hashed, never an OutOfMemoryError`(heapMib: Int) {
        val expected = mapOf("KeyFile" to "KeyFileTooLarge", "X" to "WrongPassword")
        val failures = expected.mapNotNull { (root, outcome) ->
            val m = MemoryRun.keyFile(root, "${heapMib}m")
            if (m.step("open")?.outcome == outcome) null else "root $root: ${describe(m)}"
        } + listOfNotNull(
            // At the key-file limit the KeyFile document is parsed; with no key it is damaged.
            MemoryRun.keyFile("KeyFile", "${heapMib}m", parsed = true).let { m ->
                if (m.step("open")?.outcome == "KeyFileDamaged") null else "KeyFile root at the limit: ${describe(m)}"
            },
        )
        if (failures.isNotEmpty()) fail("on a $heapMib MiB heap:\n" + failures.joinToString("\n"))
    }

    @Test
    fun `a dictionary entry keeps at most its charge divided by the margin of 1_5`() {
        // 3-byte names and empty values, the shape that costs the most per byte of file; then
        // longer names and values, whose bytes are charged on top of the fixed cost.
        val shapes = listOf(Triple(1_000_000, 3, 0), Triple(300_000, 16, 8), Triple(200_000, 64, 0))
        val failures = shapes.mapNotNull { (count, name, value) ->
            val measured = MemoryRun.entryCost(count, name, value)
            val allowed = (VariantDictionary.ENTRY_HEAP_BYTES + name + value) / 1.5
            if (measured <= allowed) null else "$count entries, $name-byte names, $value-byte values: $measured bytes each, over $allowed"
        }
        if (failures.isNotEmpty()) fail(failures.joinToString("\n"))
    }

    private fun describe(m: MemoryRun.Measured): String =
        m.steps.joinToString { s -> "${s.step} ${s.outcome} ${s.values.filterKeys { it in DETAIL }.filterValues { it.isNotEmpty() }}" }
            .ifEmpty { m.log.lines().takeLast(5).joinToString("\n") }

    /**
     * True when [m] ends in an outcome allowed for a vault near the limits: it opens and saves; it
     * opens read-only as too large to save; the open stops at a limit; or the save stops for
     * memory before anything is written. A save that wrote the file always verifies.
     */
    private fun allowed(m: MemoryRun.Measured): Boolean {
        val open = m.step("open") ?: return false
        val save = m.step("save")
        return when {
            open.outcome == "NotEnoughMemory" -> open.values["cause"] == "LIMIT"
            open.outcome != "Unlocked" || save == null -> false
            save.outcome == "Saved" -> true
            save.outcome == "ReadOnly" -> open.values["saveability"] == "ReadOnly(reason=TOO_LARGE_TO_SAVE)"
            save.outcome == "NotEnoughMemory" -> save.values["written"] == "false"
            else -> false
        }
    }

    private companion object {
        val DETAIL = setOf("cause", "saveability", "written", "peak")
        const val EDITS = 16
    }
}
