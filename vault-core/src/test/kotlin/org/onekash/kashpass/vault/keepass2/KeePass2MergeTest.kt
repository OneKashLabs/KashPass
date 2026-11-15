package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.open.VaultOpener

/**
 * A desktop Synchronize of a KashPass-edited copy gives the same result as if KeePass 2 had made
 * the phone's edits. For each scenario ([MergeScenarios]) the phone copy A is KashPass's save
 * ([CompanionRig]); KeePass 2 builds the desktop copy D and its own phone copy A' from the same
 * base and runs Synchronize four ways (`keepass2-read.sh --merge`). The export
 * of D<-A must equal D<-A', and A<-D must equal A'<-D, with UUIDs new in the run numbered (each
 * side draws its own recycle bin UUID) and the new-object expiry time difference left out
 * ([CompanionComparison.NEW_OBJECT_EXPIRY]). Every result meets its scenario's written
 * expectation, and KashPass opens every merged file through [VaultOpener] with the content KeePass
 * 2 reads. Writes build/reports/keepass2/merge.md. Runs with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2MergeTest {

    private val key = KeePass2Run.newKey()

    @Test
    fun `KeePass 2's Synchronize of a KashPass copy equals its Synchronize of its own copy`() {
        val started = System.nanoTime()
        val generated = KeePass2Run.keepass2ResavedFiles(listOf(ReplayInputs.base.file)).single()
        val plugin = MergeScenarios.base(Fixtures.PLUGIN_DATA)
        val bases = MergeScenarios.BASES.map { MergeScenarios.base(it.first) } + plugin + generated
        val baseXml = KeePass2Run.keepass2XmlOpened(bases, key)
        // Merge compares times, so both edit times lie after every time in the bases (a fixture
        // generated minutes ago included); the phone and desktop take one each.
        val newest = baseXml.values.maxOf(::newestTime)
        val earlier = maxOf(Instant.now(), newest.plusSeconds(60)).truncatedTo(ChronoUnit.SECONDS)
        val later = earlier.plusSeconds(1_800)
        val hash = { s: String -> KeePass2Report.mac(key, s.encodeToByteArray()) }
        val scenarios = MergeScenarios(hash, earlier, later)
        val all = MergeScenarios.BASES.flatMap { (name, tag) -> scenarios.sample(MergeScenarios.base(name), baseXml.getValue(name), tag) } +
            scenarios.historyLimit(plugin, baseXml.getValue(plugin.name), "Three backups", 3, "(plugin-data, limit 3)") +
            scenarios.historyLimit(generated, baseXml.getValue(generated.name), "main", 10, "(generated, limit 10)") +
            scenarios.pluginData(plugin, baseXml.getValue(plugin.name))

        val problems = mutableListOf<String>()
        for (s in all) s.premise(baseXml.getValue(s.base.name))?.let { problems += "${s.name}: premise: $it" }

        val cases = all.mapIndexed { i, s ->
            val phone = CompanionRig.run(s.base, s.phone, s.phoneAt, "phone-$i-${s.base.name}")
            s.phoneSave?.invoke(phone)?.let { problems += "${s.name}: $it" }
            KeePass2Run.MergeCase(s.name, s.base, phone, s.phone, s.desktop, s.phoneAt, s.desktopAt)
        }
        val t0 = System.nanoTime()
        val merged = KeePass2Run.keepass2Merge(cases, key)
        val mergeSeconds = (System.nanoTime() - t0) / 1_000_000_000

        val outcomes = mutableListOf<String>()
        val hashEmpty = hash("")
        for (s in all) {
            val results = merged.getValue(s.name)
            val normal = KeePassXml.Normal(input = baseXml.getValue(s.base.name), empty = hashEmpty)
            for ((ours, reference) in listOf("D-A" to "D-A2", "A-D" to "A2-D")) {
                val (expiry, diff) = KeePassXml.diff(results.getValue(ours).xml.flat(normal), results.getValue(reference).xml.flat(normal))
                    .partition(CompanionComparison.NEW_OBJECT_EXPIRY::containsMatchIn)
                if (diff.isNotEmpty()) problems += "${s.name}: $ours differs from $reference:\n    " + diff.take(12).joinToString("\n    ")
                else outcomes += "${s.name}: $ours = $reference" + if (expiry.isNotEmpty()) " (${expiry.size} new-object expiry line(s))" else ""
            }
            for (m in KeePass2Run.MERGES) s.expect(m, results.getValue(m).xml).forEach { problems += "${s.name}: $m: $it" }
            // KashPass opens each merged file as the app does; 4.1 content stays 4.1.
            for (m in KeePass2Run.MERGES) {
                val document = CompanionRig.open(results.getValue(m).file).document
                if (KeePassXml.isKdbx41(results.getValue(m).xml) && document.savedMinor() != 1) problems += "${s.name}: $m: KashPass would save 4.${document.savedMinor()}"
            }
        }

        // KashPass reads every merged file with the content KeePass 2 reads.
        val files = merged.values.flatMap { it.values.map { m -> m.file } }
        Agreement.owned(files, KeePass2Run.keepass2(files, key), key).takeIf { it.isNotEmpty() }?.let { problems += "KashPass reads merged files differently:\n$it" }

        val out = StringBuilder("# Merge\n\n")
        out.append("Each scenario: KashPass edits the phone copy, KeePassLib the desktop copy and its own phone copy from the same base; ")
        out.append("KeePass 2's Synchronize merges them both ways, and the results with KashPass's copy must equal those with KeePassLib's.\n\n")
        out.append("Scenarios: ${all.size} (each merged four ways). Run time: ${(System.nanoTime() - started) / 1_000_000_000} s (KeePass 2 merges: $mergeSeconds s).\n\n")
        out.append("Outcomes:\n\n").append(KeePass2Files.bullets(outcomes)).append("\n\n")
        out.append(if (problems.isEmpty()) "No problems.\n" else "Problems (${problems.size}):\n\n" + KeePass2Files.bullets(problems) + "\n")
        KeePass2Files.writeReport("merge.md", out.toString())
        if (problems.isNotEmpty()) fail("${problems.size} problems:\n" + problems.take(30).joinToString("\n"))
    }

    // The newest time any element of [xml] holds.
    private fun newestTime(xml: KeePassXml): Instant =
        xml.all().mapNotNull { e -> runCatching { Instant.parse(e.text().trim()) }.getOrNull() }.maxOrNull() ?: Instant.EPOCH
}
