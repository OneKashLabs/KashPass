package org.onekash.kashpass.vault.keepass2

import io.kotest.property.RandomSource
import io.kotest.property.arbitrary.next
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import kotlin.random.Random
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.VaultModel

/**
 * Generated vaults (re-saved by KeePass 2 first, as [KeePass2DifferentialEditingTest] does) and
 * generated sequences of add, single-field edit and delete, each run by KashPass ([CompanionRig])
 * and replayed by KeePass 2 as its UI does them (`keepass2-read.sh --replay`); both
 * files must export the same ([CompanionComparison]). The batch comes from one seed
 * ([PropertyRuns]) and is written with the result to build/reports/keepass2/edit-sequences.md. Runs
 * with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2EditSequenceTest {

    private val key = KeePass2Run.newKey()
    private val hashEmpty = KeePass2Report.mac(key, ByteArray(0))

    @Test
    fun `KashPass and KeePass 2 give the same file for generated edit sequences`() {
        val seed = PropertyRuns.seed()
        val inputs = List(CASES) { i -> VaultFile("generated-$i.kdbx", VaultModel.write(Generators.doc.next(RandomSource.seeded(seed + i)), aesRounds = 1UL)) }
        val resaved = KeePass2Run.keepass2ResavedFiles(inputs)
        val inputXml = KeePass2Run.keepass2Xml(resaved, key).mapValues { (name, e) -> (e as? KeePass2Run.Export.Opened)?.xml ?: fail("$name: $e") }
        val cases = resaved.mapIndexed { i, input -> KeePass2Run.ReplayCase("sequence-$i", input, ops(Random(seed + i), CompanionRig.open(input).document)) }

        class Saved(val file: VaultFile, val window: KeePassXml.Window)
        val kashPass = cases.associate { c ->
            val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
            c.name to Saved(CompanionRig.run(c.input, c.ops, now, "kashpass-${c.name}.kdbx"), KeePassXml.Window.of(now, now))
        }
        val kashPassXml = KeePass2Run.keepass2XmlOpened(kashPass.values.map { it.file }, key)
        val keePass = KeePass2Run.keepass2Replay(cases, key)

        val problems = mutableListOf<String>()
        val outcomes = mutableListOf<String>()
        for (c in cases) {
            val compared = CompanionComparison.compare(
                inputXml.getValue(c.input.name), kashPassXml.getValue("kashpass-${c.name}.kdbx"), kashPass.getValue(c.name).window, keePass.getValue(c.name), hashEmpty,
            )
            problems += compared.problems.map { "${c.name}: $it" }
            val ops = c.ops.joinToString("; ") { it.line.substringBefore('\t') }
            if (compared.diff.isEmpty()) outcomes += "${c.name} ($ops): same"
            else problems += "${c.name} ($ops): KashPass | KeePass 2 differ:\n    " + compared.diff.take(12).joinToString("\n    ")
        }
        val out = StringBuilder("# Generated edit sequences\n\n")
            .append("Seed $seed, $CASES generated vaults re-saved by KeePass 2, one sequence each, run by KashPass and replayed by KeePassLib.\n\n")
            .append("Outcomes:\n\n").append(KeePass2Files.bullets(outcomes)).append("\n\n")
            .append(if (problems.isEmpty()) "No problems.\n" else "Problems (${problems.size}):\n\n" + KeePass2Files.bullets(problems) + "\n")
        KeePass2Files.writeReport("edit-sequences.md", out.toString())
        if (problems.isNotEmpty()) fail("${problems.size} problems (seed $seed):\n" + problems.take(20).joinToString("\n"))
    }

    // 1-8 actions on [document]: an add to a group outside the recycle bin, an edit of one standard
    // field of an entry not yet deleted, or a delete; a deleted entry is not touched again.
    private fun ops(r: Random, document: VaultDocument): List<CompanionOp> {
        val alive = DocumentIds.entries(document).values.map { it.child("UUID")!!.text() }.toMutableList()
        val groups = EntryEdits.groups(document).map { c -> DocumentIds.groups(document).getValue(c.id).child("UUID")!!.text() }
        return List(r.nextInt(1, 9)) {
            when {
                alive.isEmpty() || r.nextInt(4) == 0 -> {
                    val uuid = Uuids.format(UUID(r.nextLong(), r.nextLong()))
                    alive += uuid
                    CompanionOp.Add(groups.random(r).takeIf { r.nextBoolean() }, uuid, text(r), text(r), text(r), text(r))
                }
                r.nextInt(3) == 0 -> CompanionOp.Delete(alive.removeAt(r.nextInt(alive.size)))
                else -> CompanionOp.Edit(alive.random(r), CompanionOp.STANDARD.random(r), text(r))
            }
        }
    }

    private fun text(r: Random) = List(r.nextInt(1, 12)) { "abcdefgh &<é漢".random(r) }.joinToString("").let { if (it.isBlank()) "v$it" else it }

    private companion object {
        const val CASES = 20
    }
}
