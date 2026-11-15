package org.onekash.kashpass.vault.fuzz

import java.io.File
import java.security.MessageDigest
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.fixtures.TestFiles

/**
 * Replays every fuzz target over its corpus-derived seeds in the default suite, so a container
 * change that breaks a target fails here before any fuzzing run. A fuzzing crash becomes a corpus
 * recipe, which then replays here too. The time bound is 2 s per input after a warm-up, a margin
 * over the 1 s the fuzzing runs check.
 */
class FuzzReplayTest {

    private fun replay(name: String, seeds: List<ByteArray>, target: (ByteArray) -> Unit) {
        assertTrue(seeds.size > 10, "$name: ${seeds.size} seeds")
        val previous = FuzzTargets.timeLimitMillis
        try {
            FuzzTargets.timeLimitMillis = Long.MAX_VALUE
            target(seeds.first())
            FuzzTargets.timeLimitMillis = 2_000
            for (seed in seeds) target(seed)
        } finally {
            FuzzTargets.timeLimitMillis = previous
        }
    }

    @Test
    fun `the whole-file target passes on every corpus file`() = replay("decode", FuzzSeeds.files, FuzzTargets::decode)

    @Test
    fun `the body target passes on every corpus payload`() = replay("body", FuzzSeeds.bodies, FuzzTargets::body)

    @Test
    fun `the inner header target passes on every corpus content`() = replay("innerHeader", FuzzSeeds.innerHeaders, FuzzTargets::innerHeader)

    @Test
    fun `the dictionary target passes on every corpus dictionary`() = replay("dictionary", FuzzSeeds.dictionaries, FuzzTargets::dictionary)

    @Test
    fun `the XML target passes on every fixture and XML corpus case`() = replay("xml", FuzzSeeds.xml, FuzzTargets::xml)

    @Test
    fun `the round-trip target passes on every seed`() = replay("roundTrip", FuzzSeeds.roundTrips, FuzzTargets::roundTrip)

    @Test
    fun `the cross-encode target passes on every fixture and XML corpus case`() = replay("crossEncode", FuzzSeeds.crossEncodes, FuzzTargets::crossEncode)

    /** Writes the seeds into Jazzer's corpus folder; runs with -Pkashpass.fuzzSeeds only. */
    @Test
    @EnabledIfSystemProperty(named = "kashpass.fuzzSeeds", matches = "true")
    fun `write the seeds for the fuzzing runs`() {
        val root = File(TestFiles.root, "vault-core/.cifuzz-corpus/${DecoderFuzzTest::class.java.name}")
        val sets = mapOf(
            "decode" to FuzzSeeds.files, "body" to FuzzSeeds.bodies, "innerHeader" to FuzzSeeds.innerHeaders,
            "dictionary" to FuzzSeeds.dictionaries, "xml" to FuzzSeeds.xml,
            "roundTrip" to FuzzSeeds.roundTrips, "crossEncode" to FuzzSeeds.crossEncodes,
        )
        for ((method, seeds) in sets) {
            val dir = File(root, method).apply { mkdirs() }
            for (seed in seeds) {
                val name = MessageDigest.getInstance("SHA-1").digest(seed).joinToString("") { "%02x".format(it) }
                File(dir, "seed-$name").writeBytes(seed)
            }
        }
    }
}
