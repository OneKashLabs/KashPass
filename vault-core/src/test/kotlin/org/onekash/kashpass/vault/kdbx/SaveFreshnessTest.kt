package org.onekash.kashpass.vault.kdbx

import java.security.SecureRandom
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.testing.RawKdbx

/**
 * Every save of one opened file writes a master seed, an IV and a KDF salt or seed of its own,
 * none of them the file's, all drawn from the one random source the save is given.
 */
class SaveFreshnessTest {

    // Records the size of every draw.
    private class CountingRandom : SecureRandom() {
        val draws = mutableListOf<Int>()

        override fun nextBytes(bytes: ByteArray) {
            super.nextBytes(bytes)
            draws += bytes.size
        }
    }

    // Fills draw n with the byte n, so each value shows which draw it came from.
    private class NumberedRandom : SecureRandom() {
        var draws = 0

        override fun nextBytes(bytes: ByteArray) {
            draws++
            bytes.fill(draws.toByte())
        }
    }

    private class Fresh(val seed: ByteArray, val iv: ByteArray, val salt: ByteArray)

    private fun values(header: OuterHeader) = Fresh(header.masterSeed, header.iv, saltOf(header.kdf))

    private fun ivSize(name: String) = if (name.contains("chacha20")) 12 else 16

    @ParameterizedTest
    @ValueSource(strings = ["keepass2-weak-aeskdf-6000.kdbx", "keepass2-chacha20-argon2d.kdbx", "keepass2-argon2-secret-and-data.kdbx"])
    fun `two saves of one file differ from each other and from the file in every random value`(name: String) {
        val opened = openedHeader(RawKdbx.parse(Fixtures.bytes(name)))
        val settings = SaveSettings.from(opened)
        val first = assertIs<KdbxHeaderWriter.Write.Written>(KdbxHeaderWriter.write(settings, 0, SecureRandom())).header
        val second = assertIs<KdbxHeaderWriter.Write.Written>(KdbxHeaderWriter.write(settings, 0, SecureRandom())).header
        val all = listOf(values(opened), values(first), values(second))
        for (i in all.indices) for (j in all.indices) {
            if (i == j) continue
            assertFalse(all[i].seed.contentEquals(all[j].seed), "$name master seed $i $j")
            assertFalse(all[i].iv.contentEquals(all[j].iv), "$name IV $i $j")
            assertFalse(all[i].salt.contentEquals(all[j].salt), "$name KDF salt $i $j")
        }
        for (v in all.drop(1)) {
            assertEquals(32, v.seed.size)
            assertEquals(ivSize(name), v.iv.size)
            assertEquals(32, v.salt.size)
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["keepass2-weak-aeskdf-6000.kdbx", "keepass2-chacha20-argon2d.kdbx"])
    fun `every random byte comes from the save's random source, in KeePass 2's order`(name: String) {
        val settings = SaveSettings.from(openedHeader(RawKdbx.parse(Fixtures.bytes(name))))
        val counting = CountingRandom()
        KdbxHeaderWriter.write(settings, 0, counting)
        assertEquals(listOf(32, ivSize(name), 32), counting.draws)

        // The draws come in this order: master seed, IV, then the KDF salt or seed.
        val numbered = NumberedRandom()
        val header = assertIs<KdbxHeaderWriter.Write.Written>(KdbxHeaderWriter.write(settings, 0, numbered)).header
        assertEquals(3, numbered.draws)
        assertContentEquals(ByteArray(32) { 1 }, header.masterSeed)
        assertContentEquals(ByteArray(ivSize(name)) { 2 }, header.iv)
        assertContentEquals(ByteArray(32) { 3 }, saltOf(header.kdf))
    }
}
