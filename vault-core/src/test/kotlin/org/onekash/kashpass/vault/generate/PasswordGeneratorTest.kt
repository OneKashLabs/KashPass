package org.onekash.kashpass.vault.generate

import java.security.SecureRandom
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

class PasswordGeneratorTest {

    private val letters = ('A'..'Z') + ('a'..'z') + ('0'..'9')

    @Test
    fun `the default is 20 characters of upper case, lower case and digits`() {
        val password = PasswordGenerator.generate()
        assertEquals(20, password.size)
        assertTrue(password.all { it in letters }, String(password))
    }

    @ParameterizedTest
    @CsvSource("8,false", "8,true", "20,true", "64,false", "64,true")
    fun `length and symbols are honored`(length: Int, symbols: Boolean) {
        val allowed = if (symbols) letters + PasswordGenerator.SYMBOLS.toList() else letters
        repeat(200) {
            val password = PasswordGenerator.generate(length, symbols)
            assertEquals(length, password.size)
            assertTrue(password.all { it in allowed }, String(password))
        }
    }

    @Test
    fun `lengths outside 8 to 64 are refused`() {
        for (length in listOf(-1, 0, 7, 65, 1_000)) assertFailsWith<IllegalArgumentException> { PasswordGenerator.generate(length) }
    }

    @Test
    fun `symbols are KeePass 2's special set`() {
        assertEquals("!\"#\$%&'*+,./:;=?@\\^`|~", PasswordGenerator.SYMBOLS)
    }

    @Test
    fun `every allowed character is equally likely with a seeded source`() {
        val seeded = SecureRandom.getInstance("SHA1PRNG").apply { setSeed(42L) }
        // 99.9% critical value of chi-square for 61 degrees of freedom (62 characters - 1).
        assertTrue(chiSquare(seeded, symbols = false) < 101.0)
    }

    @Test
    fun `every allowed character is equally likely with the real source`() {
        // A bound a fair source exceeds with probability below 1e-9 (Wilson-Hilferty, 83 degrees of
        // freedom), so this test does not flake, and a biased draw (modulo bias, a missing
        // character) lands far above it.
        assertTrue(chiSquare(SecureRandom(), symbols = true) < 190.0)
    }

    @Test
    fun `symbols show up when enabled`() {
        val all = (1..1_000).flatMap { PasswordGenerator.generate(20, true).toList() }.toSet()
        assertEquals((letters + PasswordGenerator.SYMBOLS.toList()).toSet(), all)
    }

    private fun chiSquare(random: SecureRandom, symbols: Boolean): Double {
        val alphabet = if (symbols) letters + PasswordGenerator.SYMBOLS.toList() else letters
        val counts = HashMap<Char, Int>()
        repeat(10_000) {
            for (c in PasswordGenerator.generate(20, symbols, random)) counts.merge(c, 1, Int::plus)
        }
        assertEquals(alphabet.toSet(), counts.keys)
        val expected = 10_000 * 20.0 / alphabet.size
        return counts.values.sumOf { (it - expected) * (it - expected) / expected }
    }
}
