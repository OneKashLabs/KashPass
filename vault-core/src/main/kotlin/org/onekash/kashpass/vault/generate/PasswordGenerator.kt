package org.onekash.kashpass.vault.generate

import java.security.SecureRandom

/**
 * Generates passwords: by default 20 characters drawn uniformly from upper case, lower case and
 * digits, with [SYMBOLS] as an option. Keeps no state; the caller wipes the returned array.
 * [PasswordGeneratorTest] pins the sets and the uniformity.
 */
object PasswordGenerator {

    const val DEFAULT_LENGTH = 20
    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 64

    /** The optional special characters: no brackets of any kind, '-', '_' or space. */
    const val SYMBOLS = "!\"#$%&'*+,./:;=?@\\^`|~"

    private const val LETTERS_AND_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    /**
     * Returns a password of [length] characters ([MIN_LENGTH] to [MAX_LENGTH]). Each character is
     * drawn independently with [SecureRandom.nextInt], which rejects out-of-range draws instead of
     * taking a modulo, so every allowed character is equally likely.
     */
    fun generate(length: Int = DEFAULT_LENGTH, symbols: Boolean = false, random: SecureRandom = SecureRandom()): CharArray {
        require(length in MIN_LENGTH..MAX_LENGTH) { "length must be $MIN_LENGTH to $MAX_LENGTH" }
        val alphabet = if (symbols) LETTERS_AND_DIGITS + SYMBOLS else LETTERS_AND_DIGITS
        return CharArray(length) { alphabet[random.nextInt(alphabet.length)] }
    }
}
