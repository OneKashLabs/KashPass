package org.onekash.kashpass.vault.doc

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Bytes held XOR-masked with a random mask of the same length, so the plaintext exists only in
 * the copies [plain] hands out. Never shows its content in `toString`.
 */
internal class MaskedBytes private constructor(private val masked: ByteArray, private val mask: ByteArray) {

    /** The length of the value in bytes. */
    val byteLength: Int get() = masked.size

    /** Returns a fresh plaintext copy; the caller zero-fills it. */
    fun plain(): ByteArray = ByteArray(masked.size) { (masked[it].toInt() xor mask[it].toInt()).toByte() }

    /** Returns true when [other] holds the same bytes, compared in constant time for a length. */
    fun contentEquals(other: MaskedBytes): Boolean {
        val a = plain()
        val b = other.plain()
        return try {
            MessageDigest.isEqual(a, b)
        } finally {
            a.fill(0)
            b.fill(0)
        }
    }

    override fun toString() = "MaskedBytes($byteLength bytes)"

    companion object {
        private val random = SecureRandom()

        /** Takes ownership of [bytes]: masks them in place, so no plaintext copy remains. */
        fun of(bytes: ByteArray): MaskedBytes {
            val mask = ByteArray(bytes.size).also { random.nextBytes(it) }
            for (i in bytes.indices) bytes[i] = (bytes[i].toInt() xor mask[i].toInt()).toByte()
            return MaskedBytes(bytes, mask)
        }
    }
}
