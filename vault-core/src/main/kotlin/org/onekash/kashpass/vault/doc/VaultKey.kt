package org.onekash.kashpass.vault.doc

import java.security.MessageDigest
import org.onekash.kashpass.vault.kdbx.CompositeKey

/**
 * The parts a vault's composite key is built from, held masked: the 32-byte SHA-256 of the UTF-8
 * password and the key-file part, at least one of them.
 * The password text is never kept. Never shows its content in `toString`. [VaultKeyTest] pins
 * the hashes and composite keys.
 */
internal class VaultKey private constructor(private val passwordHash: MaskedBytes?, private val keyFilePart: MaskedBytes?) {

    /** Returns a copy of the password hash, null without a password; the caller zero-fills it. */
    fun passwordHash(): ByteArray? = passwordHash?.plain()

    /** Returns a copy of the key-file part, null without a key file; the caller zero-fills it. */
    fun keyFilePart(): ByteArray? = keyFilePart?.plain()

    /**
     * Runs [block] on copies of the password hash and key-file part, null for a part this key
     * lacks, and zero-fills both copies when it returns or throws.
     */
    inline fun <T> withParts(block: (passwordHash: ByteArray?, keyFilePart: ByteArray?) -> T): T {
        val hash = passwordHash()
        val part = keyFilePart()
        return try {
            block(hash, part)
        } finally {
            hash?.fill(0)
            part?.fill(0)
        }
    }

    /** Returns the 32-byte composite key ([CompositeKey.compute]); the caller zero-fills it. */
    fun compositeKey(): ByteArray = withParts(CompositeKey::compute)

    override fun toString() = "VaultKey(****)"

    companion object {
        /** The length of a password hash, the SHA-256 of the password. */
        const val HASH_BYTES = 32

        /**
         * Returns the key of [password], encoded as UTF-8 with lone surrogates replaced
         * ([withUtf8]), and, when given, the key file's [keyFilePart]. Zero-fills [password];
         * [keyFilePart] is copied and stays the caller's to zero-fill.
         */
        fun password(password: CharArray, keyFilePart: ByteArray? = null): VaultKey = try {
            val hash = withUtf8(password) { buffer, length -> MessageDigest.getInstance("SHA-256").apply { update(buffer, 0, length) }.digest() }
            VaultKey(MaskedBytes.of(hash), keyFilePart?.let { MaskedBytes.of(it.copyOf()) })
        } finally {
            password.fill('\u0000')
        }

        /**
         * Returns the key of a stored 32-byte password [hash] (biometric unlock) and, when given,
         * the key file's [keyFilePart]. Both are copied and stay the caller's to zero-fill.
         */
        fun passwordHash(hash: ByteArray, keyFilePart: ByteArray?): VaultKey {
            require(hash.size == HASH_BYTES) { "a password hash is $HASH_BYTES bytes" }
            return VaultKey(MaskedBytes.of(hash.copyOf()), keyFilePart?.let { MaskedBytes.of(it.copyOf()) })
        }

        /**
         * Returns the key of the key file's [keyFilePart] alone; the part is copied and stays the
         * caller's to zero-fill.
         */
        fun keyFile(keyFilePart: ByteArray): VaultKey = VaultKey(null, MaskedBytes.of(keyFilePart.copyOf()))
    }
}
