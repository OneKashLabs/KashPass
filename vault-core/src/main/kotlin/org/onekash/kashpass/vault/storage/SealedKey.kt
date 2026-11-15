package org.onekash.kashpass.vault.storage

import java.security.MessageDigest
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher

/**
 * A secret sealed with AES-GCM, as stored on disk: `[version | iv length | iv | ciphertext and
 * tag]`. [SealedKeyTest] pins the layout.
 */
class SealedKey(val iv: ByteArray, val ciphertext: ByteArray) {

    fun encode(): ByteArray = byteArrayOf(VERSION, iv.size.toByte()) + iv + ciphertext

    companion object {
        private const val VERSION: Byte = 1

        private const val IV_BYTES = 12
        private const val TAG_BYTES = 16

        /**
         * Reads [bytes] written by [encode]; null for anything else, so damage reads as nothing
         * stored.
         */
        fun decode(bytes: ByteArray): SealedKey? {
            if (bytes.size < 2 || bytes[0] != VERSION) return null
            val ivSize = bytes[1].toInt() and 0xFF
            if (ivSize != IV_BYTES || bytes.size < 2 + ivSize + TAG_BYTES) return null
            return SealedKey(bytes.copyOfRange(2, 2 + ivSize), bytes.copyOfRange(2 + ivSize, bytes.size))
        }
    }
}

/**
 * Seals and opens a [SealedKey] with a cipher the caller initialised (on Android, one a
 * biometric check unlocked). The SHA-256 of the vault location is the associated data, so a
 * sealed key copied to another vault's slot doesn't open.
 */
object AesGcm {
    const val TRANSFORMATION = "AES/GCM/NoPadding"
    const val TAG_BITS = 128

    /** Encrypts [plaintext] with [cipher] (in encrypt mode) and zero-fills [plaintext]. */
    fun seal(cipher: Cipher, plaintext: ByteArray, location: String): SealedKey = try {
        cipher.updateAAD(associatedData(location))
        SealedKey(cipher.iv, cipher.doFinal(plaintext))
    } finally {
        plaintext.fill(0)
    }

    /**
     * Decrypts [sealed] with [cipher] (in decrypt mode with its IV); null when the tag doesn't
     * verify. Any other failure (the Keystore busy or the operation dropped) is thrown, so the
     * caller can keep what is stored for another try.
     */
    fun open(cipher: Cipher, sealed: SealedKey, location: String): ByteArray? = try {
        cipher.updateAAD(associatedData(location))
        cipher.doFinal(sealed.ciphertext)
    } catch (e: AEADBadTagException) {
        null
    }

    private fun associatedData(location: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(location.toByteArray(Charsets.UTF_8))
}
