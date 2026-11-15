package org.onekash.kashpass.vault.kdbx

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-CBC with PKCS#7 padding, the KDBX 4 outer cipher, on the platform's default provider
 * (no provider is named; `AES/CBC/NoPadding` exists on every Android API level). KashPass removes
 * the padding itself: a last byte of 0 or above 16, or a pad byte that differs from it, is
 * [KdbxException.BadPadding]. The decoder checks the block HMACs before it
 * decrypts, so a padding failure follows a valid MAC and is damage, never a wrong key, and the
 * time the check takes tells an attacker nothing.
 *
 * The provider copies the key into its SecretKeySpec and native state, and Conscrypt copies the
 * input and output arrays around each native call; KashPass cannot clear those copies.
 */
internal object AesCbc {

    private const val BLOCK = 16

    /**
     * Decrypts [length] bytes of [data] from [offset] in place and returns the plaintext length
     * after the padding. The plaintext is written over the ciphertext; the caller zero-fills it.
     * An empty ciphertext decrypts to 0 bytes, with no padding check. Throws
     * [KdbxException.CiphertextNotBlockMultiple] for a length that is not a multiple of 16 and
     * [KdbxException.BadPadding] for invalid padding.
     */
    fun decrypt(key: ByteArray, iv: ByteArray, data: ByteArray, offset: Int, length: Int): Int {
        cbc(Cipher.DECRYPT_MODE, key, iv, data, offset, length)
        if (length == 0) return 0
        val pad = data[offset + length - 1].toInt() and 0xFF
        if (pad == 0 || pad > BLOCK) throw KdbxException.BadPadding()
        for (i in 2..pad) {
            if (data[offset + length - i].toInt() and 0xFF != pad) throw KdbxException.BadPadding()
        }
        return length - pad
    }

    /**
     * Returns the size of [length] bytes after PKCS#7 padding: the next multiple of 16 above
     * [length], so an aligned input gains a whole block. Throws [KdbxException.InvalidLength]
     * with [KdbxException.Field.RANGE] for a negative [length] or a padded size above
     * Int.MAX_VALUE.
     */
    fun paddedLength(length: Int): Int {
        if (length < 0) throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        val pad = BLOCK - length % BLOCK
        if (length > Int.MAX_VALUE - pad) throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        return length + pad
    }

    /**
     * Pads [length] bytes of [data] from [offset] with PKCS#7 (1 to 16 bytes, a full block for an
     * aligned input) in the bytes after them, encrypts the padded range in place and returns its
     * size, [paddedLength] of [length]. The bytes outside the padded range are not touched. Throws
     * [KdbxException.InvalidLength] for a key that is not 32 bytes, an IV that is not 16, a range
     * outside [data] or fewer than [paddedLength] bytes from [offset], before anything is written.
     * When the provider throws, the range holds plaintext and padding; the caller zero-fills it.
     */
    fun encrypt(key: ByteArray, iv: ByteArray, data: ByteArray, offset: Int, length: Int): Int {
        if (key.size != 32) throw KdbxException.InvalidLength(KdbxException.Field.KEY)
        if (iv.size != BLOCK) throw KdbxException.InvalidLength(KdbxException.Field.IV)
        Bytes.checkRange(data.size, offset, length)
        val padded = paddedLength(length)
        Bytes.checkRange(data.size, offset, padded)
        data.fill((padded - length).toByte(), offset + length, offset + padded)
        cbc(Cipher.ENCRYPT_MODE, key, iv, data, offset, padded)
        return padded
    }

    /**
     * Returns [plain] padded with PKCS#7 (1 to 16 bytes, a full block for an aligned input) and
     * encrypted, as a new array.
     */
    fun encrypt(key: ByteArray, iv: ByteArray, plain: ByteArray): ByteArray {
        val out = plain.copyOf(paddedLength(plain.size))
        try {
            encrypt(key, iv, out, 0, plain.size)
        } catch (e: Throwable) {
            // The copy holds the plaintext until the cipher overwrites it.
            out.fill(0)
            throw e
        }
        return out
    }

    /**
     * Runs AES-256-CBC without padding over [length] bytes of [data] from [offset] in place.
     * Throws [KdbxException.InvalidLength] for a key that is not 32 bytes, an IV that is not 16 or
     * a range outside [data], and [KdbxException.CiphertextNotBlockMultiple] for a length that is
     * not a multiple of 16; a length of 0 does nothing.
     */
    internal fun cbc(mode: Int, key: ByteArray, iv: ByteArray, data: ByteArray, offset: Int, length: Int) {
        if (key.size != 32) throw KdbxException.InvalidLength(KdbxException.Field.KEY)
        if (iv.size != BLOCK) throw KdbxException.InvalidLength(KdbxException.Field.IV)
        Bytes.checkRange(data.size, offset, length)
        if (length % BLOCK != 0) throw KdbxException.CiphertextNotBlockMultiple()
        if (length == 0) return
        Digests.provider {
            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            cipher.init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            cipher.doFinal(data, offset, length, data, offset)
        }
    }
}
