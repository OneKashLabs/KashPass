package org.onekash.kashpass.vault.storage

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import org.junit.jupiter.api.Test

// A software AES key stands in for the Keystore key, which only exists on a device.
class SealedKeyTest {

    private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val loc = "content://fake/vault.kdbx"
    private val secret = ByteArray(32) { it.toByte() }

    private fun encryptCipher() = Cipher.getInstance(AesGcm.TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }

    private fun decryptCipher(sealed: SealedKey) = Cipher.getInstance(AesGcm.TRANSFORMATION).apply {
        init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(AesGcm.TAG_BITS, sealed.iv))
    }

    @Test
    fun `a sealed key round-trips through its bytes and opens with the same location`() {
        val sealed = AesGcm.seal(encryptCipher(), secret.copyOf(), loc)
        val read = assertIs<SealedKey>(SealedKey.decode(sealed.encode()))
        assertContentEquals(secret, assertIs<ByteArray>(AesGcm.open(decryptCipher(read), read, loc)))
    }

    @Test
    fun `sealing wipes the plaintext it was given`() {
        val plain = secret.copyOf()
        AesGcm.seal(encryptCipher(), plain, loc)
        assertEquals(List(32) { 0.toByte() }, plain.toList())
    }

    @Test
    fun `another location, a changed byte or an unknown version doesn't open`() {
        val sealed = AesGcm.seal(encryptCipher(), secret.copyOf(), loc)
        assertNull(AesGcm.open(decryptCipher(sealed), sealed, "content://fake/other.kdbx"))
        val bytes = sealed.encode()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        val tampered = SealedKey.decode(bytes)!!
        assertNull(AesGcm.open(decryptCipher(tampered), tampered, loc))
        val wrongVersion = sealed.encode().also { it[0] = 2 }
        assertNull(SealedKey.decode(wrongVersion))
        assertNull(SealedKey.decode(ByteArray(3)))
        assertNull(SealedKey.decode(byteArrayOf(1, 99, 0, 0)))
        assertNull(SealedKey.decode(byteArrayOf(1, 8) + ByteArray(8 + 16)), "IV not 12 bytes")
        assertNull(SealedKey.decode(byteArrayOf(1, 12) + ByteArray(12 + 15)), "shorter than the tag")
    }

    @Test
    fun `a cipher failure other than the tag is thrown, not read as damage`() {
        val sealed = AesGcm.seal(encryptCipher(), secret.copyOf(), loc)
        // An uninitialised cipher stands in for a Keystore operation that was dropped.
        assertFailsWith<IllegalStateException> { AesGcm.open(Cipher.getInstance(AesGcm.TRANSFORMATION), sealed, loc) }
    }
}
