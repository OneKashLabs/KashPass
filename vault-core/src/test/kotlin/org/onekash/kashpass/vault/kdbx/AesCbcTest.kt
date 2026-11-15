package org.onekash.kashpass.vault.kdbx

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.PrimitiveVectors
import org.onekash.kashpass.vault.testing.RawKdbx

class AesCbcTest {

    private val key = Random(1).nextBytes(32)
    private val iv = Random(2).nextBytes(16)

    @Test
    fun `round trips at the edge lengths and decrypts in place at an offset`() {
        for (n in PrimitiveVectors.paddingLengths) {
            val plain = Random(n).nextBytes(n)
            val encrypted = AesCbc.encrypt(key, iv, plain)
            assertEquals(n + 16 - n % 16, encrypted.size, "padded size for $n")
            val buf = ByteArray(7) + encrypted + ByteArray(9)
            val length = AesCbc.decrypt(key, iv, buf, 7, encrypted.size)
            assertEquals(n, length)
            assertContentEquals(plain, buf.copyOfRange(7, 7 + n))
        }
    }

    @Test
    fun `an empty ciphertext decrypts to nothing`() {
        assertEquals(0, AesCbc.decrypt(key, iv, ByteArray(4), 2, 0))
    }

    @Test
    fun `invalid padding is BadPadding at every position`() {
        for ((name, block) in PrimitiveVectors.badPaddingBlocks()) {
            val data = block.copyOf()
            AesCbc.cbc(Cipher.ENCRYPT_MODE, key, iv, data, 0, 16)
            assertThrows<KdbxException.BadPadding>(name) { AesCbc.decrypt(key, iv, data, 0, 16) }
        }
    }

    @Test
    fun `a pad of 1 to 16 equal bytes is accepted`() {
        for (pad in 1..16) {
            val data = ByteArray(16) { if (it >= 16 - pad) pad.toByte() else 9 }
            AesCbc.cbc(Cipher.ENCRYPT_MODE, key, iv, data, 0, 16)
            assertEquals(16 - pad, AesCbc.decrypt(key, iv, data, 0, 16))
        }
    }

    @Test
    fun `a length that is not a block multiple is refused`() {
        for (n in listOf(1, 15, 17, 33)) {
            assertThrows<KdbxException.CiphertextNotBlockMultiple> { AesCbc.decrypt(key, iv, ByteArray(n), 0, n) }
        }
    }

    @Test
    fun `wrong key, IV and range are refused before the provider runs`() {
        assertEquals(KdbxException.Field.KEY, assertThrows<KdbxException.InvalidLength> { AesCbc.decrypt(ByteArray(16), iv, ByteArray(16), 0, 16) }.field)
        assertEquals(KdbxException.Field.IV, assertThrows<KdbxException.InvalidLength> { AesCbc.decrypt(key, ByteArray(12), ByteArray(16), 0, 16) }.field)
        assertEquals(KdbxException.Field.IV, assertThrows<KdbxException.InvalidLength> { AesCbc.encrypt(key, ByteArray(15), ByteArray(1)) }.field)
        val data = ByteArray(32)
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { AesCbc.decrypt(key, iv, data, 16, 32) }.field)
        assertContentEquals(ByteArray(32), data)
    }

    private fun jcaPadded(plain: ByteArray): ByteArray = Cipher.getInstance("AES/CBC/PKCS5Padding")
        .apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(this@AesCbcTest.iv)) }
        .doFinal(plain)

    @Test
    fun `the padded length is the next multiple of 16 above the length`() {
        val expected = mapOf(0 to 16, 1 to 16, 15 to 16, 16 to 32, 17 to 32, 31 to 32, 32 to 48, Int.MAX_VALUE - 16 to Int.MAX_VALUE - 15)
        for ((n, padded) in expected) assertEquals(padded, AesCbc.paddedLength(n), "length $n")
        for (n in listOf(-1, Int.MIN_VALUE, Int.MAX_VALUE - 15, Int.MAX_VALUE)) {
            assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { AesCbc.paddedLength(n) }.field, "length $n")
        }
    }

    @Test
    fun `in-place encryption pads within the caller's buffer, matches the JCA and round trips`() {
        for (n in PrimitiveVectors.paddingLengths) {
            val plain = Random(n).nextBytes(n)
            val padded = AesCbc.paddedLength(n)
            val buf = ByteArray(7) { 0x55 } + plain + ByteArray(padded - n) { 0x77 } + ByteArray(9) { 0x33 }
            assertEquals(padded, AesCbc.encrypt(key, iv, buf, 7, n), "length $n")
            assertContentEquals(jcaPadded(plain), buf.copyOfRange(7, 7 + padded), "length $n")
            assertContentEquals(AesCbc.encrypt(key, iv, plain), buf.copyOfRange(7, 7 + padded), "length $n")
            assertContentEquals(ByteArray(7) { 0x55 }, buf.copyOf(7), "bytes before, length $n")
            assertContentEquals(ByteArray(9) { 0x33 }, buf.copyOfRange(7 + padded, buf.size), "bytes after, length $n")
            assertEquals(n, AesCbc.decrypt(key, iv, buf, 7, padded))
            assertContentEquals(plain, buf.copyOfRange(7, 7 + n))
        }
    }

    @Test
    fun `in-place encryption of the NIST SP 800-38A F-2-5 plaintext starts with its ciphertext`() {
        val nistKey = PrimitiveVectors.NIST_KEY.hexToByteArray()
        val nistIv = PrimitiveVectors.NIST_IV.hexToByteArray()
        val buf = PrimitiveVectors.NIST_PLAINTEXT.hexToByteArray().copyOf(80)
        assertEquals(80, AesCbc.encrypt(nistKey, nistIv, buf, 0, 64))
        assertContentEquals(PrimitiveVectors.NIST_CIPHERTEXT.hexToByteArray(), buf.copyOf(64))
        // An aligned input gets a whole block of 16s, chained on the last ciphertext block.
        val last = ByteArray(16) { 16 }
        AesCbc.cbc(Cipher.ENCRYPT_MODE, nistKey, buf.copyOfRange(48, 64), last, 0, 16)
        assertContentEquals(last, buf.copyOfRange(64, 80))
    }

    @Test
    fun `in-place encryption without room for the padding, or with a wrong key or IV, writes nothing`() {
        for (n in listOf(0, 1, 15, 16, 17)) {
            val buf = Random(n).nextBytes(AesCbc.paddedLength(n) - 1)
            val before = buf.copyOf()
            assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { AesCbc.encrypt(key, iv, buf, 0, n) }.field, "length $n")
            assertContentEquals(before, buf, "length $n")
        }
        val buf = Random(9).nextBytes(32)
        val before = buf.copyOf()
        assertEquals(KdbxException.Field.KEY, assertThrows<KdbxException.InvalidLength> { AesCbc.encrypt(ByteArray(16), iv, buf, 0, 5) }.field)
        assertEquals(KdbxException.Field.IV, assertThrows<KdbxException.InvalidLength> { AesCbc.encrypt(key, ByteArray(12), buf, 0, 5) }.field)
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { AesCbc.encrypt(key, iv, buf, -1, 5) }.field)
        assertEquals(KdbxException.Field.RANGE, assertThrows<KdbxException.InvalidLength> { AesCbc.encrypt(key, iv, buf, 30, 5) }.field)
        assertContentEquals(before, buf)
    }

    @Test
    fun `in-place encryption of a KeePass 2 file's payload gives the ciphertext KeePass 2 wrote`() {
        val bytes = Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx")
        val opened = KdbxToolkit.open(bytes, KdbxToolkit.Key(TestFiles.password))
        val header = RawKdbx.parse(bytes)
        val cipherKey = KdbxToolkit.sha256(header.field(RawKdbx.MASTER_SEED) + opened.transformedKey)
        val payload = opened.compressedBytes!!
        val buf = payload.copyOf(AesCbc.paddedLength(payload.size))
        assertEquals(opened.ciphertext.size, AesCbc.encrypt(cipherKey, header.field(RawKdbx.ENCRYPTION_IV), buf, 0, payload.size))
        assertContentEquals(opened.ciphertext, buf)
    }
}
