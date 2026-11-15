package org.onekash.kashpass.vault.open

import java.util.HexFormat
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.storage.AesGcm
import org.onekash.kashpass.vault.storage.SealedKey
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.TestVaults

/**
 * A biometric key stored by an earlier release unlocks: the sealed bytes, the 32-byte
 * passphrase hash they hold and the composite keys built from it are permanent formats. Every
 * constant here was computed outside KashPass (Python's hashlib and the cryptography package's
 * AESGCM), so a change in how KashPass encodes, hashes or combines the password fails this test.
 */
class StoredKeyCompatibilityTest {

    private val loc = "content://fake/vault.kdbx"

    private fun opener(bytes: ByteArray): VaultOpening {
        val storage = FakeVaultStorage().apply { put(loc, bytes) }
        return VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO)
    }

    private fun zeroed(b: ByteArray) = b.all { it == 0.toByte() }

    @Test
    fun `the fixture password is the published throwaway one these constants hash`() {
        assertEquals("kashpass-test", TestFiles.password)
    }

    @Test
    fun `a sealed key written by an earlier release opens to the passphrase hash`() {
        val sealed = assertIs<SealedKey>(SealedKey.decode(hex(SEALED)))
        val cipher = Cipher.getInstance(AesGcm.TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(ByteArray(32) { it.toByte() }, "AES"), GCMParameterSpec(AesGcm.TAG_BITS, sealed.iv))
        }
        assertContentEquals(hex(PASSWORD_HASH), AesGcm.open(cipher, sealed, loc))
    }

    @Test
    fun `the stored hash unlocks a password vault and hands out the same hash`() = runBlocking<Unit> {
        val opened = assertIs<OpenResult.Unlocked>(opener(Fixtures.bytes(PASSWORD_VAULT)).openWithKey(loc, hex(PASSWORD_HASH)))
        assertEquals(UnlockOrigin.STORED_KEY, opened.session.opened.origin)
        assertContentEquals(hex(PASSWORD_HASH), opened.session.unlockKey())
    }

    @Test
    fun `the stored hash and the key file unlock a password and key file vault`() = runBlocking<Unit> {
        val fixture = Fixtures.named(KEY_FILE_VAULT)
        val opener = opener(Fixtures.bytes(fixture.name))
        val opened = assertIs<OpenResult.Unlocked>(opener.openWithKey(loc, hex(PASSWORD_HASH), keyFile = Fixtures.bytes(fixture.keyFile!!)))
        assertEquals(UnlockOrigin.STORED_KEY_AND_KEY_FILE, opened.session.opened.origin)
        assertContentEquals(hex(PASSWORD_HASH), opened.session.unlockKey())
        assertEquals(OpenResult.WrongPassword, opener.openWithKey(loc, hex(PASSWORD_HASH)), "the hash alone is not the key")
    }

    @Test
    fun `a password session seals the same hash, with or without a key file, and a key file alone seals none`() = runBlocking<Unit> {
        val password = assertIs<OpenResult.Unlocked>(opener(Fixtures.bytes(PASSWORD_VAULT)).open(loc, TestFiles.password.toCharArray()))
        assertEquals(UnlockOrigin.PASSWORD, password.session.opened.origin)
        assertContentEquals(hex(PASSWORD_HASH), password.session.unlockKey())

        val keyed = Fixtures.named(KEY_FILE_VAULT)
        val both = assertIs<OpenResult.Unlocked>(
            opener(Fixtures.bytes(keyed.name)).open(loc, TestFiles.password.toCharArray(), keyFile = Fixtures.bytes(keyed.keyFile!!)),
        )
        assertEquals(UnlockOrigin.PASSWORD_AND_KEY_FILE, both.session.opened.origin)
        assertContentEquals(hex(PASSWORD_HASH), both.session.unlockKey())

        val only = Fixtures.named("keepass2-keyfile-only-v2.kdbx")
        val keyFileOnly = assertIs<OpenResult.Unlocked>(opener(Fixtures.bytes(only.name)).open(loc, CharArray(0), keyFile = Fixtures.bytes(only.keyFile!!)))
        assertEquals(UnlockOrigin.KEY_FILE_ONLY, keyFileOnly.session.opened.origin)
        assertNull(keyFileOnly.session.unlockKey())
    }

    @Test
    fun `a non-ASCII password and a lone surrogate hash as KeePass 2 encodes them`() = runBlocking<Unit> {
        for ((password, hash) in listOf("pässwörd €→😀" to NON_ASCII_HASH, "a\uD800" to LONE_SURROGATE_HASH)) {
            // The composite key of a password is SHA-256 of its hash, which is also the composite
            // key of a key-file part equal to that hash: the vault is keyed without encoding text.
            val vault = rekeyed(KdbxToolkit.Key(null, hex(hash)))
            val opened = assertIs<OpenResult.Unlocked>(opener(vault).open(loc, password.toCharArray()), password)
            assertContentEquals(hex(hash), opened.session.unlockKey(), password)
        }
    }

    @Test
    fun `a stored key that is not 32 bytes is a wrong password and is wiped`() = runBlocking<Unit> {
        val opener = opener(Fixtures.bytes(PASSWORD_VAULT))
        for (size in listOf(0, 31, 33, 64, 65)) {
            val key = hex(PASSWORD_HASH).copyOf(size).also { if (size > 32) it.fill(1, 32, size) }
            assertEquals(OpenResult.WrongPassword, opener.openWithKey(loc, key), "$size bytes")
            assertTrue(zeroed(key), "$size bytes")
        }
    }

    // The generated vault, keyed by [key] instead of the test password.
    private fun rekeyed(key: KdbxToolkit.Key): ByteArray {
        val layers = KdbxToolkit.open(TestVaults.bytes(aesRounds = 1_000UL), KdbxToolkit.Key(TestVaults.PASSWORD)).layers
        return KdbxToolkit.build(layers.copy(key = key))
    }

    private fun hex(s: String): ByteArray = HexFormat.of().parseHex(s)

    private companion object {
        const val PASSWORD_VAULT = "keepass2-weak-aeskdf-6000.kdbx"
        const val KEY_FILE_VAULT = "keepass2-password-keyfile-v2.kdbx"

        // SHA-256 of the UTF-8 bytes of "kashpass-test".
        const val PASSWORD_HASH = "c335301d1f795a105e1a52eecc010f187ec31cff7888cbefcfa043db5c660083"

        // SHA-256 of the UTF-8 bytes of "pässwörd €→😀".
        const val NON_ASCII_HASH = "34114f4f69d69d771a4ba379ea853c3581c9033933b9b6b646b3790040d8f2ad"

        // SHA-256 of 61 EF BF BD: "a" and U+FFFD, which .NET's UTF-8 encoder writes for a lone
        // surrogate.
        const val LONE_SURROGATE_HASH = "51d277510ba4bf97b25f12d38513c1b620a2a33fc83b3beeeb0dd971bf429e6d"

        // SealedKey version 1 of PASSWORD_HASH: AES-256-GCM under the key 00 01 .. 1F with the IV
        // 64 65 .. 6F and the SHA-256 of "content://fake/vault.kdbx" as associated data.
        const val SEALED = "010c6465666768696a6b6c6d6e6f8b2eee7b66900c8e60780d06166465e53c011af5f3e4389d6871ef93a7c5a5cb467" +
            "fd8e893a0873bb7717fd1c3dd06e2"
    }
}
