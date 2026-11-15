package org.onekash.kashpass.vault.doc

import java.util.HexFormat
import kotlin.test.assertContentEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.testing.KdbxToolkit

class VaultKeyTest {

    private fun hex(s: String): ByteArray = HexFormat.of().parseHex(s)

    private val part = ByteArray(32) { (it * 11 + 5).toByte() }

    @Test
    fun `a password hashes as KeePass 2 encodes it, the hashes StoredKeyCompatibilityTest pins`() {
        // SHA-256 of the UTF-8 bytes; a lone surrogate encodes as U+FFFD.
        val cases = mapOf(
            "kashpass-test" to "c335301d1f795a105e1a52eecc010f187ec31cff7888cbefcfa043db5c660083",
            "pässwörd €→😀" to "34114f4f69d69d771a4ba379ea853c3581c9033933b9b6b646b3790040d8f2ad",
            "a\uD800" to "51d277510ba4bf97b25f12d38513c1b620a2a33fc83b3beeeb0dd971bf429e6d",
        )
        for ((password, hash) in cases) {
            assertContentEquals(hex(hash), VaultKey.password(password.toCharArray()).passwordHash(), password)
        }
    }

    @Test
    fun `the password is zero-filled and the key keeps its own copies of the arrays it is given`() {
        val chars = "kashpass-test".toCharArray()
        val filePart = part.copyOf()
        val key = VaultKey.password(chars, filePart)
        assertTrue(chars.all { it == '\u0000' }, "password")
        filePart.fill(0)
        assertContentEquals(part, key.keyFilePart(), "the caller zero-filling its part leaves the key intact")
        val hash = ByteArray(32) { 7 }
        val stored = VaultKey.passwordHash(hash, null)
        hash.fill(0)
        assertContentEquals(ByteArray(32) { 7 }, stored.passwordHash())
    }

    @Test
    fun `the composite key is KeePass 2's for every way to unlock`() {
        val hash = VaultKey.password("kashpass-test".toCharArray()).passwordHash()!!
        // Password; password and key file; key file alone; empty password and key file.
        assertContentEquals(KdbxToolkit.Key("kashpass-test").composite(), VaultKey.password("kashpass-test".toCharArray()).compositeKey())
        assertContentEquals(KdbxToolkit.Key("kashpass-test", part).composite(), VaultKey.password("kashpass-test".toCharArray(), part.copyOf()).compositeKey())
        assertContentEquals(KdbxToolkit.Key(null, part).composite(), VaultKey.keyFile(part.copyOf()).compositeKey())
        assertContentEquals(KdbxToolkit.Key("", part).composite(), VaultKey.password(CharArray(0), part.copyOf()).compositeKey())
        // The stored passphrase hash, alone and with the key file's part.
        assertContentEquals(KdbxToolkit.Key("kashpass-test").composite(), VaultKey.passwordHash(hash.copyOf(), null).compositeKey())
        assertContentEquals(KdbxToolkit.Key("kashpass-test", part).composite(), VaultKey.passwordHash(hash.copyOf(), part.copyOf()).compositeKey())
    }

    @Test
    fun `a key-file-only key has no password hash and prints no content`() {
        val key = VaultKey.keyFile(part.copyOf())
        assertNull(key.passwordHash())
        assertContentEquals(part, key.keyFilePart())
        assertTrue(HexFormat.of().formatHex(part) !in key.toString().lowercase(), key.toString())
    }
}
