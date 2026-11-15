package org.onekash.kashpass.platform

import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.onekash.kashpass.testing.fakeKeyStore
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.SealResult
import org.onekash.kashpass.vault.storage.StoredKeyState
import org.onekash.kashpass.vault.storage.UnlockAvailability
import org.onekash.kashpass.vault.storage.UnsealResult
import org.robolectric.RobolectricTestRunner

// Robolectric has no AndroidKeyStore, which is what an app test building the real graph sees. The
// Keystore paths themselves are checked on the emulator.
@RunWith(RobolectricTestRunner::class)
class KeystoreUnlockKeyStoreTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val loc = "content://fake/vault.kdbx"

    @Test
    fun `without the Keystore provider nothing throws and nothing is usable`() = runBlocking<Unit> {
        val dir = temp.newFolder("biometric")
        File(dir, "stray.bin").writeBytes(byteArrayOf(1))
        val store = KeystoreUnlockKeyStore(dir, availability = { UnlockAvailability.READY })
        assertEquals(UnlockAvailability.UNAVAILABLE, store.availability())
        assertEquals(StoredKeyState.NONE, store.state(loc))
        val secret = ByteArray(32) { 1 }
        assertEquals(SealResult.Failed, store.seal(loc, secret) { Confirmation.Confirmed })
        assertEquals(List(32) { 0.toByte() }, secret.toList())
        assertEquals(UnsealResult.Missing, store.unseal(loc) { Confirmation.Confirmed })
        store.delete(loc)
    }

    @Test
    fun `creating the store touches nothing`() {
        var asked = 0
        KeystoreUnlockKeyStore(temp.newFolder("b"), availability = { UnlockAvailability.READY }, keyStore = { asked++; null })
        assertEquals(0, asked)
    }

    @Test
    fun `only a missing key reads as invalidated, a transient failure keeps the stored data`() {
        val dir = temp.newFolder("state")
        val hash = org.onekash.kashpass.vault.backup.Sha256.ofLocation(loc)
        File(dir, "$hash.bin").writeBytes(org.onekash.kashpass.vault.storage.SealedKey(ByteArray(12), ByteArray(48)).encode())
        val alias = "kashpass-unlock-$hash"
        fun state(keys: Map<String, java.security.Key>) =
            KeystoreUnlockKeyStore(dir, availability = { UnlockAvailability.READY }, keyStore = { fakeKeyStore(keys) }).state(loc)

        assertEquals(StoredKeyState.STORED, state(mapOf(alias to javax.crypto.spec.SecretKeySpec(ByteArray(32), "AES"))))
        assertEquals(StoredKeyState.INVALIDATED, state(emptyMap()))
        // A key the cipher refuses (as a locked phone's would be) isn't a reason to delete it.
        assertEquals(StoredKeyState.STORED, state(mapOf(alias to javax.crypto.spec.SecretKeySpec(ByteArray(32), "HmacSHA256"))))
    }

    @Test
    fun `a key the Keystore can't recover reads as unrecoverable, other load failures keep it`() = runBlocking<Unit> {
        val dir = temp.newFolder("unrecoverable")
        val hash = org.onekash.kashpass.vault.backup.Sha256.ofLocation(loc)
        File(dir, "$hash.bin").writeBytes(org.onekash.kashpass.vault.storage.SealedKey(ByteArray(12), ByteArray(48)).encode())
        val alias = "kashpass-unlock-$hash"
        val keys = mapOf(alias to javax.crypto.spec.SecretKeySpec(ByteArray(32), "AES"))
        fun store(failure: Exception) =
            KeystoreUnlockKeyStore(dir, availability = { UnlockAvailability.READY }, keyStore = { fakeKeyStore(keys, failure) })
        var prompts = 0
        val count: suspend (org.onekash.kashpass.vault.storage.CryptoHandle) -> Confirmation = { prompts++; Confirmation.Confirmed }

        val unrecoverable = java.security.UnrecoverableKeyException("key blob unreadable")
        assertEquals(StoredKeyState.UNRECOVERABLE, store(unrecoverable).state(loc))
        assertEquals(UnsealResult.Unrecoverable, store(unrecoverable).unseal(loc, count))

        for (other in listOf(java.security.NoSuchAlgorithmException("busy"), java.security.ProviderException("busy"))) {
            assertEquals(StoredKeyState.STORED, store(other).state(loc))
            assertEquals(UnsealResult.Failed, store(other).unseal(loc, count))
        }
        // No prompt runs for a key that didn't load, and the stored file stays for the caller.
        assertEquals(0, prompts)
        assertEquals(true, File(dir, "$hash.bin").isFile)
    }
}
