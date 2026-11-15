package org.onekash.kashpass.platform

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.header.Argon2Variant
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PrefsVaultStateStoreTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val argon = KdfSettings.Argon2(Argon2Variant.ARGON2ID, 2UL, 67_108_864UL, 2U, 0x13U)

    @Test
    fun `remembers the vault and its KDF state across instances`() {
        PrefsVaultStateStore(context).apply {
            saveVault(VAULT, "Passwords.kdbx")
            saveKdfBaseline(VAULT, argon)
            saveWeakWarningDismissed(VAULT, KdfSettings.AesKdf(6_000UL))
        }
        val again = PrefsVaultStateStore(context)
        assertEquals(RememberedVault(VAULT, "Passwords.kdbx"), again.vault())
        assertEquals(argon, again.kdfBaseline(VAULT))
        assertEquals(KdfSettings.AesKdf(6_000UL), again.weakWarningDismissedFor(VAULT))
    }

    @Test
    fun `state for another location is not returned`() {
        val store = PrefsVaultStateStore(context)
        store.saveKdfBaseline(VAULT, argon)
        assertNull(store.kdfBaseline("content://other"))
        assertNull(store.weakWarningDismissedFor("content://other"))
    }

    @Test
    fun `the biometric key-file mark is kept per location and survives clear, which keeps the stored key`() {
        val store = PrefsVaultStateStore(context)
        store.saveBiometricNeedsKeyFile(VAULT, true)
        assertEquals(true, PrefsVaultStateStore(context).biometricNeedsKeyFile(VAULT))
        assertFalse(store.biometricNeedsKeyFile("content://other"))
        store.clear(VAULT)
        assertEquals(true, store.biometricNeedsKeyFile(VAULT))
        store.saveBiometricNeedsKeyFile(VAULT, false)
        assertFalse(store.biometricNeedsKeyFile(VAULT))
    }

    @Test
    fun `the key-file unlock mark is kept per location, survives clear and can be removed`() {
        val store = PrefsVaultStateStore(context)
        store.saveKeyFileUnlock(VAULT, true)
        assertEquals(true, PrefsVaultStateStore(context).keyFileUnlock(VAULT))
        assertFalse(store.keyFileUnlock("content://other"))
        store.clear(VAULT)
        assertEquals(true, store.keyFileUnlock(VAULT))
        store.saveKeyFileUnlock(VAULT, false)
        assertFalse(store.keyFileUnlock(VAULT))
    }

    @Test
    fun `clear forgets the KDF state for that location`() {
        val store = PrefsVaultStateStore(context)
        store.saveKdfBaseline(VAULT, argon)
        store.saveWeakWarningDismissed(VAULT, argon)
        store.clear(VAULT)
        assertNull(store.kdfBaseline(VAULT))
        assertNull(store.weakWarningDismissedFor(VAULT))
    }

    @Test
    fun `the preferences file holds only the eleven non-secret keys`() {
        PrefsVaultStateStore(context).apply {
            saveVault(VAULT, "Passwords.kdbx", readOnly = true)
            saveKdfBaseline(VAULT, argon)
            saveWeakWarningDismissed(VAULT, argon)
            saveNewestSeen(VAULT, java.time.Instant.parse("2026-10-20T12:00:00Z"))
            saveBiometricOfferShown(VAULT)
            saveBackupKeep(5)
            saveKeyFile(VAULT, KEY_FILE, "vault.keyx")
            saveBiometricNeedsKeyFile(VAULT, true)
            saveKeyFileUnlock(VAULT, true)
        }
        val prefs = context.getSharedPreferences(PrefsVaultStateStore.FILE, Context.MODE_PRIVATE).all
        assertEquals(PrefsVaultStateStore.KEYS, prefs.keys)
        assertEquals(11, PrefsVaultStateStore.KEYS.size)
        for (value in prefs.values) assertFalse(value.toString().contains(TestVaults.PASSWORD))
    }

    private companion object {
        const val VAULT = "content://com.google.android.apps.docs.storage/document/acc%3D1%3Bdoc%3D9"
        const val KEY_FILE = "content://com.google.android.apps.docs.storage/document/acc%3D1%3Bdoc%3D12"
    }

    @Test
    fun `the newest change seen is remembered per location as a time only, and cleared with the rest`() {
        val time = java.time.Instant.parse("2026-10-20T12:34:56Z")
        PrefsVaultStateStore(context).saveNewestSeen(VAULT, time)
        val again = PrefsVaultStateStore(context)
        assertEquals(time, again.newestSeen(VAULT))
        assertEquals(null, again.newestSeen("content://other"))
        again.clear(VAULT)
        assertEquals(null, again.newestSeen(VAULT))
    }

    @Test
    fun `whether the fingerprint offer was shown is remembered per location and cleared with the rest`() {
        PrefsVaultStateStore(context).saveBiometricOfferShown(VAULT)
        val again = PrefsVaultStateStore(context)
        assertEquals(true, again.biometricOfferShown(VAULT))
        assertEquals(false, again.biometricOfferShown("content://other"))
        again.resetBiometricOffer(VAULT)
        assertEquals(false, again.biometricOfferShown(VAULT))
        again.saveBiometricOfferShown(VAULT)
        again.clear(VAULT)
        assertEquals(false, again.biometricOfferShown(VAULT))
    }

    @Test
    fun `the backup count is app-wide, unset reads null, it round-trips and clear keeps it`() {
        val store = PrefsVaultStateStore(context)
        assertEquals(null, store.backupKeep())
        store.saveBackupKeep(1)
        assertEquals(1, PrefsVaultStateStore(context).backupKeep())
        store.clear(VAULT)
        assertEquals(1, store.backupKeep())
    }

    @Test
    fun `the key file is remembered for its vault only, with its name, and clearing it forgets it`() {
        PrefsVaultStateStore(context).saveKeyFile(VAULT, KEY_FILE, "vault.keyx")
        val again = PrefsVaultStateStore(context)
        assertEquals(RememberedKeyFile(KEY_FILE, "vault.keyx"), again.keyFile(VAULT))
        assertNull(again.keyFile("content://other"))
        // Clearing the vault's KDF state when it is chosen again keeps its key file.
        again.clear(VAULT)
        assertEquals(RememberedKeyFile(KEY_FILE, "vault.keyx"), again.keyFile(VAULT))
        again.clearKeyFile()
        assertNull(again.keyFile(VAULT))
    }

    @Test
    fun `a read-only vault is remembered as read-only, and a vault saved without the flag reads writable`() {
        PrefsVaultStateStore(context).saveVault(VAULT, "Passwords.kdbx", readOnly = true)
        assertEquals(RememberedVault(VAULT, "Passwords.kdbx", readOnly = true), PrefsVaultStateStore(context).vault())
        PrefsVaultStateStore(context).saveVault(VAULT, "Passwords.kdbx")
        assertEquals(RememberedVault(VAULT, "Passwords.kdbx", readOnly = false), PrefsVaultStateStore(context).vault())
        // A vault remembered before the flag existed has no read-only key.
        context.getSharedPreferences(PrefsVaultStateStore.FILE, Context.MODE_PRIVATE).edit().remove("vault_read_only").commit()
        assertEquals(RememberedVault(VAULT, "Passwords.kdbx", readOnly = false), PrefsVaultStateStore(context).vault())
    }

    @Test
    fun `a stored key file entry that can't be read is ignored`() {
        context.getSharedPreferences(PrefsVaultStateStore.FILE, Context.MODE_PRIVATE).edit().putString("key_file", "no separators").commit()
        assertNull(PrefsVaultStateStore(context).keyFile(VAULT))
    }
}
