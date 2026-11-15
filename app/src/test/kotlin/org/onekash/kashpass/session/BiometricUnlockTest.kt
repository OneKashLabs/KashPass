package org.onekash.kashpass.session

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.storage.KeyFileRead
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.StoredKeyState
import org.onekash.kashpass.vault.storage.UnlockAvailability
import org.onekash.kashpass.vault.testing.FakeUnlockKeyStore
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.TestVaults

class BiometricUnlockTest {

    private val loc = TestVaults.LOCATION
    private val keys = FakeUnlockKeyStore()
    private val opener = FakeVaultOpener()
    private val state = FakeVaultStateStore()
    private val sessions = SessionHolder()
    private val biometric = BiometricUnlock(keys, opener, state, sessions)

    private fun unlocked(): Unlocked = runBlocking {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        Unlocked(loc, opened.session, opened.kdf, false).also(sessions::set)
    }

    private val yes: suspend (org.onekash.kashpass.vault.storage.CryptoHandle) -> Confirmation = { Confirmation.Confirmed }

    @Test
    fun `the offer shows for a file session on a ready phone once, never for a backup`() {
        val u = unlocked()
        assertTrue(biometric.offerVisible(u))
        biometric.markOfferShown(loc)
        assertFalse(biometric.offerVisible(u))
        state.resetBiometricOffer(loc)
        keys.available = UnlockAvailability.NONE_ENROLLED
        assertFalse(biometric.offerVisible(u))
        keys.available = UnlockAvailability.READY
        val backup = org.onekash.kashpass.vault.backup.BackupInfo("b", java.time.Instant.now(), 1, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0")
        assertFalse(biometric.offerVisible(u.withSession(u.session, backup = backup)))
    }

    @Test
    fun `turning on seals the session's key after the prompt, and Cancel stores nothing`() = runBlocking<Unit> {
        val u = unlocked()
        assertEquals(EnableResult.NotEnabled(Confirmation.Cancelled), biometric.enable(u) { Confirmation.Cancelled })
        assertEquals(StoredKeyState.NONE, keys.state(loc))
        assertEquals(EnableResult.Enabled, biometric.enable(u, yes))
        assertTrue(keys.stored(loc)!!.contentEquals(u.session.unlockKey()!!))
        assertEquals(BiometricStatus.On, biometric.status(loc))
        assertTrue(state.biometricOfferShown(loc))
        biometric.disable(loc)
        assertEquals(BiometricStatus.Off, biometric.status(loc))
    }

    @Test
    fun `a session-only file gets no offer, no seal and no prompt`() = runBlocking<Unit> {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL), access = FileAccess.SESSION_ONLY)
        val u = Unlocked(loc, opened.session, opened.kdf, false, sessionName = "Shared.kdbx").also(sessions::set)
        assertFalse(biometric.offerVisible(u))
        assertFalse(biometric.canSeal(u))
        var prompts = 0
        assertEquals(EnableResult.NotEnabled(Confirmation.Cancelled), biometric.enable(u) { prompts++; Confirmation.Confirmed })
        assertEquals(0, prompts)
        assertEquals(StoredKeyState.NONE, keys.state(loc))
        assertFalse(state.biometricOfferShown(loc))
    }

    @Test
    fun `a read-only remembered vault stays read-only after biometric unlock`() = runBlocking<Unit> {
        val u = unlocked()
        biometric.enable(u, yes)
        val result = biometric.unlock(loc, { KeyFileRead.None }, FileAccess.PROVIDER_READ_ONLY, yes)
        val opened = (result as BiometricResult.Opened).opened
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.PROVIDER_READ_ONLY), opened.session.saveability)
        assertEquals(FileAccess.PROVIDER_READ_ONLY, opener.accesses.last())
    }

    @Test
    fun `a key-file-only session is never sealed and shows no prompt`() = runBlocking<Unit> {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL, password = null, keyPart = TestVaults.KEY_FILE_PART)
        val opened = TestVaults.unlock(bytes, password = "", keyFile = TestVaults.KEY_FILE)
        val u = Unlocked(loc, opened.session, opened.kdf, false).also(sessions::set)
        var prompts = 0
        assertEquals(EnableResult.NotEnabled(Confirmation.Cancelled), biometric.enable(u) { prompts++; Confirmation.Confirmed })
        assertEquals(0, prompts)
        assertEquals(StoredKeyState.NONE, keys.state(loc))
    }

    @Test
    fun `a lock while the turn-on prompt shows stores nothing`() = runBlocking<Unit> {
        val u = unlocked()
        val result = biometric.enable(u) {
            sessions.lock()
            Confirmation.Confirmed
        }
        assertEquals(EnableResult.NotEnabled(Confirmation.Interrupted), result)
        assertEquals(StoredKeyState.NONE, keys.state(loc))
    }

    @Test
    fun `a lockout while turning on stores nothing and leaves the offer unchanged`() = runBlocking<Unit> {
        val u = unlocked()
        assertEquals(EnableResult.NotEnabled(Confirmation.LockedOut), biometric.enable(u) { Confirmation.LockedOut })
        assertEquals(StoredKeyState.NONE, keys.state(loc))
    }

    @Test
    fun `unlocking opens with the stored key through the opener`() = runBlocking<Unit> {
        biometric.enable(unlocked(), yes)
        sessions.lock()
        val result = biometric.unlock(loc, confirm = yes)
        assertTrue(result is BiometricResult.Opened)
        assertEquals(listOf("openWithKey"), opener.calls.filter { it == "openWithKey" })
    }

    @Test
    fun `Cancel, Use password, an interruption and a failure keep the stored key`() = runBlocking<Unit> {
        biometric.enable(unlocked(), yes)
        assertEquals(BiometricResult.Cancelled, biometric.unlock(loc) { Confirmation.Cancelled })
        assertEquals(BiometricResult.UsePassword, biometric.unlock(loc) { Confirmation.UsePassword })
        assertEquals(BiometricResult.Interrupted, biometric.unlock(loc) { Confirmation.Interrupted })
        assertEquals(BiometricResult.Failed, biometric.unlock(loc) { Confirmation.Failed })
        assertEquals(StoredKeyState.STORED, keys.state(loc))
    }

    @Test
    fun `each reason to turn off deletes the key and lets the offer show again`() = runBlocking<Unit> {
        val u = unlocked()
        suspend fun on() { biometric.enable(u, yes); assertTrue(state.biometricOfferShown(loc)) }

        on(); keys.invalidate(loc)
        assertEquals(BiometricResult.TurnedOff(TurnOffReason.NEW_BIOMETRIC), biometric.unlock(loc, confirm = yes))
        assertEquals(StoredKeyState.NONE, keys.state(loc)); assertFalse(state.biometricOfferShown(loc))

        on()
        assertEquals(BiometricResult.TurnedOff(TurnOffReason.LOCKED_OUT), biometric.unlock(loc) { Confirmation.LockedOut })
        assertEquals(StoredKeyState.NONE, keys.state(loc)); assertFalse(state.biometricOfferShown(loc))

        on(); opener.keyResult = { OpenResult.WrongPassword }
        assertEquals(BiometricResult.TurnedOff(TurnOffReason.PASSWORD_CHANGED), biometric.unlock(loc, confirm = yes))
        assertEquals(StoredKeyState.NONE, keys.state(loc))
        opener.keyResult = null

        on(); keys.invalidate(loc); keys.available = UnlockAvailability.NO_SCREEN_LOCK
        assertEquals(BiometricResult.TurnedOff(TurnOffReason.SCREEN_LOCK_REMOVED), biometric.unlock(loc, confirm = yes))
        assertEquals(StoredKeyState.NONE, keys.state(loc))

        keys.available = UnlockAvailability.READY
        on(); keys.invalidate(loc); keys.available = UnlockAvailability.NONE_ENROLLED
        assertEquals(BiometricResult.TurnedOff(TurnOffReason.BIOMETRICS_REMOVED), biometric.unlock(loc, confirm = yes))
        assertEquals(StoredKeyState.NONE, keys.state(loc))
    }

    @Test
    fun `other open results pass through and keep the key`() = runBlocking<Unit> {
        biometric.enable(unlocked(), yes)
        opener.keyResult = { OpenResult.Unreadable(org.onekash.kashpass.vault.storage.StorageFailure.TIMED_OUT) }
        assertTrue(biometric.unlock(loc, confirm = yes) is BiometricResult.NotOpened)
        assertEquals(StoredKeyState.STORED, keys.state(loc))
    }

    @Test
    fun `only one prompt at a time`() = runBlocking<Unit> {
        biometric.enable(unlocked(), yes)
        val gate = CompletableDeferred<Confirmation>()
        val first = async(start = CoroutineStart.UNDISPATCHED) { biometric.unlock(loc) { gate.await() } }
        assertEquals(BiometricResult.Busy, biometric.unlock(loc, confirm = yes))
        assertEquals(EnableResult.Busy, biometric.enable(unlocked(), yes))
        gate.complete(Confirmation.Cancelled)
        assertEquals(BiometricResult.Cancelled, first.await())
    }

    @Test
    fun `an unusable key is noticed without a prompt and turned off once`() = runBlocking<Unit> {
        biometric.enable(unlocked(), yes)
        assertEquals(null, biometric.reconcile(loc))
        keys.invalidate(loc)
        assertEquals(TurnOffReason.NEW_BIOMETRIC, biometric.reconcile(loc))
        assertEquals(StoredKeyState.NONE, keys.state(loc))
        assertEquals(null, biometric.reconcile(loc))
    }

    @Test
    fun `stored data that doesn't open after the prompt turns the feature off`() = runBlocking<Unit> {
        biometric.enable(unlocked(), yes)
        keys.damage(loc)
        assertEquals(BiometricResult.TurnedOff(TurnOffReason.DAMAGED), biometric.unlock(loc, confirm = yes))
        assertEquals(StoredKeyState.NONE, keys.state(loc))
        assertFalse(state.biometricOfferShown(loc))
        // Turning on again starts clean.
        keys.damage(loc)
        biometric.enable(unlocked(), yes)
        assertTrue(biometric.unlock(loc, confirm = yes) is BiometricResult.Opened)
    }

    @Test
    fun `a stored hash that isn't the vault's reads as a changed password`() = runBlocking<Unit> {
        val u = unlocked()
        keys.seal(loc, ByteArray(32) { 7 }, yes)
        assertEquals(BiometricResult.TurnedOff(TurnOffReason.PASSWORD_CHANGED), biometric.unlock(loc, confirm = yes))
        assertEquals(StoredKeyState.NONE, keys.state(loc))
        // The real hash opens.
        biometric.enable(u, yes)
        assertTrue(biometric.unlock(loc, confirm = yes) is BiometricResult.Opened)
    }

    @Test
    fun `an interrupted or failed turn-on stores nothing and leaves the offer unshown`() = runBlocking<Unit> {
        val u = unlocked()
        assertEquals(EnableResult.NotEnabled(Confirmation.Interrupted), biometric.enable(u) { Confirmation.Interrupted })
        assertEquals(EnableResult.NotEnabled(Confirmation.Failed), biometric.enable(u) { Confirmation.Failed })
        assertEquals(StoredKeyState.NONE, keys.state(loc))
        assertFalse(state.biometricOfferShown(loc))
    }

    @Test
    fun `a key the Keystore can't recover turns the feature off on the lock screen and on unlock`() = runBlocking<Unit> {
        biometric.enable(unlocked(), yes)
        keys.unrecoverable(loc)
        assertEquals(TurnOffReason.UNRECOVERABLE_KEY, biometric.reconcile(loc))
        assertEquals(StoredKeyState.NONE, keys.state(loc))
        assertFalse(state.biometricOfferShown(loc))
        assertEquals(null, biometric.reconcile(loc))

        biometric.enable(unlocked(), yes)
        keys.unrecoverable(loc)
        assertEquals(BiometricResult.TurnedOff(TurnOffReason.UNRECOVERABLE_KEY), biometric.unlock(loc, confirm = yes))
        assertEquals(null, keys.stored(loc))
        assertFalse(state.biometricOfferShown(loc))
    }

    private val passwordHash: ByteArray
        get() = java.security.MessageDigest.getInstance("SHA-256").digest(TestVaults.PASSWORD.toByteArray(Charsets.UTF_8))

    private val keyFileArrays = mutableListOf<ByteArray>()
    private var keyFileReads = 0

    private val keyFile: suspend () -> KeyFileRead = {
        keyFileReads++
        KeyFileRead.Bytes(TestVaults.KEY_FILE.also { keyFileArrays += it })
    }

    private fun keyFileOnlySession(): Unlocked = runBlocking {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL, password = null, keyPart = TestVaults.KEY_FILE_PART)
        val opened = TestVaults.unlock(bytes, password = "", keyFile = TestVaults.KEY_FILE)
        Unlocked(loc, opened.session, opened.kdf, false).also(sessions::set)
    }

    @Test
    fun `the key file is read again for each fingerprint unlock and its bytes are zero-filled`() = runBlocking<Unit> {
        keys.seal(loc, passwordHash, yes)
        val first = biometric.unlock(loc, keyFile, confirm = yes) as BiometricResult.Opened
        assertEquals(UnlockOrigin.STORED_KEY_AND_KEY_FILE, first.opened.session.opened.origin)
        assertTrue(biometric.unlock(loc, keyFile, confirm = yes) is BiometricResult.Opened)
        assertEquals(2, keyFileReads)
        assertTrue(keyFileArrays.all { bytes -> bytes.all { it == 0.toByte() } })
        // A cancelled prompt zero-fills the bytes read for it.
        assertEquals(BiometricResult.Cancelled, biometric.unlock(loc, keyFile) { Confirmation.Cancelled })
        assertTrue(keyFileArrays.all { bytes -> bytes.all { it == 0.toByte() } })
    }

    @Test
    fun `a key file that can't be read stops before the prompt and keeps the stored key`() = runBlocking<Unit> {
        keys.seal(loc, passwordHash, yes)
        var prompts = 0
        for (read in listOf(KeyFileRead.Failed(StorageFailure.NOT_FOUND), KeyFileRead.KeePassVault)) {
            assertEquals(BiometricResult.KeyFileUnreadable(read), biometric.unlock(loc, { read }) { prompts++; Confirmation.Confirmed })
        }
        assertEquals(0, prompts)
        assertEquals(emptyList<String>(), opener.calls.filter { it == "openWithKey" })
        assertEquals(StoredKeyState.STORED, keys.state(loc))
    }

    @Test
    fun `a wrong result with a key file keeps the stored hash and doesn't claim the password changed`() = runBlocking<Unit> {
        keys.seal(loc, passwordHash, yes)
        state.saveBiometricOfferShown(loc)
        opener.keyResult = { OpenResult.WrongPassword }
        assertEquals(BiometricResult.KeyFileMismatch, biometric.unlock(loc, keyFile, confirm = yes))
        assertEquals(StoredKeyState.STORED, keys.state(loc))
        assertTrue(state.biometricOfferShown(loc))
        // Without a key file the same result means the password changed.
        assertEquals(BiometricResult.TurnedOff(TurnOffReason.PASSWORD_CHANGED), biometric.unlock(loc, confirm = yes))
    }

    @Test
    fun `a key-file-only session can't be sealed, so the offer never shows for it`() {
        val u = keyFileOnlySession()
        assertFalse(biometric.canSeal(u))
        assertFalse(biometric.offerVisible(u))
        assertTrue(biometric.canSeal(unlocked()))
    }

    private fun passwordAndKeyFileSession(): Unlocked = runBlocking {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL, keyPart = TestVaults.KEY_FILE_PART)
        val opened = TestVaults.unlock(bytes, keyFile = TestVaults.KEY_FILE)
        Unlocked(loc, opened.session, opened.kdf, false).also(sessions::set)
    }

    @Test
    fun `set up with a key file and given none, it requests the file with no prompt or derivation and keeps the key`() = runBlocking<Unit> {
        val u = passwordAndKeyFileSession()
        assertEquals(UnlockOrigin.PASSWORD_AND_KEY_FILE, u.session.opened.origin)
        assertEquals(EnableResult.Enabled, biometric.enable(u, yes))
        assertTrue(state.biometricNeedsKeyFile(loc))
        // The stored hash alone reads as a wrong password for this vault, like a changed password.
        opener.keyResult = { OpenResult.WrongPassword }
        var prompts = 0
        assertEquals(BiometricResult.KeyFileNeeded, biometric.unlock(loc) { prompts++; Confirmation.Confirmed })
        assertEquals(0, prompts)
        assertEquals(emptyList<String>(), opener.calls.filter { it == "openWithKey" })
        assertEquals(StoredKeyState.STORED, keys.state(loc))
        assertTrue(state.biometricOfferShown(loc))
        opener.keyResult = null
        val opened = biometric.unlock(loc, keyFile, confirm = yes) as BiometricResult.Opened
        assertEquals(UnlockOrigin.STORED_KEY_AND_KEY_FILE, opened.opened.session.opened.origin)
    }

    @Test
    fun `a key-file seal sets the key-file mark, and a password seal, a disable or a turn-off clears it`() = runBlocking<Unit> {
        val withKeyFile = passwordAndKeyFileSession()
        biometric.enable(withKeyFile, yes)
        assertTrue(state.biometricNeedsKeyFile(loc))
        biometric.enable(unlocked(), yes)
        assertFalse("a password-only seal replaces the key", state.biometricNeedsKeyFile(loc))
        biometric.enable(passwordAndKeyFileSession(), yes)
        biometric.disable(loc)
        assertFalse(state.biometricNeedsKeyFile(loc))
        biometric.enable(passwordAndKeyFileSession(), yes)
        keys.invalidate(loc)
        biometric.reconcile(loc)
        assertFalse(state.biometricNeedsKeyFile(loc))
        biometric.enable(passwordAndKeyFileSession(), yes)
        assertEquals(EnableResult.NotEnabled(Confirmation.Cancelled), biometric.enable(unlocked()) { Confirmation.Cancelled })
        assertFalse("a cancelled seal deletes the old key", state.biometricNeedsKeyFile(loc))
    }
}
