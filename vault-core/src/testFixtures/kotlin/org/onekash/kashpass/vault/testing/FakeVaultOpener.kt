package org.onekash.kashpass.vault.testing

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.open.LastCopyReason
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.RefreshResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.open.VaultOpening
import org.onekash.kashpass.vault.open.VaultSession

/**
 * Shared fake of [VaultOpening] for app tests. [check] returns [checkResult]; [open] returns
 * [openResult] when set, otherwise unlocks a real [TestVaults] vault through the real opener: with
 * no key file the vault of [TestVaults.PASSWORD], with a key file and an empty password the vault
 * of [TestVaults.KEY_FILE] alone, with both the vault of [TestVaults.PASSWORD] and
 * [TestVaults.KEY_FILE]. [openWithKey] unlocks the password vaults with the passphrase hash, so the
 * session's origin is STORED_KEY or STORED_KEY_AND_KEY_FILE. Like the real opener it zero-fills
 * the password, key and key-file arrays on every path, and the test-vault path unlocks on
 * [dispatcher] instead of the caller's thread. [dismissed] records every dismissal of the weak
 * warning. [hold] holds check, refresh, reopen and the session [openBackup], and [holdUnlock] the
 * unlocks; each counts the calls cancelled while held. Refresh and backups return scripted
 * results; [reopen] and the session [openBackup] reopen the test vault with the session's
 * credentials, keeping its origin; the password [openBackup] opens the test vault read-only by
 * default. Each call's [FileAccess] is passed to the real opener and recorded in [accesses].
 */
class FakeVaultOpener(private val dispatcher: CoroutineDispatcher = Dispatchers.Default) : VaultOpening {

    private val storage = FakeVaultStorage()
    private val state = FakeVaultStateStore()
    private val backupStore = FakeBackupStore()
    private val real = VaultOpener.create(storage, state, dispatcher, backupStore)

    /** What [refresh] returns for a session. */
    var refreshResult: (VaultSession) -> RefreshResult = { RefreshResult.Unchanged }

    /** What [reopen] returns; by default the test vault unlocked again. */
    var reopenResult: (() -> OpenResult)? = null

    /** What [backups] lists. */
    var backupList: List<BackupInfo> = emptyList()

    private var gate: CompletableDeferred<Unit>? = null

    /**
     * Makes the next check, refresh, reopen and session [openBackup] calls suspend until [release]
     * or until their caller is cancelled ([cancelledHeld]).
     */
    fun hold() {
        gate = CompletableDeferred()
    }

    /** The check, refresh, reopen and session [openBackup] calls cancelled while held. */
    var cancelledHeld = 0
        private set

    private suspend fun awaitGate() = awaitOrCount(gate) { cancelledHeld++ }

    /** Lets held check, refresh, reopen and session [openBackup] calls finish. */
    fun release() {
        gate?.complete(Unit)
        gate = null
    }

    private var unlockGate: CompletableDeferred<Unit>? = null

    /**
     * Makes the next open, openWithKey and password openBackup calls suspend until
     * [releaseUnlock] or until their caller is cancelled, as a long key derivation does.
     */
    fun holdUnlock() {
        unlockGate = CompletableDeferred()
    }

    /** Lets held open, openWithKey and password openBackup calls finish. */
    fun releaseUnlock() {
        unlockGate?.complete(Unit)
        unlockGate = null
    }

    /** The open, openWithKey and password openBackup calls cancelled while held. */
    var cancelledUnlocks = 0
        private set

    private suspend fun awaitUnlockGate() = awaitOrCount(unlockGate) { cancelledUnlocks++ }

    // Waits for [held] when set; a cancel while waiting is counted and rethrown.
    private suspend fun awaitOrCount(held: CompletableDeferred<Unit>?, counted: () -> Unit) {
        try {
            held?.await()
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            counted()
            throw e
        }
    }

    /** Every openWithKey, refresh, reopen and openBackup call, by name. */
    val calls = mutableListOf<String>()

    var checkResult: OpenResult = OpenResult.Ready(KdfSettings.AesKdf(600_000UL), weak = false)

    /** When set, [open] returns its result instead of unlocking the test vault. */
    var openResult: ((password: String) -> OpenResult)? = null

    var checks = 0
        private set
    var opens = 0
        private set

    /** Dismissals recorded by [dismissWeakWarning]. */
    val dismissed = mutableListOf<Pair<String, KdfSettings>>()

    /** Password arrays passed to [open], kept to assert they were zero-filled. */
    val passwordArrays = mutableListOf<CharArray>()

    /** The access of each check, open, openWithKey and password openBackup call, in order. */
    val accesses = mutableListOf<FileAccess>()

    /** The location of each check, open and openWithKey call, in order. */
    val locations = mutableListOf<String>()

    override suspend fun check(location: String, access: FileAccess): OpenResult {
        checks++
        accesses += access
        locations += location
        awaitGate()
        return checkResult
    }

    /** The acceptedSlow argument of each [open] and password [openBackup] call, in order. */
    val acceptedSlow = mutableListOf<KdfSettings?>()

    override suspend fun open(location: String, password: CharArray, acceptedSlow: KdfSettings?, keyFile: ByteArray?, access: FileAccess): OpenResult {
        opens++
        accesses += access
        locations += location
        this.acceptedSlow += acceptedSlow
        passwordArrays += password
        val text = String(password)
        return try {
            awaitUnlockGate()
            openResult?.invoke(text) ?: run {
                storage.put(LOCATION, vaultFor(text, keyFile))
                real.open(LOCATION, text.toCharArray(), keyFile = keyFile?.copyOf(), access = access)
            }
        } finally {
            password.fill('\u0000')
            keyFile?.fill(0)
        }
    }

    /** What [openWithKey] returns instead of unlocking the test vault, when set. */
    var keyResult: (() -> OpenResult)? = null

    override suspend fun openWithKey(location: String, key: ByteArray, acceptedSlow: KdfSettings?, keyFile: ByteArray?, access: FileAccess): OpenResult {
        calls += "openWithKey"
        accesses += access
        locations += location
        try {
            awaitUnlockGate()
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            key.fill(0)
            keyFile?.fill(0)
            throw e
        }
        val result = keyResult
        if (result != null) {
            key.fill(0)
            keyFile?.fill(0)
            return result()
        }
        storage.put(LOCATION, if (keyFile == null) testVault else keyFileVault)
        return real.openWithKey(LOCATION, key, keyFile = keyFile, access = access)
    }

    override suspend fun dismissWeakWarning(location: String, kdf: KdfSettings) {
        dismissed += location to kdf
        real.dismissWeakWarning(LOCATION, kdf)
    }

    override suspend fun refresh(location: String, session: VaultSession): RefreshResult {
        calls += "refresh"
        // As the real opener: a released session fails the call.
        check(session.isOpen) { "session released" }
        awaitGate()
        return refreshResult(session)
    }

    override suspend fun reopen(location: String, session: VaultSession): OpenResult {
        calls += "reopen"
        awaitGate()
        reopenResult?.let { return it() }
        storage.put(LOCATION, vaultFor(session.opened.origin))
        return real.reopen(LOCATION, session)
    }

    /** Times passed to [acceptNewest], in order. */
    val accepted = mutableListOf<java.time.Instant>()

    override suspend fun acceptNewest(location: String, time: java.time.Instant) {
        accepted += time
    }

    override suspend fun backups(location: String): List<BackupInfo> = backupList

    /** What [openBackup] returns instead of opening the test vault, when set. */
    var backupResult: OpenResult? = null

    /** When set, gives the session [openBackup]'s result, ahead of [backupResult]. */
    var backupFor: ((VaultSession) -> OpenResult)? = null

    override suspend fun openBackup(
        location: String,
        backup: BackupInfo,
        password: CharArray,
        lastCopy: LastCopyReason?,
        acceptedSlow: KdfSettings?,
        keyFile: ByteArray?,
        access: FileAccess,
    ): OpenResult {
        calls += "openBackup"
        accesses += access
        this.acceptedSlow += acceptedSlow
        val text = String(password)
        password.fill('\u0000')
        try {
            awaitUnlockGate()
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            keyFile?.fill(0)
            throw e
        }
        backupResult?.let {
            keyFile?.fill(0)
            return it
        }
        return real.openBackup(LOCATION, keep(vaultFor(text, keyFile)), text.toCharArray(), lastCopy, keyFile = keyFile, access = access)
    }

    override suspend fun openBackup(location: String, backup: BackupInfo, session: VaultSession): OpenResult {
        calls += "openBackup"
        check(session.isOpen) { "session released" }
        awaitGate()
        backupFor?.let { return it(session) }
        backupResult?.let { return it }
        return real.openBackup(LOCATION, keep(vaultFor(session.opened.origin)), session)
    }

    // Stores [vault] at the test location and as a backup, and returns the backup's info.
    private suspend fun keep(vault: ByteArray): BackupInfo {
        storage.put(LOCATION, vault)
        return (backupStore.add(LOCATION, vault, BackupKind.OPENED) as? BackupResult.Added)?.info
            ?: backupStore.list(LOCATION).first { it.sha256 == Sha256.hex(vault) }
    }

    private fun vaultFor(password: String, keyFile: ByteArray?) = when {
        keyFile == null -> testVault
        password.isEmpty() -> keyFileOnlyVault
        else -> keyFileVault
    }

    private fun vaultFor(origin: UnlockOrigin) = when (origin) {
        UnlockOrigin.PASSWORD, UnlockOrigin.STORED_KEY -> testVault
        UnlockOrigin.PASSWORD_AND_KEY_FILE, UnlockOrigin.STORED_KEY_AND_KEY_FILE -> keyFileVault
        UnlockOrigin.KEY_FILE_ONLY -> keyFileOnlyVault
    }

    private companion object {
        const val LOCATION = "content://fake/test.kdbx"

        // Generated once per test JVM; encoding runs the KDF, which is slow to repeat.
        val testVault: ByteArray by lazy { TestVaults.bytes() }
        val keyFileVault: ByteArray by lazy { TestVaults.bytes(keyPart = TestVaults.KEY_FILE_PART) }
        val keyFileOnlyVault: ByteArray by lazy { TestVaults.bytes(password = null, keyPart = TestVaults.KEY_FILE_PART) }
    }
}
