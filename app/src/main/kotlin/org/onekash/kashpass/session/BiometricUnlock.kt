package org.onekash.kashpass.session

import java.util.concurrent.atomic.AtomicBoolean
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpening
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.CryptoHandle
import org.onekash.kashpass.vault.storage.KeyFileRead
import org.onekash.kashpass.vault.storage.SealResult
import org.onekash.kashpass.vault.storage.StoredKeyState
import org.onekash.kashpass.vault.storage.UnlockAvailability
import org.onekash.kashpass.vault.storage.UnlockKeyStore
import org.onekash.kashpass.vault.storage.UnsealResult
import org.onekash.kashpass.vault.storage.VaultStateStore

/** Whether biometric unlock is on for a file. */
sealed interface BiometricStatus {
    data object On : BiometricStatus
    data object Off : BiometricStatus

    /** This phone can't use it now ([reason]). */
    data class Unavailable(val reason: UnlockAvailability) : BiometricStatus
}

/** Outcome of [BiometricUnlock.enable]. */
sealed interface EnableResult {
    data object Enabled : EnableResult
    data class NotEnabled(val confirmation: Confirmation) : EnableResult
    data object Failed : EnableResult

    /** Another prompt is showing. */
    data object Busy : EnableResult
}

/** Why KashPass turned biometric unlock off; the lock screen shows it once. */
enum class TurnOffReason {
    NEW_BIOMETRIC,
    LOCKED_OUT,
    PASSWORD_CHANGED,
    SCREEN_LOCK_REMOVED,
    BIOMETRICS_REMOVED,
    DAMAGED,

    /** The Keystore can't load the key. */
    UNRECOVERABLE_KEY,
}

/** Outcome of [BiometricUnlock.unlock]. */
sealed interface BiometricResult {
    class Opened(val opened: OpenResult.Unlocked) : BiometricResult
    data object Cancelled : BiometricResult
    data object UsePassword : BiometricResult

    /** The system ended the prompt (screen off, another app); the user didn't cancel it. */
    data object Interrupted : BiometricResult

    /** The prompt or the platform failed; the stored key is kept for another try. */
    data object Failed : BiometricResult

    /** Nothing is stored for the file. */
    data object NotStored : BiometricResult
    data object Busy : BiometricResult
    data class TurnedOff(val reason: TurnOffReason) : BiometricResult

    /** The stored key was released but the file didn't open ([result]: slow, unreadable, ...). */
    data class NotOpened(val result: OpenResult) : BiometricResult

    /** The key file couldn't be used ([read]); no prompt showed and the stored key is kept. */
    data class KeyFileUnreadable(val read: KeyFileRead) : BiometricResult

    /**
     * With a key file, the stored key and the key file didn't open the vault. The stored key is
     * kept: the key file can be the wrong one.
     */
    data object KeyFileMismatch : BiometricResult

    /**
     * The stored key was sealed with a key file and none was given: no prompt showed, nothing
     * was derived and the stored key is kept.
     */
    data object KeyFileNeeded : BiometricResult
}

/**
 * Runs biometric unlock for the remembered vault: seals the open session's passphrase hash
 * ([org.onekash.kashpass.vault.open.VaultSession.unlockKey]) in [keys] behind a strong biometric
 * check, and opens the file with it through every check a password open runs. Each reason to stop
 * ([TurnOffReason]) deletes the stored key and lets the offer card show again. One prompt
 * runs at a time. [BiometricUnlockTest] pins each path.
 */
class BiometricUnlock(
    private val keys: UnlockKeyStore,
    private val opener: VaultOpening,
    private val state: VaultStateStore,
    private val sessions: SessionHolder,
) {
    private val busy = AtomicBoolean(false)

    fun status(location: String): BiometricStatus {
        val availability = keys.availability()
        if (availability != UnlockAvailability.READY) return BiometricStatus.Unavailable(availability)
        return if (keys.state(location) == StoredKeyState.STORED) BiometricStatus.On else BiometricStatus.Off
    }

    /**
     * Returns true when [unlocked] has a password to seal for a file KashPass remembers: not a
     * vault opened with a key file alone, not a session-only file, and not a released session.
     */
    fun canSeal(unlocked: Unlocked): Boolean = try {
        !unlocked.sessionOnly && unlocked.session.opened.origin != UnlockOrigin.KEY_FILE_ONLY
    } catch (e: IllegalStateException) {
        false
    }

    /**
     * Returns true when the offer card shows for [unlocked]: the remembered file itself (not a
     * backup, not a session-only file) with a password to seal ([canSeal]) on a ready phone, not
     * yet offered.
     */
    fun offerVisible(unlocked: Unlocked): Boolean =
        unlocked.target == VaultTarget.REMEMBERED &&
            canSeal(unlocked) &&
            keys.availability() == UnlockAvailability.READY &&
            keys.state(unlocked.location) == StoredKeyState.NONE &&
            !state.biometricOfferShown(unlocked.location)

    /** Records that the offer was shown for [location]; it doesn't show again unless reset. */
    fun markOfferShown(location: String) = state.saveBiometricOfferShown(location)

    /**
     * Seals [unlocked]'s key after [confirm] passes. A lock while the prompt shows ends it as
     * [Confirmation.Interrupted] and stores nothing. A session-only file stores nothing and shows
     * no prompt.
     */
    suspend fun enable(unlocked: Unlocked, confirm: suspend (CryptoHandle) -> Confirmation): EnableResult = exclusive(EnableResult.Busy) {
        if (unlocked.sessionOnly) return@exclusive EnableResult.NotEnabled(Confirmation.Cancelled)
        val locks = sessions.lockCount
        val (key, origin) = try {
            // A key-file-only vault has no password to seal; no prompt shows.
            val key = unlocked.session.unlockKey() ?: return@exclusive EnableResult.NotEnabled(Confirmation.Cancelled)
            key to unlocked.session.opened.origin
        } catch (e: IllegalStateException) {
            return@exclusive EnableResult.Failed
        }
        // The store zero-fills the key on every path.
        val result = keys.seal(unlocked.location, key) { handle ->
            val c = confirm(handle)
            if (sessions.lockCount != locks) Confirmation.Interrupted else c
        }
        // A seal replaces the stored key whatever its outcome, so the mark is set again here.
        val withKeyFile = origin == UnlockOrigin.PASSWORD_AND_KEY_FILE || origin == UnlockOrigin.STORED_KEY_AND_KEY_FILE
        state.saveBiometricNeedsKeyFile(unlocked.location, result == SealResult.Sealed && withKeyFile)
        when (result) {
            SealResult.Sealed -> {
                markOfferShown(unlocked.location)
                EnableResult.Enabled
            }
            is SealResult.NotConfirmed -> EnableResult.NotEnabled(result.confirmation)
            SealResult.Failed -> EnableResult.Failed
        }
    }

    /**
     * Turns biometric unlock off for [location] when its key is unusable (a new biometric
     * enrolled, the screen lock removed, the Keystore can't load it) and returns why; null when
     * nothing changed. The lock screen runs it when it appears, so the reason shows before any
     * prompt.
     */
    fun reconcile(location: String): TurnOffReason? = when (keys.state(location)) {
        StoredKeyState.INVALIDATED -> turnOff(location, invalidatedReason()).reason
        StoredKeyState.UNRECOVERABLE -> turnOff(location, TurnOffReason.UNRECOVERABLE_KEY).reason
        StoredKeyState.NONE, StoredKeyState.STORED -> null
    }

    private fun invalidatedReason() = when (keys.availability()) {
        UnlockAvailability.NO_SCREEN_LOCK -> TurnOffReason.SCREEN_LOCK_REMOVED
        UnlockAvailability.NONE_ENROLLED -> TurnOffReason.BIOMETRICS_REMOVED
        else -> TurnOffReason.NEW_BIOMETRIC
    }

    /** Turns biometric unlock off for [location]; the password opens the file as before. */
    fun disable(location: String) = deleteKey(location)

    private fun deleteKey(location: String) {
        keys.delete(location)
        state.saveBiometricNeedsKeyFile(location, false)
    }

    /**
     * Opens [location] with its stored key after [confirm] passes, with [access] as the
     * remembered vault's grant allows (read and write by default). [keyFile] reads the vault's
     * key file before the prompt (none by default), on every call; a key file that can't be read
     * ends here as [BiometricResult.KeyFileUnreadable].
     * A key sealed with a key file and no key file given ends here as
     * [BiometricResult.KeyFileNeeded]: the stored hash alone would read as a changed password.
     * The key-file bytes are zero-filled on every path.
     */
    suspend fun unlock(
        location: String,
        keyFile: suspend () -> KeyFileRead = { KeyFileRead.None },
        access: FileAccess = FileAccess.READ_WRITE,
        confirm: suspend (CryptoHandle) -> Confirmation,
    ): BiometricResult = exclusive(BiometricResult.Busy) {
        val bytes = when (val read = keyFile()) {
            KeyFileRead.None -> if (state.biometricNeedsKeyFile(location)) return@exclusive BiometricResult.KeyFileNeeded else null
            is KeyFileRead.Bytes -> read.bytes
            is KeyFileRead.Failed, KeyFileRead.KeePassVault -> return@exclusive BiometricResult.KeyFileUnreadable(read)
        }
        try {
            unlockWith(location, confirm, bytes, access)
        } finally {
            bytes?.fill(0)
        }
    }

    private suspend fun unlockWith(location: String, confirm: suspend (CryptoHandle) -> Confirmation, keyFile: ByteArray?, access: FileAccess): BiometricResult =
        when (val unsealed = keys.unseal(location, confirm)) {
            UnsealResult.Missing -> BiometricResult.NotStored
            UnsealResult.Failed -> BiometricResult.Failed
            // The check passed but the stored data failed verification; a retry fails the same way.
            UnsealResult.Damaged -> turnOff(location, TurnOffReason.DAMAGED)
            UnsealResult.Invalidated -> turnOff(location, invalidatedReason())
            UnsealResult.Unrecoverable -> turnOff(location, TurnOffReason.UNRECOVERABLE_KEY)
            is UnsealResult.NotConfirmed -> when (unsealed.confirmation) {
                // Android has no attempt count, so a lockout other apps caused counts too.
                Confirmation.LockedOut -> turnOff(location, TurnOffReason.LOCKED_OUT)
                Confirmation.Cancelled -> BiometricResult.Cancelled
                Confirmation.UsePassword -> BiometricResult.UsePassword
                Confirmation.Interrupted -> BiometricResult.Interrupted
                // Confirmed never comes back as NotConfirmed; it reads as a failure if it did.
                Confirmation.Failed, Confirmation.Confirmed -> BiometricResult.Failed
            }
            is UnsealResult.Unsealed -> when (val opened = opener.openWithKey(location, unsealed.secret, keyFile = keyFile, access = access)) {
                is OpenResult.Unlocked -> BiometricResult.Opened(opened)
                // With a key file either part can be wrong, so the stored hash stays.
                OpenResult.WrongPassword -> if (keyFile != null) {
                    BiometricResult.KeyFileMismatch
                } else {
                    // The stored hash doesn't match: the password was changed on another device.
                    turnOff(location, TurnOffReason.PASSWORD_CHANGED)
                }
                else -> BiometricResult.NotOpened(opened)
            }
        }

    private fun turnOff(location: String, reason: TurnOffReason): BiometricResult.TurnedOff {
        deleteKey(location)
        state.resetBiometricOffer(location)
        return BiometricResult.TurnedOff(reason)
    }

    private inline fun <T> exclusive(busyResult: T, block: () -> T): T {
        if (!busy.compareAndSet(false, true)) return busyResult
        try {
            return block()
        } finally {
            busy.set(false)
        }
    }
}
