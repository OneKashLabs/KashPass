package org.onekash.kashpass.ui.lock

import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.doc.DecodeFailure
import org.onekash.kashpass.vault.header.UnsupportedReason
import org.onekash.kashpass.vault.open.LastCopyReason
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.session.TurnOffReason
import org.onekash.kashpass.vault.policy.SlowKdf
import org.onekash.kashpass.vault.storage.StorageFailure

/**
 * What the lock screen shows. [vaultName] is null before the first pick. The password field is
 * shown only when a password can help: after a passing check or a wrong password.
 */
data class LockUiState(
    val vaultName: String? = null,
    val checking: Boolean = false,
    val showPasswordField: Boolean = false,
    val unlocking: Boolean = false,
    val message: LockMessage? = null,
    /**
     * The last good copy, shown when the file is corrupted, can't be read or its header needs
     * more memory than the heap allows.
     */
    val lastCopy: LastCopy? = null,
    /** A save was cut off and the file doesn't hold its new bytes. */
    val lostCutOffSave: Boolean = false,
    /** The backup the password field opens (read-only) instead of the file, or null. */
    val backupTarget: BackupInfo? = null,
    /** Why [backupTarget] opens as a last copy; null for a plain backup. */
    val targetLastCopy: LastCopyReason? = null,
    /** Settings that take far longer than before; Unlock then accepts them ("Unlock anyway"). */
    val slow: SlowKdf? = null,
    /** Biometric unlock is on for this file, so the main button uses it. */
    val biometricOn: Boolean = false,
    /** The password field replaces the biometric button for this appearance. */
    val passwordChosen: Boolean = false,
    /** Why biometric unlock was turned off; the screen says it once. */
    val turnedOff: TurnOffReason? = null,
    /** Counts requests for the system prompt; the screen shows it when this changes. */
    val promptRequest: Int = 0,
    /** The last biometric attempt failed for a reason other than a cancel by the user. */
    val biometricFailed: Boolean = false,
    /** Counts requests to open the file picker from elsewhere (Settings' Open another vault). */
    val pickRequest: Int = 0,
    /** The display name of the vault's key file, or null when none is set. */
    val keyFileName: String? = null,
    /** [vaultName] is a file another app handed over; it opens read-only for this session. */
    val openedFromApp: Boolean = false,
    /**
     * The remembered vault's name while an [openedFromApp] file shows; null when none is
     * remembered.
     */
    val openedInPlaceOf: String? = null,
    /** [vaultName] is a file another app handed over; it shows until Open this file or Cancel. */
    val offered: Boolean = false,
    /** The remembered vault's name while an [offered] file shows; null when none is remembered. */
    val offeredInPlaceOf: String? = null,
    /**
     * Biometric unlock was set up with a key file and no key file chip shows; the screen says to
     * add the key file.
     */
    val keyFileNeeded: Boolean = false,
    /**
     * The last unlock of the remembered vault used a key file; with no chip, the wrong-password
     * error says to add the key file again.
     */
    val keyFileUnlockedBefore: Boolean = false,
) {
    /** True when the message is a problem with the file that Retry can resolve. */
    val canRetry: Boolean get() = message is LockMessage.Unreadable && message.cause != StorageFailure.TOO_LARGE
}

/** A backup offered in place of a file that can't be opened, and why. */
data class LastCopy(val backup: BackupInfo, val reason: LastCopyReason)

/** A problem shown on the lock screen; the screen turns it into text. */
sealed interface LockMessage {
    /** True for a problem with the key file, shown while a backup is the target too. */
    val isKeyFileProblem: Boolean
        get() = this is KeyFileUnreadable || this == KeyFileDamaged || this == NotKeyFile || this == KeyFileMismatch || this == KeyFileTooLarge

    /**
     * True when the file was refused before the password was used: KDF settings refused, or a
     * format KashPass doesn't open, except an inner stream the inner header names, which is read
     * after the key verified ([UnsupportedReason.InnerStream.keyChecked]).
     */
    val passwordUnused: Boolean
        get() = this is Refused || (this is Unsupported && !(reason is UnsupportedReason.InnerStream && reason.keyChecked))

    data object WrongPassword : LockMessage
    data object Damaged : LockMessage

    /**
     * Damaged after the header HMAC verified the key; the message points to KeePass 2's Repair Mode
     * import.
     */
    data object DamagedAfterHeader : LockMessage
    data object BackupDamaged : LockMessage
    data object NotEnoughMemory : LockMessage
    data object ChooseFailed : LockMessage
    data class Unsupported(val reason: UnsupportedReason) : LockMessage
    data class Refused(val rejection: KdfRejection) : LockMessage
    data class Unreadable(val cause: StorageFailure) : LockMessage

    /** Opening failed for a reason that is not the file's. */
    data class Failed(val cause: DecodeFailure) : LockMessage

    /** The key file couldn't be read; the password field stays. */
    data class KeyFileUnreadable(val cause: StorageFailure) : LockMessage
    data object KeyFileDamaged : LockMessage

    /** The key file is a KeePass vault. */
    data object NotKeyFile : LockMessage

    /** Biometric unlock with the key file didn't open the vault; the stored key is kept. */
    data object KeyFileMismatch : LockMessage

    /**
     * The key file is XML too long to read with this device's memory
     * ([OpenResult.KeyFileTooLarge]).
     */
    data object KeyFileTooLarge : LockMessage
}
