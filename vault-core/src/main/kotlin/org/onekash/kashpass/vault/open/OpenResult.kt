package org.onekash.kashpass.vault.open

import java.time.Instant
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.doc.DecodeFailure
import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.header.UnsupportedReason
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.policy.SlowKdf
import org.onekash.kashpass.vault.storage.StorageFailure

/** Outcome of [VaultOpening.check] and [VaultOpening.open]. */
sealed interface OpenResult {

    /**
     * The header passed every check; the vault can be unlocked with a password. Check only.
     * [lostCutOffSave] is true when a save was cut off and the file doesn't hold its new bytes.
     */
    data class Ready(
        val kdf: KdfSettings,
        val weak: Boolean,
        val slow: SlowKdf? = null,
        val lostCutOffSave: Boolean = false,
    ) : OpenResult

    /**
     * The settings take far longer than before ([SlowKdf]); nothing was derived. Opening again
     * with these settings accepted derives the key.
     */
    data class TooSlow(val slow: SlowKdf) : OpenResult

    /**
     * The vault is open. [showWeakWarning] is false once dismissed for these exact settings.
     * [backup] is set when a backup was opened (read-only) instead of the file. [olderThan] is the
     * newest change seen in an earlier version of the file when this one is older (for example
     * one restored from the provider's version history); [fileNewest] is this file's newest
     * change ([org.onekash.kashpass.vault.doc.NewestChange]), which
     * [VaultOpening.acceptNewest] records to accept it. [bytesAfterEnd] is true when the file has
     * bytes after its end block, which no reader takes as content and a save drops.
     */
    class Unlocked(
        val session: VaultSession,
        val kdf: KdfSettings,
        val showWeakWarning: Boolean,
        val backup: BackupInfo? = null,
        val olderThan: Instant? = null,
        val fileNewest: Instant? = null,
        val bytesAfterEnd: Boolean = false,
    ) : OpenResult

    /**
     * The password or key file did not verify (or the header was altered; KDBX 4 cannot tell
     * them apart).
     */
    data object WrongPassword : OpenResult

    /** Unsafe or downgraded key-derivation settings; the password was not used. */
    data class Refused(val rejection: KdfRejection) : OpenResult

    /**
     * A format or algorithm KashPass does not open. The password was not used, except for an
     * [UnsupportedReason.InnerStream] with keyChecked, which the inner header names after the key
     * was derived and verified.
     */
    data class Unsupported(val reason: UnsupportedReason) : OpenResult

    /**
     * Not a KeePass vault, cut short, or corrupted; [reason] names the layer
     * ([DamageReason.afterHeaderHmac] tells damage after the key verified). [lastCopy] is the last
     * good copy of the file, which opens read-only ([LastCopyReason.CORRUPTED] or
     * [LastCopyReason.CORRUPTED_AFTER_HEADER]); set only by
     * check, open, openWithKey and reopen of the file, and null when no good copy is kept.
     */
    data class Damaged(val reason: DamageReason, val lastCopy: BackupInfo? = null) : OpenResult

    /**
     * The file could not be read; the password was not used. [lastCopy] is the last good copy of
     * the file, which opens read-only ([LastCopyReason.UNAVAILABLE]); set only by check, open,
     * openWithKey and reopen of the file, never for a file that is too large, and null when no
     * good copy is kept.
     */
    data class Unreadable(val cause: StorageFailure, val lastCopy: BackupInfo? = null) : OpenResult

    /** A kept backup's bytes don't match the SHA-256 in its name; it was not decrypted. */
    data object BackupDamaged : OpenResult

    /**
     * Opening the file needs more memory than the app's heap allows. [lastCopy] is the last good
     * copy of the file, which opens read-only ([LastCopyReason.UNAVAILABLE]); set only when the
     * file's header needs more memory than the heap allows (its dictionaries), by check, open,
     * openWithKey and reopen of the file, never when reading or decrypting the file needs it, and
     * null when no good copy is kept.
     */
    data class NotEnoughMemory(val lastCopy: BackupInfo? = null) : OpenResult

    /**
     * Opening failed for a reason that is not the file's: the platform lacks an algorithm, or a
     * KashPass bug ([cause]). No last good copy is offered.
     */
    data class Failed(val cause: DecodeFailure) : OpenResult

    /**
     * The key file is an XML key file whose key can't be read (its hash doesn't match, for
     * example); nothing was read or derived.
     */
    data object KeyFileDamaged : OpenResult

    /**
     * The key file is XML with a KeyFile root, longer than this heap allows for XML
     * ([org.onekash.kashpass.vault.doc.KeyFile.parse]); nothing was read or derived.
     */
    data object KeyFileTooLarge : OpenResult
}

/** Why a backup opens as the last copy of a file that can't be opened. */
enum class LastCopyReason {
    /**
     * The file could not be read ([OpenResult.Unreadable]) or its header needs more memory than
     * the heap allows ([OpenResult.NotEnoughMemory]).
     */
    UNAVAILABLE,

    /** The file is corrupted ([OpenResult.Damaged]). */
    CORRUPTED,

    /**
     * The file is corrupted after the header HMAC verified the key
     * ([DamageReason.afterHeaderHmac]); a repair import on the desktop reads past such damage.
     */
    CORRUPTED_AFTER_HEADER,
}

/** Outcome of [VaultOpening.refresh]. */
sealed interface RefreshResult {
    /** The file holds the bytes the session was read from or last saved. */
    data object Unchanged : RefreshResult

    /**
     * The file changed and was read again with the session's key; [opened] holds the new session.
     */
    class Reloaded(val opened: OpenResult.Unlocked) : RefreshResult

    /** The file couldn't be read again or failed a check; [result] says why. */
    data class Failed(val result: OpenResult) : RefreshResult
}
