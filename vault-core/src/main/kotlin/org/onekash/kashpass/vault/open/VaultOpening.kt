package org.onekash.kashpass.vault.open

import java.time.Instant
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.header.KdfSettings

/**
 * Opens a vault through every security check. The app depends on this, never on the container.
 *
 * The [FileAccess] given to [check], [open], [openWithKey] and the password [openBackup] sets how
 * the file opens: [FileAccess.PROVIDER_READ_ONLY] opens it read-only and otherwise like the
 * remembered file; [FileAccess.SESSION_ONLY] opens it read-only, checks it against no stored
 * settings and stores nothing for it ([VaultOpener.storesFor]). [refresh], [reopen] and the
 * session [openBackup] take the access from the session.
 */
interface VaultOpening {

    /**
     * Reads [location] and checks its header without a password: Ready, Refused, Unsupported,
     * Damaged, Unreadable or NotEnoughMemory; Ready carries a [OpenResult.Ready.slow] warning when
     * the settings take far longer than before. [OpenResult.Damaged], [OpenResult.Unreadable] and
     * a header's [OpenResult.NotEnoughMemory] carry the last good copy when one is kept (none for
     * a file that is too large). With a pending save marker
     * and a Ready result: the new bytes clear the marker; the old bytes clear it and set
     * [OpenResult.Ready.lostCutOffSave]; other bytes set [OpenResult.Ready.lostCutOffSave] and
     * keep the marker until [open] or [openWithKey] unlocks the file.
     */
    suspend fun check(location: String, access: FileAccess = FileAccess.READ_WRITE): OpenResult

    /**
     * Reads [location] again, checks it, and decrypts the same bytes with [password] and, when
     * given, the contents of a key file [keyFile]. With a key file and an empty [password] the key
     * file is tried alone first, then once with an empty password. A key file that can't be read
     * is [OpenResult.KeyFileDamaged] before anything is read, and an XML key file longer than
     * this heap allows is [OpenResult.KeyFileTooLarge]. A file whose settings are
     * [OpenResult.TooSlow] is derived only when they equal [acceptedSlow]. Unlocking clears a
     * pending save marker. Cancelling the caller stops a running key derivation, and this throws
     * CancellationException; a cancel that lands after the file verified leaves what an open
     * stores (the KDF baseline, the newest change, the opened backup) and no session. The
     * password and key-file arrays are zero-filled before this returns, on every path.
     */
    suspend fun open(
        location: String,
        password: CharArray,
        acceptedSlow: KdfSettings? = null,
        keyFile: ByteArray? = null,
        access: FileAccess = FileAccess.READ_WRITE,
    ): OpenResult

    /**
     * Opens [location] like [open], with [key] (a [VaultSession.unlockKey] of this vault) in place
     * of the password, and the contents of the vault's key file [keyFile] when it has one. [key]
     * and [keyFile] are zero-filled before this returns, on every path.
     */
    suspend fun openWithKey(
        location: String,
        key: ByteArray,
        acceptedSlow: KdfSettings? = null,
        keyFile: ByteArray? = null,
        access: FileAccess = FileAccess.READ_WRITE,
    ): OpenResult

    /** Hides the weak-settings warning for [location] until its KDF settings differ from [kdf]. */
    suspend fun dismissWeakWarning(location: String, kdf: KdfSettings)

    /**
     * Reads [location] again before an edit: [RefreshResult.Unchanged] when it holds the
     * session's baseline, otherwise a new session unlocked with [session]'s key through every
     * check (an unknown baseline always reloads). Leaves a pending save marker as it is.
     * [session]'s vault is read at the start only; when the session is released during the file
     * read (a lock), the call stops before any key derivation with IllegalStateException, the
     * exception a released session gives, which the caller maps to a lock (VaultOpenerTest).
     */
    suspend fun refresh(location: String, session: VaultSession): RefreshResult

    /**
     * Opens the file at [location] with [session]'s key through every check; Close backup and
     * Reload use it. Leaves a pending save marker as it is. [session] is read and checked as in
     * [refresh].
     */
    suspend fun reopen(location: String, session: VaultSession): OpenResult

    /** Records [time] as the newest change seen at [location], accepting an older file. */
    suspend fun acceptNewest(location: String, time: Instant)

    /** Returns the backups kept for [location], newest first. */
    suspend fun backups(location: String): List<BackupInfo>

    /**
     * Opens [backup] read-only with [password] and [keyFile] as [open] uses them, through every
     * check except the downgrade comparison; [lastCopy] marks it as the last copy of a file that
     * can't be opened ([OpenResult.Damaged], [OpenResult.Unreadable] or
     * [OpenResult.NotEnoughMemory]). Never changes stored state. The password and key-file arrays
     * are zero-filled before this returns.
     */
    suspend fun openBackup(
        location: String,
        backup: BackupInfo,
        password: CharArray,
        lastCopy: LastCopyReason? = null,
        acceptedSlow: KdfSettings? = null,
        keyFile: ByteArray? = null,
        access: FileAccess = FileAccess.READ_WRITE,
    ): OpenResult

    /**
     * Opens [backup] read-only like [openBackup], with [session]'s key instead of a password; a
     * slow backup is refused as [OpenResult.TooSlow] (open it from the lock screen to accept).
     * When [session] is a last copy, [backup] opens as a last copy for the same reason.
     */
    suspend fun openBackup(location: String, backup: BackupInfo, session: VaultSession): OpenResult
}
