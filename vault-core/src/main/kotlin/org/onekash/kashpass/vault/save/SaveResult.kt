package org.onekash.kashpass.vault.save

import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.storage.Writability

/**
 * Outcome of a save. Every result carries [opened], the vault the session keeps afterwards: the
 * saved document with a new baseline after [Saved], otherwise the document that was meant to be
 * saved, with the baseline [OpenedVault.Baseline.Unknown] whenever the file can have changed.
 * [prepared] is set when the encoded bytes can be written again ([VaultSaving.retry],
 * [VaultSaving.saveCopy]).
 */
sealed interface SaveResult {
    val opened: OpenedVault
    val prepared: PreparedSave?

    /** Written, read back with the same SHA-256 and decrypted with the session key. */
    class Saved(override val opened: OpenedVault) : SaveResult {
        override val prepared: PreparedSave? = null
    }

    /**
     * The file differs from the baseline (other bytes, shorter, empty, unreadable); nothing
     * written.
     */
    class Conflict(override val opened: OpenedVault, override val prepared: PreparedSave) : SaveResult

    /**
     * The provider didn't answer the writability check or the re-read in time; nothing written,
     * and the file is as it was, so the same bytes can be written again.
     */
    class NotReachable(override val opened: OpenedVault, override val prepared: PreparedSave) : SaveResult

    /** The file can't be written ([reason]); refused before encoding. */
    class NotWritable(override val opened: OpenedVault, val reason: Writability) : SaveResult {
        override val prepared: PreparedSave? = null
    }

    /** The vault opened read-only ([reason]) and is never saved. */
    class ReadOnly(override val opened: OpenedVault, val reason: Saveability.ReadOnly) : SaveResult {
        override val prepared: PreparedSave? = null
    }

    /** The encoded file's key derivation settings fail the policy; nothing written. */
    class KdfRefused(override val opened: OpenedVault, val rejection: KdfRejection?) : SaveResult {
        override val prepared: PreparedSave? = null
    }

    /**
     * The backup of the file about to be replaced couldn't be kept (full storage); nothing written.
     */
    class BackupFailed(override val opened: OpenedVault, override val prepared: PreparedSave) : SaveResult

    /** The write failed before the file was opened; it is unchanged. */
    class WriteFailed(override val opened: OpenedVault, override val prepared: PreparedSave) : SaveResult

    /** The write failed or timed out, and the file holds the old bytes. */
    class NotSavedUnchanged(override val opened: OpenedVault, override val prepared: PreparedSave) : SaveResult

    /** The write failed or timed out and the file holds neither the old nor the new bytes. */
    class MaybeDamaged(override val opened: OpenedVault, override val prepared: PreparedSave) : SaveResult

    /** The file was written but didn't read back as written or didn't decrypt. */
    class VerifyFailed(override val opened: OpenedVault, override val prepared: PreparedSave) : SaveResult

    /** An earlier write to this file hasn't finished in the provider; nothing new written. */
    class WriterStillRunning(override val opened: OpenedVault, override val prepared: PreparedSave) : SaveResult

    /**
     * Encoding or reading the encoded header back needed more memory than the app's heap allows,
     * or the encoded file is over the save caps for this heap (its XML, its decompressed payload
     * or its size); nothing written.
     */
    class NotEnoughMemory(override val opened: OpenedVault) : SaveResult {
        override val prepared: PreparedSave? = null
    }

    /**
     * An unexpected exception stopped the save. [prepared] is set when the bytes were encoded.
     * The baseline stays known when the write never started, so the file is unchanged; after the
     * write started it is [OpenedVault.Baseline.Unknown].
     */
    class UnexpectedError(override val opened: OpenedVault, override val prepared: PreparedSave?) : SaveResult
}

/** Outcome of [VaultSaving.saveCopy]. */
sealed interface CopyResult {
    /** Written and verified; [displayName] is the name the provider gave, when it reports one. */
    data class Saved(val displayName: String?) : CopyResult

    /**
     * The copy couldn't be written or verified; the picker's file at [location] holds no verified
     * copy and can hold part of one.
     */
    data class Failed(val location: String) : CopyResult

    /**
     * Nothing was written: [location] already holds bytes or can't be read, or the bytes to copy
     * fail the header or KDF checks or are over the save caps for this heap. The file is left as
     * it was.
     */
    data class Refused(val location: String) : CopyResult
}
