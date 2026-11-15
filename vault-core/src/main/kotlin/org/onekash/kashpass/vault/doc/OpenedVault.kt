package org.onekash.kashpass.vault.doc

import java.time.Instant

/**
 * A vault as one save needs it: the document (which carries the session credentials,
 * [VaultDocument.credentials]), the conflict baseline, and the size and time of the read. Lives in
 * this package so saving never depends on opening.
 *
 * Immutable and shared: a session, a failed save's prepared bytes and the next session can hold
 * the same instance, so nothing here is released from under another holder. Every OpenedVault
 * made from one unlock shares the credentials; a lock drops the session's reference. They are
 * never zero-filled, because another holder can use them; they stay masked ([VaultKey]) and are
 * freed with the last reference.
 */
class OpenedVault internal constructor(
    val document: VaultDocument,
    val baseline: Baseline,
    /** Size of the bytes read, in bytes. */
    val openedSize: Long,
    /** When the bytes were read. */
    val openedAt: Instant,
    /** What the unlock was given; every vault made from this one keeps it. */
    val origin: UnlockOrigin,
    /** How the file is held; every vault made from this one keeps it. */
    val access: FileAccess = FileAccess.READ_WRITE,
) {
    val saveability: Saveability get() = document.saveability

    /**
     * Returns the same vault holding [document], with its credentials, baseline, origin and access.
     */
    fun withDocument(document: VaultDocument) = OpenedVault(document, baseline, openedSize, openedAt, origin, access)

    /** Returns the same vault with [baseline]. */
    fun withBaseline(baseline: Baseline) = OpenedVault(document, baseline, openedSize, openedAt, origin, access)

    override fun toString() = "OpenedVault($baseline)"

    /** What the remote file must hold for a save to overwrite it. */
    sealed interface Baseline {
        /** The SHA-256 of the bytes last read or written, as lowercase hex. */
        data class Known(val sha256: String) : Baseline

        /** A failed save left the file unknown; the next save treats it as changed. */
        data object Unknown : Baseline
    }
}
