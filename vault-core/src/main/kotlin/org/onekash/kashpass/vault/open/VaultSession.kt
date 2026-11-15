package org.onekash.kashpass.vault.open

import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.index.FieldRefs
import org.onekash.kashpass.vault.index.VaultIndex

/**
 * An unlocked vault: the [OpenedVault] a save works from, and the browsable index and the field
 * reference resolver built from it. [release] drops all three, so locking leaves no reference
 * behind.
 */
class VaultSession internal constructor(opened: OpenedVault, index: VaultIndex, refs: FieldRefs) {

    // Volatile: a lock releases the session on the main thread while the opener reads isOpen on
    // its own (VaultOpening.refresh).
    @Volatile
    private var vault: OpenedVault? = opened

    @Volatile
    private var current: VaultIndex? = index

    @Volatile
    private var resolver: FieldRefs? = refs

    /** The browsable index. Throws after [release]. */
    val index: VaultIndex get() = checkNotNull(current) { "session released" }

    /** Resolves `{REF:}` field references for display, reveal and copy. Throws after [release]. */
    val refs: FieldRefs get() = checkNotNull(resolver) { "session released" }

    /** The vault as a save needs it. Throws after [release]. */
    val opened: OpenedVault get() = checkNotNull(vault) { "session released" }

    /** Whether this session's vault can be saved. Throws after [release]. */
    val saveability: Saveability get() = opened.saveability

    /**
     * Returns a copy of the 32-byte KDBX passphrase hash this session's key is built from (the
     * SHA-256 of the UTF-8 password, the password part of the composite key), for biometric unlock
     * to seal; null for a [UnlockOrigin.KEY_FILE_ONLY] session, which has no password to seal. A
     * key-file part is never returned. Throws after [release]. The caller zero-fills the copy.
     */
    fun unlockKey(): ByteArray? {
        val opened = opened
        if (opened.origin == UnlockOrigin.KEY_FILE_ONLY) return null
        return checkNotNull(opened.document.credentials.passwordHash())
    }

    /** True until [release]. */
    val isOpen: Boolean get() = current != null

    /**
     * Drops this session's references to the vault, the index and the resolver; safe to call more
     * than once. The vault is immutable and can outlive this session in another holder (a failed
     * save's prepared bytes, the next session), so nothing in it is torn down here.
     */
    fun release() {
        vault = null
        current = null
        resolver = null
    }

    override fun toString() = "VaultSession(open=$isOpen)"

    companion object {
        /** A session over [opened], with its index and resolver built from the document. */
        fun from(opened: OpenedVault) = VaultSession(opened, VaultIndex.from(opened.document), FieldRefs.from(opened.document))
    }
}
