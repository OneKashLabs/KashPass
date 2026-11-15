package org.onekash.kashpass.vault.save

import org.onekash.kashpass.vault.doc.OpenedVault

/**
 * Encoded bytes ready to write, with the vault they came from (its credentials verify the
 * write). Retry and Save as copy write these same bytes, never encoding again.
 */
class PreparedSave internal constructor(
    internal val location: String,
    internal val bytes: ByteArray,
    internal val sha256: String,
    internal val vault: OpenedVault,
) {
    override fun toString() = "PreparedSave(${bytes.size} bytes)"
}
