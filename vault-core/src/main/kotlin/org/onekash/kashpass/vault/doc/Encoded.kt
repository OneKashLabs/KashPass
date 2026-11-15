package org.onekash.kashpass.vault.doc

import org.onekash.kashpass.vault.policy.KdfRejection

/**
 * The outcome of [VaultXmlCodec.encode]: one value for every way a save's encode ends, the
 * counterpart of [Decoded]. No result has a string form that shows key, plaintext or file bytes.
 */
internal sealed interface Encoded {

    /**
     * The whole KDBX 4 file; the caller owns [bytes], which hold no plaintext. [xmlBytes] is the
     * length of the XML written and [payloadBytes] of the decompressed payload (inner header and
     * XML), for the save caps ([VaultXmlCodec.Limits]).
     */
    class Bytes(val bytes: ByteArray, val xmlBytes: Long, val payloadBytes: Long) : Encoded {
        override fun toString() = "Encoded.Bytes(${bytes.size} bytes)"
    }

    /**
     * The KDF settings are outside the policy's bounds ([rejection]) or have an Argon2 salt of a
     * length [KdfSaltException] refuses (null); nothing was derived.
     */
    data class Refused(val rejection: KdfRejection?) : Encoded

    /** The save needs more memory than this device has. */
    data object NotEnoughMemory : Encoded

    /** The save failed for a reason that is not the vault's: a platform algorithm or a bug. */
    data object Failed : Encoded
}
