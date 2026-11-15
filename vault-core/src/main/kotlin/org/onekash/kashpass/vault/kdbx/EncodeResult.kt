package org.onekash.kashpass.vault.kdbx

/**
 * The outcome of a save through [KdbxEncoder]: one value for every way an encode ends, so no
 * exception but a CancellationException reaches the caller. No result has a string form that
 * shows key, plaintext or file bytes.
 */
internal sealed interface EncodeResult {

    /** The whole KDBX 4 file; the caller owns [bytes], which hold no plaintext. */
    class Encoded(val bytes: ByteArray) : EncodeResult

    /** The caller's KDF check refused the parameters of the written header; nothing was derived. */
    data object Refused : EncodeResult

    /**
     * The caller's KDF threw [cause], an exception other than an OutOfMemoryError or a
     * CancellationException; the caller translates it.
     */
    class DeriveFailed(val cause: Exception) : EncodeResult

    /**
     * The save needs more memory than this device has: an OutOfMemoryError was thrown, the KDF's
     * included, or the file would be larger than an array can hold.
     */
    data object NotEnoughMemory : EncodeResult

    /** The save failed for a reason that is not the vault's ([FailureCause]). */
    data class Failed(val cause: FailureCause) : EncodeResult
}
