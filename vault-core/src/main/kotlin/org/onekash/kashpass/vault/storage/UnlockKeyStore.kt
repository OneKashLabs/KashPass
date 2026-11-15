package org.onekash.kashpass.vault.storage

/**
 * Keeps one secret per vault location sealed under a key the platform releases only after a
 * strong biometric check, for biometric unlock. The app implements it over the Android
 * Keystore; tests use FakeUnlockKeyStore, which keeps the same contract.
 */
interface UnlockKeyStore {

    /** Returns whether this phone can protect a secret this way now. */
    fun availability(): UnlockAvailability

    /** Returns what is stored for [location]. */
    fun state(location: String): StoredKeyState

    /**
     * Seals [secret] for [location] under a new key after [confirm] reports the check passed;
     * [secret] is zero-filled before this returns, on every path.
     */
    suspend fun seal(location: String, secret: ByteArray, confirm: suspend (CryptoHandle) -> Confirmation): SealResult

    /** Releases the secret stored for [location] after [confirm] reports the check passed. */
    suspend fun unseal(location: String, confirm: suspend (CryptoHandle) -> Confirmation): UnsealResult

    /** Deletes the sealed secret and its key for [location]; safe when nothing is stored. */
    fun delete(location: String)
}

/** Whether [UnlockKeyStore] can be used. */
enum class UnlockAvailability {
    READY,

    /** No strong biometric is enrolled. */
    NONE_ENROLLED,

    /** The phone has no screen lock, so the platform can't protect the key. */
    NO_SCREEN_LOCK,

    /** No suitable hardware, or the platform refused. */
    UNAVAILABLE,
}

/** What [UnlockKeyStore.state] finds. */
enum class StoredKeyState {
    NONE,
    STORED,

    /**
     * A secret is stored but its key is unusable (new enrollment, screen lock removed).
     */
    INVALIDATED,

    /**
     * A secret is stored but the platform can't load its key (the key store's copy of the key is
     * unreadable). Retrying fails the same way, so the caller deletes what is stored.
     */
    UNRECOVERABLE,
}

/** The platform's crypto object for one check; only the platform reads [platform]. */
class CryptoHandle(val platform: Any)

/** What the system check reported. */
sealed interface Confirmation {
    data object Confirmed : Confirmation

    /** The user dismissed it. */
    data object Cancelled : Confirmation

    /** The user chose the password instead. */
    data object UsePassword : Confirmation

    /** The system ended it (screen off, another app, a lock). */
    data object Interrupted : Confirmation

    /** Too many failed tries; the platform locked the sensor. */
    data object LockedOut : Confirmation

    /** Any other failure (time-out, hardware unavailable). */
    data object Failed : Confirmation
}

/** Outcome of [UnlockKeyStore.seal]. */
sealed interface SealResult {
    data object Sealed : SealResult

    /** The check didn't pass; nothing was stored. */
    data class NotConfirmed(val confirmation: Confirmation) : SealResult

    /** The key or the file couldn't be made; nothing was stored. */
    data object Failed : SealResult
}

/** Outcome of [UnlockKeyStore.unseal]. */
sealed interface UnsealResult {
    /** The secret; the caller zero-fills it after use. */
    class Unsealed(val secret: ByteArray) : UnsealResult

    data class NotConfirmed(val confirmation: Confirmation) : UnsealResult

    /** Nothing is stored for the location. */
    data object Missing : UnsealResult

    /** The key is unusable; the caller deletes what is stored. */
    data object Invalidated : UnsealResult

    /** The platform can't load the key; the caller deletes what is stored. */
    data object Unrecoverable : UnsealResult

    /**
     * The check passed but the stored bytes failed verification: damaged; the caller deletes them.
     */
    data object Damaged : UnsealResult

    /** The platform failed; what is stored is kept for another try. */
    data object Failed : UnsealResult
}
