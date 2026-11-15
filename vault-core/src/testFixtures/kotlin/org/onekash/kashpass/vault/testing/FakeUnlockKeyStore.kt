package org.onekash.kashpass.vault.testing

import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.CryptoHandle
import org.onekash.kashpass.vault.storage.SealResult
import org.onekash.kashpass.vault.storage.StoredKeyState
import org.onekash.kashpass.vault.storage.UnlockAvailability
import org.onekash.kashpass.vault.storage.UnlockKeyStore
import org.onekash.kashpass.vault.storage.UnsealResult

/**
 * Shared fake of [UnlockKeyStore]: keeps secrets in memory, calls the caller's confirm for every
 * seal and unseal as the platform prompt does, and can report that the phone isn't ready, that a
 * stored key was invalidated (a new enrollment) or that the platform can't load it.
 */
class FakeUnlockKeyStore : UnlockKeyStore {

    var available: UnlockAvailability = UnlockAvailability.READY

    /** When true, a confirmed seal fails as the Keystore does without a usable auth token. */
    var failSeal = false

    private val secrets = mutableMapOf<String, ByteArray>()
    private val invalidated = mutableSetOf<String>()
    private val damaged = mutableSetOf<String>()
    private val unrecoverable = mutableSetOf<String>()

    /** Every seal, unseal and delete, by name and location. */
    val calls = mutableListOf<Pair<String, String>>()

    /** The bytes stored for [location], or null. */
    fun stored(location: String): ByteArray? = secrets[location]?.copyOf()

    /** Makes the key stored for [location] unusable, as a new enrollment does. */
    fun invalidate(location: String) {
        invalidated += location
    }

    /** Makes the key stored for [location] fail to load, as an unreadable Keystore entry does. */
    fun unrecoverable(location: String) {
        unrecoverable += location
    }

    /** Makes what is stored for [location] fail to open after the prompt passes. */
    fun damage(location: String) {
        damaged += location
    }

    override fun availability() = available

    override fun state(location: String) = when {
        location !in secrets -> StoredKeyState.NONE
        location in invalidated -> StoredKeyState.INVALIDATED
        location in unrecoverable -> StoredKeyState.UNRECOVERABLE
        else -> StoredKeyState.STORED
    }

    override suspend fun seal(location: String, secret: ByteArray, confirm: suspend (CryptoHandle) -> Confirmation): SealResult = try {
        calls += "seal" to location
        // As on the device, a new seal starts from a new key: the old one is deleted first.
        secrets.remove(location)
        invalidated -= location
        damaged -= location
        unrecoverable -= location
        when (val c = confirm(CryptoHandle(Unit))) {
            Confirmation.Confirmed -> if (failSeal) SealResult.Failed else {
                secrets[location] = secret.copyOf()
                invalidated -= location
                SealResult.Sealed
            }
            else -> SealResult.NotConfirmed(c)
        }
    } finally {
        secret.fill(0)
    }

    override suspend fun unseal(location: String, confirm: suspend (CryptoHandle) -> Confirmation): UnsealResult {
        calls += "unseal" to location
        val secret = secrets[location] ?: return UnsealResult.Missing
        if (location in invalidated) return UnsealResult.Invalidated
        if (location in unrecoverable) return UnsealResult.Unrecoverable
        return when (val c = confirm(CryptoHandle(Unit))) {
            Confirmation.Confirmed -> if (location in damaged) UnsealResult.Damaged else UnsealResult.Unsealed(secret.copyOf())
            else -> UnsealResult.NotConfirmed(c)
        }
    }

    override fun delete(location: String) {
        calls += "delete" to location
        secrets.remove(location)
        invalidated -= location
        damaged -= location
        unrecoverable -= location
    }
}
