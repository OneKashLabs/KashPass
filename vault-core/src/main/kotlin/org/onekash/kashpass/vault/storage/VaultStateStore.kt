package org.onekash.kashpass.vault.storage

import java.time.Instant
import org.onekash.kashpass.vault.header.KdfSettings

/**
 * Non-secret state remembered per vault location: the KDF settings of the last successful unlock
 * (the downgrade baseline), the settings for which the weak-settings warning was dismissed, the
 * newest change time seen in the file (to notice an older version), whether the biometric unlock
 * offer was shown, and whether the biometric key needs a key file. One value is app-wide: how many
 * backup copies to keep. Nothing here is vault content or a password.
 */
interface VaultStateStore {

    /**
     * Returns the KDF settings of the last successful unlock of [location], or null.
     */
    fun kdfBaseline(location: String): KdfSettings?

    /**
     * Records [kdf] as the baseline for [location] after a successful unlock of the file.
     */
    fun saveKdfBaseline(location: String, kdf: KdfSettings)

    /** Returns the KDF settings the weak warning was dismissed for at [location], or null. */
    fun weakWarningDismissedFor(location: String): KdfSettings?

    /** Records that the user dismissed the weak warning for [kdf] at [location]. */
    fun saveWeakWarningDismissed(location: String, kdf: KdfSettings)

    /** Returns the newest change time seen in [location]'s file, or null. */
    fun newestSeen(location: String): Instant?

    /** Records [time] as the newest change seen in [location]'s file. */
    fun saveNewestSeen(location: String, time: Instant)

    /** Returns true once the biometric unlock offer was shown for [location]. */
    fun biometricOfferShown(location: String): Boolean

    /** Records that the biometric unlock offer was shown for [location]. */
    fun saveBiometricOfferShown(location: String)

    /** Lets the biometric unlock offer show again for [location], after biometric unlock is off. */
    fun resetBiometricOffer(location: String)

    /**
     * Returns true when the stored biometric key of [location] was sealed from an unlock with a
     * key file, so a biometric unlock needs that key file too.
     */
    fun biometricNeedsKeyFile(location: String): Boolean

    /**
     * Records whether the stored biometric key of [location] needs a key file; call it whenever
     * that key is sealed, replaced or deleted. [clear] leaves it, since choosing the same file
     * again keeps the key.
     */
    fun saveBiometricNeedsKeyFile(location: String, needed: Boolean)

    /** Forgets everything stored for [location]; used when the user chooses a file again. */
    fun clear(location: String)

    /** Returns the saved count of backup copies to keep, or null when unset. */
    fun backupKeep(): Int?

    /** Saves how many backup copies to keep; app-wide, so [clear] leaves it. */
    fun saveBackupKeep(count: Int)
}
