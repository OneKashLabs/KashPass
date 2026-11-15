package org.onekash.kashpass.platform

import android.content.Context
import androidx.core.content.edit
import java.time.Instant
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.header.Argon2Variant
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.storage.VaultStateStore

/**
 * The remembered vault: its content URI, the name the picker showed, and whether its provider
 * granted reading only ([readOnly]), so it opens read-only.
 */
data class RememberedVault(val location: String, val displayName: String, val readOnly: Boolean = false)

/** The key file remembered for the vault: its content URI and the name the picker showed. */
data class RememberedKeyFile(val location: String, val displayName: String)

/**
 * Keeps the app's vault state in one private preferences file: the remembered vault, the
 * KDF baseline, the weak-warning dismissal, the newest change seen, the biometric offer, whether
 * the biometric key needs a key file, the backup count, the vault's key file location, whether the
 * vault's grant is read only and whether its last unlock used a key file.
 * None of it is vault content, a password or key-file content; [PrefsVaultStateStoreTest] pins
 * the exact key set.
 */
class PrefsVaultStateStore(context: Context) : VaultStateStore {

    private val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /** Returns the remembered vault, or null before the first pick. */
    fun vault(): RememberedVault? {
        val location = prefs.getString(KEY_VAULT, null) ?: return null
        return RememberedVault(location, prefs.getString(KEY_NAME, null).orEmpty(), prefs.getBoolean(KEY_READ_ONLY, false))
    }

    /**
     * Remembers [location] as the vault, shown as [displayName]; [readOnly] when its provider
     * granted reading only.
     */
    fun saveVault(location: String, displayName: String, readOnly: Boolean = false) = prefs.edit {
        putString(KEY_VAULT, location)
        putString(KEY_NAME, displayName)
        putBoolean(KEY_READ_ONLY, readOnly)
    }

    /** Returns the key file remembered for the vault at [vault], or null. */
    fun keyFile(vault: String): RememberedKeyFile? {
        val value = prefs.getString(KEY_KEY_FILE, null) ?: return null
        val parts = value.split('\n', limit = 3).takeIf { it.size == 3 } ?: return null
        return if (parts[0] == vault) RememberedKeyFile(parts[1], parts[2]) else null
    }

    /**
     * Remembers [location], shown as [displayName], as the key file of the vault at [vault]. One
     * key file is kept, for the remembered vault, stored as "<vault>\n<location>\n<name>".
     */
    fun saveKeyFile(vault: String, location: String, displayName: String) =
        prefs.edit { putString(KEY_KEY_FILE, "$vault\n$location\n$displayName") }

    /** Forgets the remembered key file. [clear] leaves it, so choosing the same vault keeps it. */
    fun clearKeyFile() = prefs.edit { remove(KEY_KEY_FILE) }

    override fun kdfBaseline(location: String) = read(KEY_BASELINE, location)

    override fun saveKdfBaseline(location: String, kdf: KdfSettings) = write(KEY_BASELINE, location, kdf)

    override fun weakWarningDismissedFor(location: String) = read(KEY_DISMISSED, location)

    override fun saveWeakWarningDismissed(location: String, kdf: KdfSettings) = write(KEY_DISMISSED, location, kdf)

    // Stored as the set of location hashes the offer was shown for: no URI on disk for this.
    override fun biometricOfferShown(location: String) = Sha256.ofLocation(location) in offers()

    override fun saveBiometricOfferShown(location: String) = prefs.edit { putStringSet(KEY_OFFERS, offers() + Sha256.ofLocation(location)) }

    override fun resetBiometricOffer(location: String) = prefs.edit { putStringSet(KEY_OFFERS, offers() - Sha256.ofLocation(location)) }

    private fun offers(): Set<String> = prefs.getStringSet(KEY_OFFERS, emptySet()).orEmpty()

    // Stored as the set of location hashes whose stored key needs a key file, like the offers.
    override fun biometricNeedsKeyFile(location: String) = Sha256.ofLocation(location) in needsKeyFile()

    override fun saveBiometricNeedsKeyFile(location: String, needed: Boolean) = prefs.edit {
        val hash = Sha256.ofLocation(location)
        putStringSet(KEY_NEEDS_KEY_FILE, if (needed) needsKeyFile() + hash else needsKeyFile() - hash)
    }

    private fun needsKeyFile(): Set<String> = prefs.getStringSet(KEY_NEEDS_KEY_FILE, emptySet()).orEmpty()

    /**
     * Returns true when the last unlock of the vault at [location] used a key file. Stored as the
     * set of location hashes, like the offers; [clear] keeps it, so re-choosing the same vault
     * keeps it.
     */
    fun keyFileUnlock(location: String): Boolean = Sha256.ofLocation(location) in keyFileUnlocks()

    /** Records whether an unlock of the vault at [location] used a key file ([used]). */
    fun saveKeyFileUnlock(location: String, used: Boolean) = prefs.edit {
        val hash = Sha256.ofLocation(location)
        putStringSet(KEY_KEY_FILE_UNLOCK, if (used) keyFileUnlocks() + hash else keyFileUnlocks() - hash)
    }

    private fun keyFileUnlocks(): Set<String> = prefs.getStringSet(KEY_KEY_FILE_UNLOCK, emptySet()).orEmpty()

    override fun newestSeen(location: String): Instant? {
        val value = prefs.getString(KEY_NEWEST, null) ?: return null
        val (storedLocation, seconds) = value.split('\n', limit = 2).takeIf { it.size == 2 } ?: return null
        // Seconds outside Instant's range read as no stored time, as any unreadable value does.
        val second = seconds.toLongOrNull()?.takeIf { it in Instant.MIN.epochSecond..Instant.MAX.epochSecond }
        return if (storedLocation == location) second?.let(Instant::ofEpochSecond) else null
    }

    override fun saveNewestSeen(location: String, time: Instant) = prefs.edit { putString(KEY_NEWEST, "$location\n${time.epochSecond}") }

    override fun backupKeep(): Int? = if (prefs.contains(KEY_KEEP)) prefs.getInt(KEY_KEEP, 0) else null

    override fun saveBackupKeep(count: Int) = prefs.edit { putInt(KEY_KEEP, count) }

    override fun clear(location: String) = prefs.edit {
        if (read(KEY_BASELINE, location) != null) remove(KEY_BASELINE)
        if (read(KEY_DISMISSED, location) != null) remove(KEY_DISMISSED)
        if (newestSeen(location) != null) remove(KEY_NEWEST)
        putStringSet(KEY_OFFERS, offers() - Sha256.ofLocation(location))
    }

    // Stored as "<location>\n<kdf>", so state written for one file never applies to another.
    private fun read(key: String, location: String): KdfSettings? {
        val value = prefs.getString(key, null) ?: return null
        val (storedLocation, kdf) = value.split('\n', limit = 2).takeIf { it.size == 2 } ?: return null
        return if (storedLocation == location) decode(kdf) else null
    }

    private fun write(key: String, location: String, kdf: KdfSettings) =
        prefs.edit { putString(key, "$location\n${encode(kdf)}") }

    private fun encode(kdf: KdfSettings): String = when (kdf) {
        is KdfSettings.AesKdf -> "aes:${kdf.rounds}"
        is KdfSettings.Argon2 -> "argon2:${kdf.variant.name}:${kdf.iterations}:${kdf.memoryBytes}:${kdf.parallelism}:${kdf.version}"
    }

    private fun decode(text: String): KdfSettings? {
        val parts = text.split(':')
        return when (parts.firstOrNull()) {
            "aes" -> parts.getOrNull(1)?.toULongOrNull()?.let { KdfSettings.AesKdf(it) }
            "argon2" -> if (parts.size == 6) {
                val variant = Argon2Variant.entries.firstOrNull { it.name == parts[1] } ?: return null
                KdfSettings.Argon2(
                    variant = variant,
                    iterations = parts[2].toULongOrNull() ?: return null,
                    memoryBytes = parts[3].toULongOrNull() ?: return null,
                    parallelism = parts[4].toUIntOrNull() ?: return null,
                    version = parts[5].toUIntOrNull() ?: return null,
                )
            } else {
                null
            }
            else -> null
        }
    }

    companion object {
        const val FILE = "kashpass_vault"
        private const val KEY_VAULT = "vault_uri"
        private const val KEY_NAME = "vault_name"
        private const val KEY_BASELINE = "kdf_baseline"
        private const val KEY_DISMISSED = "weak_warning_dismissed"
        private const val KEY_NEWEST = "newest_seen"
        private const val KEY_OFFERS = "biometric_offer_shown"
        private const val KEY_KEEP = "backup_keep"
        private const val KEY_KEY_FILE = "key_file"
        private const val KEY_READ_ONLY = "vault_read_only"
        private const val KEY_NEEDS_KEY_FILE = "biometric_needs_key_file"
        private const val KEY_KEY_FILE_UNLOCK = "key_file_unlock"

        /** Every key this store can write. */
        val KEYS = setOf(
            KEY_VAULT, KEY_NAME, KEY_BASELINE, KEY_DISMISSED, KEY_NEWEST, KEY_OFFERS, KEY_KEEP, KEY_KEY_FILE, KEY_READ_ONLY,
            KEY_NEEDS_KEY_FILE, KEY_KEY_FILE_UNLOCK,
        )
    }
}
