package org.onekash.kashpass.vault.testing

import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.storage.VaultStateStore

/** Shared in-memory fake of [VaultStateStore]. */
class FakeVaultStateStore : VaultStateStore {

    /** When true, every call records its name in [refused] and throws an AssertionError. */
    var refuseAll = false

    /** The name of each call made while [refuseAll] was on, in order. */
    val refused = mutableListOf<String>()

    private fun guard(name: String) {
        if (!refuseAll) return
        refused += name
        throw AssertionError("state.$name")
    }

    private val baselines = mutableMapOf<String, KdfSettings>()
    private val dismissals = mutableMapOf<String, KdfSettings>()
    private val newest = mutableMapOf<String, java.time.Instant>()

    private val offers = mutableSetOf<String>()

    override fun biometricOfferShown(location: String): Boolean {
        guard("biometricOfferShown")
        return location in offers
    }

    override fun saveBiometricOfferShown(location: String) {
        guard("saveBiometricOfferShown")
        offers += location
    }

    override fun resetBiometricOffer(location: String) {
        guard("resetBiometricOffer")
        offers -= location
    }

    private val needsKeyFile = mutableSetOf<String>()

    override fun biometricNeedsKeyFile(location: String): Boolean {
        guard("biometricNeedsKeyFile")
        return location in needsKeyFile
    }

    override fun saveBiometricNeedsKeyFile(location: String, needed: Boolean) {
        guard("saveBiometricNeedsKeyFile")
        if (needed) needsKeyFile += location else needsKeyFile -= location
    }

    override fun newestSeen(location: String): java.time.Instant? {
        guard("newestSeen")
        return newest[location]
    }

    override fun saveNewestSeen(location: String, time: java.time.Instant) {
        guard("saveNewestSeen")
        newest[location] = time
    }

    override fun kdfBaseline(location: String): KdfSettings? {
        guard("kdfBaseline")
        return baselines[location]
    }

    override fun saveKdfBaseline(location: String, kdf: KdfSettings) {
        guard("saveKdfBaseline")
        baselines[location] = kdf
    }

    override fun weakWarningDismissedFor(location: String): KdfSettings? {
        guard("weakWarningDismissedFor")
        return dismissals[location]
    }

    override fun saveWeakWarningDismissed(location: String, kdf: KdfSettings) {
        guard("saveWeakWarningDismissed")
        dismissals[location] = kdf
    }

    /** The saved backup count, or null. */
    var keep: Int? = null

    override fun backupKeep(): Int? {
        guard("backupKeep")
        return keep
    }

    override fun saveBackupKeep(count: Int) {
        guard("saveBackupKeep")
        keep = count
    }

    override fun clear(location: String) {
        guard("clear")
        offers -= location
        newest.remove(location)
        baselines.remove(location)
        dismissals.remove(location)
    }
}
