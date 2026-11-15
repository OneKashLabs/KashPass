package org.onekash.kashpass.vault.open

import java.time.Instant
import org.onekash.kashpass.vault.backup.BackupDeletion
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.backup.SaveMarker
import org.onekash.kashpass.vault.backup.SaveMarkerStore
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.storage.VaultStateStore

/**
 * A backup store that keeps nothing: a session-only open uses it, and so does an opener built
 * without a backup store.
 */
internal object NoBackups : BackupStore {
    override suspend fun add(location: String, bytes: ByteArray, kind: BackupKind) = BackupResult.Failed
    override suspend fun list(location: String) = emptyList<BackupInfo>()
    override suspend fun read(location: String, id: String): ByteArray? = null
    override suspend fun keepNewest(location: String, count: Int) = 0
    override suspend fun delete(location: String, id: String) = BackupDeletion.NotFound
}

/** A marker store that never has a marker. */
internal object NoMarkers : SaveMarkerStore {
    override fun set(location: String, oldSha256: String, newSha256: String) = Unit
    override fun get(location: String): SaveMarker? = null
    override fun clear(location: String) = Unit
}

/** A state store that keeps nothing and reads as a location never seen, for a session-only open. */
internal object NoState : VaultStateStore {
    override fun kdfBaseline(location: String): KdfSettings? = null
    override fun saveKdfBaseline(location: String, kdf: KdfSettings) = Unit
    override fun weakWarningDismissedFor(location: String): KdfSettings? = null
    override fun saveWeakWarningDismissed(location: String, kdf: KdfSettings) = Unit
    override fun newestSeen(location: String): Instant? = null
    override fun saveNewestSeen(location: String, time: Instant) = Unit
    override fun biometricOfferShown(location: String) = false
    override fun saveBiometricOfferShown(location: String) = Unit
    override fun resetBiometricOffer(location: String) = Unit
    override fun biometricNeedsKeyFile(location: String) = false
    override fun saveBiometricNeedsKeyFile(location: String, needed: Boolean) = Unit
    override fun clear(location: String) = Unit
    override fun backupKeep(): Int? = null
    override fun saveBackupKeep(count: Int) = Unit
}
