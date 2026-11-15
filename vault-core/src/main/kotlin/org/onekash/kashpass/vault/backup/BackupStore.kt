package org.onekash.kashpass.vault.backup

import java.security.MessageDigest
import java.time.Instant

/**
 * Encrypted copies of a vault file, kept on the phone byte for byte as read or written: the bytes
 * of each successful open, the remote bytes each save replaces, and the bytes each verified save
 * wrote. They hold nothing decrypted. The app keeps them in storage excluded from Android backup
 * and device transfer.
 */
interface BackupStore {

    /**
     * Keeps [bytes] as a backup of [location], unless they equal the newest backup. An
     * [BackupKind.OPENED] or [BackupKind.SAVED] add then deletes copies beyond the count to keep
     * ([BackupRetention]); a [BackupKind.BEFORE_SAVE] add deletes nothing, so the last good copy
     * before a write is verified is kept. Nothing is deleted while an unverified save of
     * [location] is pending. Never throws for a storage problem; reports it as
     * [BackupResult.Failed].
     */
    suspend fun add(location: String, bytes: ByteArray, kind: BackupKind): BackupResult

    /**
     * Deletes [location]'s backups beyond the newest [count] (limited by [BackupRetention.clamp])
     * and returns how many it deleted; a file it can't delete isn't counted. Deletes nothing while
     * an unverified save of [location] is pending. Never throws.
     */
    suspend fun keepNewest(location: String, count: Int): Int

    /**
     * Deletes backup [id] of [location], except the newest ([BackupRetention.NEWEST_FIRST]) and
     * except while an unverified save of [location] is pending. An id this store didn't generate
     * is [BackupDeletion.NotFound]. Never throws; a delete that fails is [BackupDeletion.Failed].
     */
    suspend fun delete(location: String, id: String): BackupDeletion

    /** Returns the backups of [location], newest first. */
    suspend fun list(location: String): List<BackupInfo>

    /** Returns backup [id] of [location], or null when it doesn't exist or can't be read. */
    suspend fun read(location: String, id: String): ByteArray?
}

/** Why a backup was taken. */
enum class BackupKind {
    /** The bytes a successful unlock read. */
    OPENED,

    /** The remote bytes a save was about to replace. */
    BEFORE_SAVE,

    /** The bytes a save wrote and verified, so the newest backup matches the file. */
    SAVED,
}

/** One kept backup. [id] is a name KashPass generated, never one from a provider. */
data class BackupInfo(val id: String, val createdAt: Instant, val size: Long, val kind: BackupKind, val sha256: String)

/** Outcome of [BackupStore.add]. */
sealed interface BackupResult {
    data class Added(val info: BackupInfo) : BackupResult

    /** The bytes equal the newest backup, which already keeps them. */
    data object SameAsNewest : BackupResult

    /** The backup couldn't be written or didn't read back the same (full storage, I/O). */
    data object Failed : BackupResult
}

/** Outcome of [BackupStore.delete]. */
enum class BackupDeletion {
    Deleted,

    /** No such backup: already gone, or not a name the store generated. */
    NotFound,

    /** The backup is the newest, which is never deleted. */
    Newest,

    /** An unverified save of the location is pending; nothing is deleted until it ends. */
    Pinned,

    /** The file couldn't be deleted. */
    Failed,
}

/** Lowercase hex SHA-256, used for backup checks, folder names and the save marker. */
object Sha256 {
    fun hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** Hashes a location; the hash is stored in place of the location, so no URI is on disk. */
    fun ofLocation(location: String): String = hex(location.toByteArray(Charsets.UTF_8))
}
