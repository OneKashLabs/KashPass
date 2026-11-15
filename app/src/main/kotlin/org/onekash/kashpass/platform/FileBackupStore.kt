package org.onekash.kashpass.platform

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.time.Instant
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.onekash.kashpass.vault.backup.BackupDeletion
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.backup.BackupRetention
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.backup.Sha256

/**
 * Keeps backups as files under [root], which the app places in noBackupFilesDir: excluded from
 * Auto Backup and device transfer (developer.android.com/identity/data/autobackup). Each vault gets
 * a folder named by the hash of its location, and each backup a name KashPass generates
 * ("<millis>-<kind>-<sha256>.kdbx"), never a provider's name (Android security guidance,
 * "Untrustworthy ContentProvider-provided filename").
 * A backup is written to a temporary file, synced, renamed, then read back and checked by SHA-256.
 * [FileBackupStoreTest] pins each step.
 */
class FileBackupStore(
    private val root: File,
    private val io: CoroutineDispatcher,
    /** How many copies each vault keeps, as set in Vault backups. */
    private val keep: () -> Int = { BackupRetention.DEFAULT_KEEP },
    /** True for a folder (named by its location hash) whose save marker is pending. */
    private val pinned: (folderName: String) -> Boolean = { false },
    private val now: () -> Instant = Instant::now,
) : BackupStore {

    // One add at a time: an open's backup and a save's can race, and each must see the other's
    // file.
    private val adding = Mutex()

    override suspend fun add(location: String, bytes: ByteArray, kind: BackupKind): BackupResult = adding.withLock { withContext(io) { addNow(location, bytes, kind) } }

    private fun addNow(location: String, bytes: ByteArray, kind: BackupKind): BackupResult {
        val folder = folder(location)
        val sha = Sha256.hex(bytes)
        if (infos(folder).firstOrNull()?.sha256 == sha) return BackupResult.SameAsNewest
        val name = "${now().toEpochMilli()}-${kind.name.lowercase()}-$sha.kdbx"
        val target = File(folder, name)
        val temp = File(folder, "$name.tmp")
        try {
            if (!folder.isDirectory && !folder.mkdirs()) return BackupResult.Failed
            folder.listFiles { f -> f.name.endsWith(".tmp") }?.forEach { it.delete() }
            FileOutputStream(temp).use {
                it.write(bytes)
                it.fd.sync()
            }
            if (!temp.renameTo(target) || Sha256.hex(target.readBytes()) != sha) {
                temp.delete()
                target.delete()
                return BackupResult.Failed
            }
        } catch (e: IOException) {
            temp.delete()
            target.delete()
            return BackupResult.Failed
        } catch (e: RuntimeException) {
            // A SecurityException from storage, or any other exception: a failed backup, no crash.
            temp.delete()
            target.delete()
            return BackupResult.Failed
        } catch (e: OutOfMemoryError) {
            // The read-back of a large vault on a small heap.
            temp.delete()
            target.delete()
            return BackupResult.Failed
        }
        // The backup is kept; trimming older ones is best effort. A before-save copy trims nothing.
        if (kind != BackupKind.BEFORE_SAVE) trim(folder, keep(), justAdded = name)
        val all = try {
            infos(folder)
        } catch (e: RuntimeException) {
            emptyList()
        }
        return BackupResult.Added(all.firstOrNull { it.id == name } ?: BackupInfo(name, now(), bytes.size.toLong(), kind, sha))
    }

    override suspend fun keepNewest(location: String, count: Int): Int = adding.withLock { withContext(io) { trim(folder(location), count) } }

    // Deletes the folder's copies beyond the newest [count]; returns how many it deleted. Never
    // throws.
    private fun trim(folder: File, count: Int, justAdded: String? = null): Int = try {
        if (pinned(folder.name)) 0 else BackupRetention.toDelete(infos(folder), count, justAdded).count { File(folder, it.id).delete() }
    } catch (e: RuntimeException) {
        0
    }

    /**
     * Trims each vault's folder to the backup count, except a folder whose save is unverified,
     * and removes leftover temporary files, so a vault that isn't opened keeps no more copies than
     * that. Runs under the same lock as [add], so it never removes the temporary file of an add in
     * progress. Never throws.
     */
    suspend fun pruneAll() = adding.withLock {
        withContext(io) {
            val folders = try {
                root.listFiles { f -> f.isDirectory }.orEmpty()
            } catch (e: RuntimeException) {
                emptyArray()
            }
            for (folder in folders) {
                try {
                    folder.listFiles { f -> f.name.endsWith(".tmp") }?.forEach { it.delete() }
                    trim(folder, keep())
                } catch (e: RuntimeException) {
                    // A failure in one folder doesn't stop pruning the others.
                }
            }
        }
    }

    override suspend fun delete(location: String, id: String): BackupDeletion = adding.withLock {
        withContext(io) {
            // Only names this store generated; anything else (a path, "..") is refused.
            if (!NAME.matches(id)) return@withContext BackupDeletion.NotFound
            try {
                val folder = folder(location)
                val all = infos(folder)
                when {
                    all.none { it.id == id } -> BackupDeletion.NotFound
                    all.first().id == id -> BackupDeletion.Newest
                    pinned(folder.name) -> BackupDeletion.Pinned
                    File(folder, id).delete() -> BackupDeletion.Deleted
                    else -> BackupDeletion.Failed
                }
            } catch (e: RuntimeException) {
                // A SecurityException from storage, or any other: a failed delete, no crash.
                BackupDeletion.Failed
            }
        }
    }

    override suspend fun list(location: String): List<BackupInfo> = withContext(io) { infos(folder(location)) }

    override suspend fun read(location: String, id: String): ByteArray? = withContext(io) {
        // Only names this store generated; anything else (a path, "..") is refused.
        if (!NAME.matches(id)) return@withContext null
        try {
            File(folder(location), id).takeIf { it.isFile }?.readBytes()
        } catch (e: IOException) {
            null
        }
    }

    private fun folder(location: String) = File(root, Sha256.ofLocation(location))

    private fun infos(folder: File): List<BackupInfo> =
        folder.listFiles().orEmpty().mapNotNull { file ->
            val m = NAME.matchEntire(file.name) ?: return@mapNotNull null
            val (millis, kind, sha) = m.destructured
            BackupInfo(file.name, Instant.ofEpochMilli(millis.toLong()), file.length(), BackupKind.valueOf(kind.uppercase()), sha)
        }.sortedWith(BackupRetention.NEWEST_FIRST)

    private companion object {
        val NAME = Regex("""(\d{1,19})-(opened|before_save|saved)-([0-9a-f]{64})\.kdbx""")
    }
}
