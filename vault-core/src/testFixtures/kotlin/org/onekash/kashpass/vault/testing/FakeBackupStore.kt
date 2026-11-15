package org.onekash.kashpass.vault.testing

import java.time.Instant
import org.onekash.kashpass.vault.backup.BackupDeletion
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.backup.BackupRetention
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.backup.Sha256

/**
 * Shared in-memory fake of [BackupStore]: the same skip-if-newest, count, kind and delete rules
 * as the app's store, a settable clock and count, a pinned switch (a pending save marker),
 * switches that make adds or deletes fail (full or failing storage), a way to damage a kept
 * backup's bytes, as failing phone storage does, and a switch that refuses every call
 * ([refuseAll]).
 */
class FakeBackupStore(var now: () -> Instant = Instant::now) : BackupStore {

    /** When true, every call records its name in [refused] and throws an AssertionError. */
    var refuseAll = false

    /** The name of each call made while [refuseAll] was on, in order. */
    val refused = mutableListOf<String>()

    private fun guard(name: String) {
        if (!refuseAll) return
        refused += name
        throw AssertionError("backups.$name")
    }

    private val backups = mutableMapOf<String, MutableList<Pair<BackupInfo, ByteArray>>>()
    private var counter = 0

    /** How many copies each location keeps. */
    var keep = BackupRetention.DEFAULT_KEEP

    /** Locations whose copies nothing deletes, as while a save marker is pending. */
    var pinned: Set<String> = emptySet()

    /** When true, every [delete] of an existing, deletable copy fails. */
    var failDeletes = false

    /** When true, every [add] fails. */
    var failing = false

    /** Kinds whose [add] fails while others succeed. */
    var failingKinds: Set<BackupKind> = emptySet()

    /** Flips one byte of backup [id] of [location]; its name keeps the old hash. */
    fun corrupt(location: String, id: String) {
        val bytes = backups.getValue(location).first { it.first.id == id }.second
        bytes[bytes.size / 2] = (bytes[bytes.size / 2].toInt() xor 1).toByte()
    }

    /** Removes copy [id] of [location] with no rule applied, as lost storage would. */
    fun drop(location: String, id: String) {
        backups[location]?.removeAll { it.first.id == id }
    }

    /** Every add attempt, in order: location and kind. */
    val attempts = mutableListOf<Pair<String, BackupKind>>()

    override suspend fun add(location: String, bytes: ByteArray, kind: BackupKind): BackupResult {
        guard("add")
        attempts += location to kind
        if (failing || kind in failingKinds) return BackupResult.Failed
        val list = backups.getOrPut(location) { mutableListOf() }
        val sha = Sha256.hex(bytes)
        if (list.maxByOrNull { it.first.createdAt }?.first?.sha256 == sha) return BackupResult.SameAsNewest
        val info = BackupInfo("backup-${++counter}", now(), bytes.size.toLong(), kind, sha)
        list += info to bytes.copyOf()
        if (kind != BackupKind.BEFORE_SAVE) trim(location, keep, info.id)
        return BackupResult.Added(info)
    }

    override suspend fun keepNewest(location: String, count: Int): Int {
        guard("keepNewest")
        return trim(location, count)
    }

    private fun trim(location: String, count: Int, justAdded: String? = null): Int {
        if (location in pinned) return 0
        val list = backups[location] ?: return 0
        val doomed = BackupRetention.toDelete(list.map { it.first }, count, justAdded).toSet()
        list.removeAll { it.first in doomed }
        return doomed.size
    }

    override suspend fun delete(location: String, id: String): BackupDeletion {
        guard("delete")
        val list = backups[location] ?: return BackupDeletion.NotFound
        val entry = list.firstOrNull { it.first.id == id } ?: return BackupDeletion.NotFound
        return when {
            list(location).first().id == id -> BackupDeletion.Newest
            location in pinned -> BackupDeletion.Pinned
            failDeletes -> BackupDeletion.Failed
            else -> {
                list.remove(entry)
                BackupDeletion.Deleted
            }
        }
    }

    override suspend fun list(location: String): List<BackupInfo> {
        guard("list")
        return backups[location].orEmpty().map { it.first }.sortedWith(BackupRetention.NEWEST_FIRST)
    }

    override suspend fun read(location: String, id: String): ByteArray? {
        guard("read")
        return backups[location]?.firstOrNull { it.first.id == id }?.second?.copyOf()
    }
}
