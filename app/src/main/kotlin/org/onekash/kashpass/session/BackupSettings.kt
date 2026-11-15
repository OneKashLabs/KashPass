package org.onekash.kashpass.session

import org.onekash.kashpass.vault.backup.BackupDeletion
import org.onekash.kashpass.vault.backup.BackupRetention
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.storage.VaultStateStore

/** Outcome of a change in [BackupSettings]. */
sealed interface BackupChange {
    /** The change is saved; [keep] is the count and [copies] the open file's copies after it. */
    data class Done(val keep: Int, val copies: Int) : BackupChange

    /**
     * Nothing changed: it would delete more copies than the user confirmed (a save added one since
     * the screen counted). [copies] is the current count, for the screen to show the confirm again.
     */
    data class Recount(val copies: Int) : BackupChange
}

/**
 * Reads and changes the backup count for the open file, and deletes single copies ([delete]).
 * Lowering the count trims the open file's copies at once; raising it deletes nothing. A change
 * deletes no more copies than the caller confirmed, counted again here. The count doesn't change
 * while a backup is open (a copy on screen is never deleted under it) or without a session;
 * [delete] runs without a session, on a location [deletable] returned. [pending] is true while a
 * save marker is set for a location; the store deletes none of its copies then.
 * [BackupSettingsTest] covers it.
 */
class BackupSettings(
    private val state: VaultStateStore,
    private val backups: BackupStore,
    private val sessions: SessionHolder,
    private val pending: (location: String) -> Boolean,
) {
    /** Returns how many copies each vault keeps. */
    fun keep(): Int = BackupRetention.keepOf(state.backupKeep())

    /** Returns true while a save of the open file is unverified. */
    fun pinned(): Boolean = sessions.current.value?.let { pending(it.location) } == true

    /** Saves [count] as the count, trimming when it is lower; deletes at most [confirmed]. */
    suspend fun setKeep(count: Int, confirmed: Int): BackupChange? {
        val location = deletable() ?: return null
        val next = BackupRetention.clamp(count)
        val lower = next < keep()
        val copies = backups.list(location).size
        if (lower && copies - next > confirmed) return BackupChange.Recount(copies)
        state.saveBackupKeep(next)
        if (lower) backups.keepNewest(location, next)
        return BackupChange.Done(next, backups.list(location).size)
    }

    /**
     * Returns the open file's location for a delete to capture when it is staged; null for an
     * open backup or no session. [delete] trusts what this returned.
     */
    fun deletable(): String? = sessions.current.value?.takeIf { it.backup == null }?.location

    /**
     * Deletes backup [id] of [location] by [BackupStore.delete]. [location] must come from
     * [deletable] when the delete was staged; no session is needed, so a commit after a lock or
     * after a copy opened runs.
     */
    suspend fun delete(location: String, id: String): BackupDeletion = backups.delete(location, id)
}
