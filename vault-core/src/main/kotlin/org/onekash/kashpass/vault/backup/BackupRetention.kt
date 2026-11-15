package org.onekash.kashpass.vault.backup

/**
 * Which backups to keep: the newest `keep`, by count only; the newest is never deleted. The user
 * sets `keep` from [MIN_KEEP] to [MAX_KEEP]. [BackupRetentionTest] pins it.
 */
object BackupRetention {

    const val MIN_KEEP = 1
    const val MAX_KEEP = 30
    const val DEFAULT_KEEP = 3

    /** Returns a saved count when it is in range, else [DEFAULT_KEEP]. */
    fun keepOf(saved: Int?): Int = saved?.takeIf { it in MIN_KEEP..MAX_KEEP } ?: DEFAULT_KEEP

    /** Returns [keep] limited to [MIN_KEEP]..[MAX_KEEP]. */
    fun clamp(keep: Int): Int = keep.coerceIn(MIN_KEEP, MAX_KEEP)

    /** Orders backups newest first: by time, then by id. */
    val NEWEST_FIRST: Comparator<BackupInfo> = compareByDescending<BackupInfo> { it.createdAt }.thenByDescending { it.id }

    /**
     * Returns the backups to delete from [backups] to keep the newest [keep]. [justAdded] counts as
     * the newest whatever its time, so a copy named with a clock that ran ahead can't push out the
     * copy the current save or unlock wrote.
     */
    fun toDelete(backups: List<BackupInfo>, keep: Int, justAdded: String? = null): List<BackupInfo> {
        val ordered = backups.sortedWith(NEWEST_FIRST)
        val first = ordered.filter { it.id == justAdded }
        return (first + (ordered - first.toSet())).drop(clamp(keep))
    }
}
