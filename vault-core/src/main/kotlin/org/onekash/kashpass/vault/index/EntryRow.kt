package org.onekash.kashpass.vault.index

import java.time.Instant

/**
 * One row of the vault browser.
 *
 * [title] is null for an entry without a title; the app shows its own "(untitled)" label.
 * [groupName] is the entry's direct group, null for entries in the root group.
 * [expiry] follows [EntryDetails.expiry], so the list can mark expired entries.
 */
data class EntryRow(
    val id: String,
    val title: String?,
    val userName: String,
    val groupName: String?,
    val inRecycleBin: Boolean,
    val expiry: Instant? = null,
)

/** A filter chip above the list. */
sealed interface Chip {

    /** Every entry outside the recycle bin. */
    data object All : Chip

    /** Entries held directly by one group; [label] reads "Parent / Name" when names repeat. */
    data class Group(val id: String, val label: String) : Chip

    /** Entries in the recycle bin, shown only when this chip is selected. */
    data object RecycleBin : Chip
}
