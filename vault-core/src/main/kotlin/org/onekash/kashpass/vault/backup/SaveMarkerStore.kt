package org.onekash.kashpass.vault.backup

/**
 * The pending-save marker: set before a save writes the file and cleared when the result is
 * known, so an open after a killed process can tell whether the file holds the old bytes, the new
 * ones, or neither. It keeps only hashes, never a location, name or content.
 */
interface SaveMarkerStore {

    /**
     * Records that [location] is about to change from [oldSha256] to [newSha256]. Durable on
     * return.
     */
    fun set(location: String, oldSha256: String, newSha256: String)

    /** Returns the marker for [location], or null. */
    fun get(location: String): SaveMarker?

    /** Removes the marker for [location]. Durable on return. */
    fun clear(location: String)
}

/** A pending save: the file's SHA-256 before the write and the bytes being written. */
data class SaveMarker(val oldSha256: String, val newSha256: String)
