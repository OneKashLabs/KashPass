package org.onekash.kashpass.platform

import android.content.Context
import androidx.core.content.edit
import org.onekash.kashpass.vault.backup.SaveMarker
import org.onekash.kashpass.vault.backup.SaveMarkerStore
import org.onekash.kashpass.vault.backup.Sha256

/**
 * Keeps pending-save markers in their own private preferences file, keyed by the hash of the
 * location, so no URI is stored. Writes commit synchronously: the marker must be on disk before
 * the save writes the vault, so callers must run on a background thread. [PrefsSaveMarkerStoreTest]
 * pins what is stored.
 */
class PrefsSaveMarkerStore(context: Context) : SaveMarkerStore {

    private val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    override fun set(location: String, oldSha256: String, newSha256: String) {
        prefs.edit(commit = true) { putString(Sha256.ofLocation(location), "$oldSha256:$newSha256") }
    }

    override fun get(location: String): SaveMarker? {
        val value = prefs.getString(Sha256.ofLocation(location), null) ?: return null
        val (old, new) = value.split(':').takeIf { it.size == 2 } ?: return null
        return SaveMarker(old, new)
    }

    /** Returns true when a marker is pending for the location whose hash is [locationHash]. */
    fun isPending(locationHash: String): Boolean = prefs.contains(locationHash)

    override fun clear(location: String) {
        prefs.edit(commit = true) { remove(Sha256.ofLocation(location)) }
    }

    private companion object {
        const val FILE = "save_markers"
    }
}
