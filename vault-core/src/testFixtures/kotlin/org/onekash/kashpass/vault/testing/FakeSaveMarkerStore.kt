package org.onekash.kashpass.vault.testing

import org.onekash.kashpass.vault.backup.SaveMarker
import org.onekash.kashpass.vault.backup.SaveMarkerStore

/** Shared in-memory fake of [SaveMarkerStore]; [history] records every set and clear. */
class FakeSaveMarkerStore : SaveMarkerStore {

    /** When true, every call records its name in [refused] and throws an AssertionError. */
    var refuseAll = false

    /** The name of each call made while [refuseAll] was on, in order. */
    val refused = mutableListOf<String>()

    private fun guard(name: String) {
        if (!refuseAll) return
        refused += name
        throw AssertionError("markers.$name")
    }

    private val markers = mutableMapOf<String, SaveMarker>()

    /** "set" or "clear" per call, in order. */
    val history = mutableListOf<String>()

    override fun set(location: String, oldSha256: String, newSha256: String) {
        guard("set")
        history += "set"
        markers[location] = SaveMarker(oldSha256, newSha256)
    }

    override fun get(location: String): SaveMarker? {
        guard("get")
        return markers[location]
    }

    override fun clear(location: String) {
        guard("clear")
        history += "clear"
        markers.remove(location)
    }
}
