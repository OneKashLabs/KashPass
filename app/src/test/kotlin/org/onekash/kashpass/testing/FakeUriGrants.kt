package org.onekash.kashpass.testing

import android.net.Uri
import androidx.core.net.toUri
import org.onekash.kashpass.platform.ResolverUriGrants
import org.onekash.kashpass.platform.UriGrants

/**
 * Shared fake of [UriGrants]. It keeps the persisted grants in memory, as the system does, and
 * records every call in [calls] as "take <uri> READ" or "release <uri> READ_WRITE". A file in
 * [readOnly] gets a read grant only; with [refuseAll] every grant is refused. Releasing flags that
 * aren't held changes nothing, as [ResolverUriGrants] does.
 */
class FakeUriGrants(
    var readOnly: Set<String> = emptySet(),
    var refuseAll: Boolean = false,
) : UriGrants {

    private val held = linkedMapOf<String, Int>()

    val calls = mutableListOf<String>()

    override fun take(uri: Uri, flags: Int) {
        calls += "take $uri ${flagName(flags)}"
        if (refuseAll) throw SecurityException("no grant")
        if (uri.toString() in readOnly && flags != UriGrants.READ) throw SecurityException("read only")
        held[uri.toString()] = (held[uri.toString()] ?: 0) or flags
    }

    override fun release(uri: Uri, flags: Int) {
        calls += "release $uri ${flagName(flags)}"
        val left = (held[uri.toString()] ?: return) and flags.inv()
        if (left == 0) held.remove(uri.toString()) else held[uri.toString()] = left
    }

    override fun persisted(): List<Pair<Uri, Int>> = held.map { (location, flags) -> location.toUri() to flags }

    /** Returns the grants held now, by location. */
    fun held(): Map<String, Int> = held.toMap()

    private fun flagName(flags: Int) = if (flags == UriGrants.READ) "READ" else "READ_WRITE"
}
