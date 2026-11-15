package org.onekash.kashpass.ui.format

import java.util.Locale

/**
 * Checks whether an entry's URL opens in the browser. Only http and https open; a bare host such as
 * "example.com" or "localhost:8080" gets https://. Every other scheme is refused: a cmd:// URL is a
 * program for the desktop app to run, and schemes such as file:, intent: and javascript: reach
 * other apps' data. A URL holding a placeholder ({...}) after its field references are resolved
 * needs the desktop app to fill it in. User info ("bank.example@other.example", or an email
 * address) shows one host and opens another. Neither opens. [WebLinkTest] covers each case.
 */
object WebLink {

    private val SCHEME = Regex("^([A-Za-z][A-Za-z0-9+.-]*):(.*)$")
    private val PORT = Regex("^[0-9]+([/?#].*)?$")

    /** Returns the link to hand to the browser, or null when [url] must not open. */
    fun of(url: String): String? {
        val text = url.trim()
        if (text.isEmpty() || text.any { it.isWhitespace() } || '{' in text) return null
        val scheme = SCHEME.find(text)
        if (scheme != null && !PORT.matches(scheme.groupValues[2])) {
            val name = scheme.groupValues[1].lowercase(Locale.ROOT)
            val rest = scheme.groupValues[2]
            if (name != "http" && name != "https" || !rest.startsWith("//")) return null
            // Lower case: Android matches intent-filter schemes case-sensitively.
            return "$name:$rest".takeIf { authority(rest.removePrefix("//")) != null }
        }
        // No scheme, or host:port: require a dotted host or localhost.
        if (text.startsWith("/")) return null
        val host = authority(text) ?: return null
        val name = host.substringBefore(':')
        if (name != "localhost" && '.' !in name) return null
        return "https://$text"
    }

    // The host and port before any path, or null when empty or carrying user info.
    private fun authority(afterSlashes: String): String? {
        val end = afterSlashes.indexOfAny(charArrayOf('/', '?', '#')).let { if (it < 0) afterSlashes.length else it }
        val authority = afterSlashes.substring(0, end)
        return authority.takeIf { it.isNotEmpty() && '@' !in authority }
    }
}
