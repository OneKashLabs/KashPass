package org.onekash.kashpass.ui.components

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import androidx.core.net.toUri

/**
 * Opens an http or https [link] in the browser. Returns false for any other scheme and when no
 * app takes the link. Entry URLs reach here through [org.onekash.kashpass.ui.format.WebLink];
 * the About links are string resources. CATEGORY_BROWSABLE limits the handlers to browsers and
 * apps that accept links from a browser. This is the one place the app sends ACTION_VIEW;
 * [org.onekash.kashpass.ArchitectureRulesTest] checks that, and [OpenLinkTest] covers the rest.
 */
fun openWebLink(context: Context, link: String): Boolean {
    val uri = link.toUri()
    if (uri.scheme != "http" && uri.scheme != "https") return false
    val intent = Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE)
    return try {
        context.startActivity(intent)
        true
    } catch (e: ActivityNotFoundException) {
        false
    }
}
