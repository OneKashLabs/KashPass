package org.onekash.kashpass.vault.doc

import java.time.Duration
import java.time.Instant
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * The newest change time a vault records, used to notice a file replaced by an older version of
 * itself (for example one restored from a storage app's version history). The times read are
 * those a writer stamps on a change: entry and group times, each deletion
 * (`DeletedObject/DeletionTime`),
 * Meta settings (`SettingsChanged` and the other `*Changed` elements of Meta) and custom data
 * items (`CustomData/Item/LastModificationTime`, written for Meta, groups and entries).
 * [NewestChangeTest] pins the sources.
 */
object NewestChange {

    // A writer with a clock far ahead must not make every later file look old.
    private val FUTURE_SLACK: Duration = Duration.ofDays(1)

    private val TIME_ELEMENTS = setOf("LastModificationTime", "LocationChanged", "DeletionTime")

    /** Returns the latest change time in [document] no later than a day after [now], or null. */
    fun of(document: VaultDocument, now: Instant): Instant? {
        val limit = now.plus(FUTURE_SLACK)
        var newest: Instant? = null
        fun consider(element: XmlElement) {
            val time = KdbxTime.parse(element.text()) ?: return
            if (time.isAfter(limit)) return
            if (newest == null || time.isAfter(newest)) newest = time
        }
        fun walk(element: XmlElement) {
            for (child in element.elements()) {
                if (child.name in TIME_ELEMENTS) consider(child) else walk(child)
            }
        }
        val root = document.xml.root
        root.child("Meta")?.let { meta ->
            for (child in meta.elements()) if (child.name.endsWith("Changed")) consider(child)
            walk(meta)
        }
        // The root group a reader keeps ([rootGroupOf]) and the deleted objects of every Root.
        rootGroupOf(root)?.let(::walk)
        for (r in root.children("Root")) for (d in r.children("DeletedObjects")) walk(d)
        return newest
    }
}
