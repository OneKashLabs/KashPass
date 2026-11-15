package org.onekash.kashpass.ui.browse

import org.onekash.kashpass.vault.index.EntryRow

/** One item of the entry list: a letter header or an entry row. */
sealed interface ListEntry {
    val key: String

    data class Header(val letter: String, override val key: String) : ListEntry

    data class Row(val row: EntryRow) : ListEntry {
        override val key: String get() = row.id
    }
}

/**
 * Puts a header before each run of [rows] whose titles share an initial, keeping the rows' order
 * (A to Z, untitled last). A letter can head two runs (digits sort first and untitled entries
 * last, both under "#"), so header keys carry their position.
 */
fun withLetterHeaders(rows: List<EntryRow>): List<ListEntry> = buildList {
    var current: String? = null
    for ((i, row) in rows.withIndex()) {
        val letter = initialOf(row.title)
        if (letter != current) {
            add(ListEntry.Header(letter, "header:$i:$letter"))
            current = letter
        }
        add(ListEntry.Row(row))
    }
}

/** Returns the uppercased first letter of [title], or "#" for a digit, a symbol or no title. */
fun initialOf(title: String?): String {
    val first = title?.firstOrNull() ?: return "#"
    return if (first.isLetter()) first.uppercase() else "#"
}
