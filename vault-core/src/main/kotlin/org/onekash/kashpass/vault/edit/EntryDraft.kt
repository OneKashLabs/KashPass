package org.onekash.kashpass.vault.edit

import org.onekash.kashpass.vault.doc.ProtectedText

/** The five standard fields of an entry as the editor holds them. */
class EntryDraft(
    val title: String,
    val userName: String,
    val password: ProtectedText,
    val url: String,
    val notes: String,
) {
    override fun toString() = "EntryDraft(****)"
}

/** Outcome of [EntryEdits.edit]. */
sealed interface EditResult {
    /** Nothing differs from the entry; nothing changes and nothing needs saving. */
    data object Unchanged : EditResult

    /** The entry is missing from the document (deleted in another app). */
    data object EntryNotFound : EditResult

    /** The edited document; the session's document is untouched. */
    class Changed(val document: org.onekash.kashpass.vault.doc.VaultDocument) : EditResult
}

/** Outcome of [EntryEdits.add]: the document with the new entry and the entry's id in the index. */
class Added(val document: org.onekash.kashpass.vault.doc.VaultDocument, val entryId: String)

/** A group a new entry can go into. [label] is the path below the top level. */
data class GroupChoice(val id: String, val label: String, val isTopLevel: Boolean)
