package org.onekash.kashpass.ui.format

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import org.onekash.kashpass.R
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.storage.Writability

/** What the user can do about a save that didn't succeed. */
enum class SaveChoice { RETRY, SAVE_AS_COPY, RELOAD, KEEP_EDITING }

/**
 * Maps every save result to its message and choices: no result has an overwrite choice. Retry
 * shows only when the file is known to be unchanged; after a write that can have changed it, the
 * choices are a copy, a reload or going back. [SaveProblemTest] pins the table.
 */
object SaveProblem {

    /** Returns the message string for [result]; every subclass has one. */
    fun message(result: SaveResult): Int = when (result) {
        is SaveResult.Saved -> R.string.notice_saved
        is SaveResult.Conflict -> R.string.problem_conflict
        is SaveResult.NotReachable -> R.string.problem_not_reachable
        is SaveResult.NotWritable -> when (result.reason) {
            Writability.NO_WRITE_GRANT -> R.string.save_no_write_grant
            Writability.NOT_CONTENT -> R.string.save_not_content
            Writability.UNAVAILABLE, Writability.TIMED_OUT -> R.string.save_unavailable
            Writability.NOT_WRITABLE, Writability.WRITABLE -> R.string.save_not_writable
        }
        is SaveResult.ReadOnly -> R.string.save_read_only
        is SaveResult.KdfRefused -> R.string.problem_kdf_refused
        is SaveResult.BackupFailed -> R.string.problem_backup_failed
        is SaveResult.WriteFailed -> R.string.problem_unchanged
        is SaveResult.NotSavedUnchanged -> R.string.problem_unchanged
        is SaveResult.MaybeDamaged -> R.string.problem_maybe_damaged
        is SaveResult.VerifyFailed -> R.string.problem_verify_failed
        is SaveResult.WriterStillRunning -> R.string.problem_still_writing
        is SaveResult.NotEnoughMemory -> R.string.problem_memory
        is SaveResult.UnexpectedError -> R.string.problem_unexpected
    }

    /** Returns the choices for [result], in display order. */
    fun choices(result: SaveResult): List<SaveChoice> {
        val copy = result.prepared != null
        // True when the file is known to be unchanged. An unexpected error leaves the baseline
        // known only when the write never started.
        val unchanged = when (result) {
            is SaveResult.NotReachable, is SaveResult.BackupFailed, is SaveResult.WriteFailed, is SaveResult.NotSavedUnchanged, is SaveResult.WriterStillRunning -> true
            is SaveResult.UnexpectedError -> result.opened.baseline is OpenedVault.Baseline.Known
            else -> false
        }
        val reload = when (result) {
            is SaveResult.Conflict, is SaveResult.VerifyFailed, is SaveResult.MaybeDamaged -> true
            is SaveResult.UnexpectedError -> !unchanged
            else -> false
        }
        return buildList {
            if (copy && unchanged) add(SaveChoice.RETRY)
            if (copy) add(SaveChoice.SAVE_AS_COPY)
            if (reload) add(SaveChoice.RELOAD)
            add(SaveChoice.KEEP_EDITING)
        }
    }

    /** Returns true for refusals the editor explains in place, with no sheet. */
    fun inline(result: SaveResult) = result is SaveResult.NotWritable || result is SaveResult.ReadOnly

    /**
     * Returns the name suggested for a copy, from [pattern] ("%1${'$'}s (device %2${'$'}s).kdbx"):
     * the vault's name without ".kdbx", or [fallback], and the time as yyyy-MM-dd HHmm.
     */
    fun copyName(pattern: String, fallback: String, displayName: String?, now: LocalDateTime): String {
        val base = displayName?.removeSuffix(".kdbx")?.ifBlank { null } ?: fallback
        return String.format(pattern, base, now.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HHmm")))
    }
}
