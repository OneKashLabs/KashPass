package org.onekash.kashpass.session

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.time.Instant
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultSession

/** Which file an unlock belongs to; distinct from how it was unlocked (its UnlockOrigin). */
enum class VaultTarget {
    /** The remembered vault file. */
    REMEMBERED,

    /** A backup of the remembered vault, open read-only in place of the file. */
    BACKUP,

    /**
     * A file another app handed over, open read-only for this session. Nothing about it is
     * stored: no biometric key, offer, backup or file state.
     */
    SESSION_ONLY,
}

/**
 * Holds the unlocked vault and what the browser shows about how it was opened. [backup] is set
 * when a backup is open (read-only) instead of the file. [fileNewest] is the open file's newest
 * change and [olderThan] the newer one seen before, both from [OpenResult.Unlocked]; [olderThan]
 * is null unless the file is older, and is cleared in place when the user accepts the file, so
 * operations holding this object stay valid. [sessionName] is the name a [VaultTarget.SESSION_ONLY]
 * file shows, which the remembered vault's name doesn't describe. [bytesAfterEnd] is
 * [OpenResult.Unlocked.bytesAfterEnd] of the bytes the session holds.
 */
class Unlocked(
    val location: String,
    val session: VaultSession,
    val kdf: KdfSettings,
    val showWeakWarning: Boolean,
    val backup: BackupInfo? = null,
    olderThan: Instant? = null,
    val fileNewest: Instant? = null,
    val sessionName: String? = null,
    val bytesAfterEnd: Boolean = false,
) {
    /**
     * Which file this unlock belongs to. A session opened with [FileAccess.SESSION_ONLY] is
     * session-only, and every vault made from it keeps that access ([OpenedVault.access]), so a
     * save or reload keeps the target. Read at construction, so [session] must be open.
     */
    val target: VaultTarget = when {
        session.opened.access == FileAccess.SESSION_ONLY -> VaultTarget.SESSION_ONLY
        backup != null -> VaultTarget.BACKUP
        else -> VaultTarget.REMEMBERED
    }

    /** True for a file another app handed over ([VaultTarget.SESSION_ONLY]). */
    val sessionOnly: Boolean get() = target == VaultTarget.SESSION_ONLY

    @Volatile
    var olderThan: Instant? = olderThan

    /**
     * True once the browser has put focus in its search field for this session. It lives here,
     * not in a view model, so an activity recreated while unlocked doesn't open the keyboard again.
     */
    @Volatile
    var searchFocusGiven: Boolean = false

    /** True once the user dismissed the row about data after the end; kept across saves. */
    @Volatile
    var bytesAfterEndDismissed: Boolean = false

    /**
     * Returns the same unlock with [session] in place of the current one (after a save or
     * reload). [session]'s access sets a session-only target ([target]); otherwise [backup]
     * selects the remembered file or a backup.
     */
    fun withSession(
        session: VaultSession,
        kdf: KdfSettings = this.kdf,
        backup: BackupInfo? = this.backup,
        olderThan: Instant? = this.olderThan,
        fileNewest: Instant? = this.fileNewest,
        bytesAfterEnd: Boolean = this.bytesAfterEnd,
    ) = Unlocked(location, session, kdf, showWeakWarning, backup, olderThan, fileNewest, sessionName, bytesAfterEnd)
        .also {
            it.searchFocusGiven = searchFocusGiven
            it.bytesAfterEndDismissed = bytesAfterEndDismissed
        }
}

/**
 * Holds the one unlocked session; every screen reads it from [current]. [lock]
 * releases it, so a reference kept elsewhere holds no vault data.
 */
class SessionHolder {

    private val state = MutableStateFlow<Unlocked?>(null)

    /**
     * Runs once for every [lock], from any caller; the app clears the clipboard here. It must
     * not throw: the clipboard guards its own calls.
     */
    @Volatile
    var onLock: () -> Unit = {}

    // True when [announceLock] ran [onLock] for the next [lock].
    @Volatile
    private var announced = false

    /** The unlocked vault, or null while locked. */
    val current: StateFlow<Unlocked?> = state.asStateFlow()

    private val locks = MutableStateFlow(0L)

    /**
     * Number of [lock] calls, observable: a lock-screen unlock running at a lock is cancelled
     * (LockViewModel), and a result that arrives after a lock sees a changed count and is
     * discarded.
     */
    val lockCounts: StateFlow<Long> = locks.asStateFlow()

    /** The current value of [lockCounts]. */
    val lockCount: Long get() = locks.value

    /** Makes [unlocked] the current session, releasing any previous one. */
    fun set(unlocked: Unlocked) {
        state.value?.session?.release()
        state.value = unlocked
    }

    /**
     * Puts [session] in place of the current one, keeping the rest of the unlock, when [expected]
     * is current; returns false (and releases [session]) when a lock or another unlock came
     * first. The replaced session's vault shares the credentials, which only a lock drops.
     */
    fun replace(
        expected: Unlocked,
        session: VaultSession,
        kdf: KdfSettings = expected.kdf,
        backup: BackupInfo? = expected.backup,
        olderThan: Instant? = expected.olderThan,
        fileNewest: Instant? = expected.fileNewest,
        bytesAfterEnd: Boolean = expected.bytesAfterEnd,
    ): Boolean {
        if (state.value !== expected) {
            session.release()
            return false
        }
        set(expected.withSession(session, kdf, backup, olderThan, fileNewest, bytesAfterEnd))
        return true
    }

    /**
     * Runs [onLock] now for a [lock] that waits for a save to end; that [lock] doesn't run it
     * again.
     */
    fun announceLock() {
        if (announced) return
        announced = true
        onLock()
    }

    /** Releases the session, returns to the locked state and runs [onLock] once. */
    fun lock() {
        locks.update { it + 1 }
        state.value?.session?.release()
        state.value = null
        if (announced) announced = false else onLock()
    }
}
