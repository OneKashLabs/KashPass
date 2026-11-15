package org.onekash.kashpass.session

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.coroutineScope
import java.time.Clock
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference
import kotlin.time.Duration
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.edit.DeleteKind
import org.onekash.kashpass.vault.edit.EntryDelete
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.RefreshResult
import org.onekash.kashpass.vault.open.VaultOpening
import org.onekash.kashpass.vault.open.VaultSession
import org.onekash.kashpass.vault.save.CopyResult
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.save.VaultSaving
import kotlinx.coroutines.CancellationException
import org.onekash.kashpass.vault.storage.DeleteResult
import org.onekash.kashpass.vault.storage.ReadResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.VaultStorage
import org.onekash.kashpass.vault.storage.maxVaultBytes

/**
 * Runs saves for the unlocked session in [scope], which outlives screens, so a save finishes after
 * the editor closes and a lock can wait for it. Every result replaces the session with the vault
 * the result carries: the saved document after a save, otherwise the same document with the
 * baseline the save left (unknown after a write that can have changed the file).
 * [SaveCoordinatorTest] pins it.
 */
class SaveCoordinator(
    private val sessions: SessionHolder,
    private val saver: VaultSaving,
    private val opener: VaultOpening,
    private val scope: CoroutineScope,
    /** Visible to tests, which check that the graph hands every part the same storage. */
    internal val storage: VaultStorage? = null,
    private val backups: BackupStore? = null,
    /** Runs index rebuilds and deletes off the main thread. */
    private val compute: CoroutineDispatcher = Dispatchers.Default,
    private val clock: Clock = Clock.systemUTC(),
    /** The heap the read limit ([maxVaultBytes]) derives from. */
    private val maxHeapBytes: () -> Long = { Runtime.getRuntime().maxMemory() },
) {
    private val events = MutableSharedFlow<SaveEvent>(extraBufferCapacity = 8)

    // The unlock a pending lock is for; saves for it are refused until a new unlock.
    @Volatile
    private var locking: Unlocked? = null

    // True from [refuseNewSaves] until [cancelRunning]: a lock waits for the running jobs.
    @Volatile
    private var lockWaiting = false

    private val swapping = Mutex()

    // The end of the newest job [launch] started; the next job waits for it.
    private val previousDone = AtomicReference(CompletableDeferred(Unit))

    // Every running save, retry and copy, so a lock can wait for and cancel them.
    private val running = MutableStateFlow<Set<Job>>(emptySet())

    // The newest save or retry, whose result a lock reports.
    @Volatile
    private var latest: Deferred<SaveResult?>? = null

    // True once a save was refused because a lock was coming; its change is lost.
    @Volatile
    private var refusedForLock = false

    /** True while any save, retry or copy job runs, including recording its result. */
    val hasRunningJobs: Boolean get() = running.value.isNotEmpty()

    private val busyState = MutableStateFlow(false)

    /** Emits [hasRunningJobs]; the background keep-alive job and the browser's edit gate use it. */
    val busy: StateFlow<Boolean> = busyState.asStateFlow()

    // Running calls of [counted]; workLock guards it and the update of workingState.
    private val workLock = Any()
    private var inFlight = 0
    private val workingState = MutableStateFlow(false)

    /**
     * True while [busy] is true or a call wrapped in [counted] runs (the re-reads, reopens,
     * backup opens, copies and file details). The screens show progress from it.
     * The undo window alone leaves it false; its commit is a tracked job. [WorkingSignalTest]
     * pins it.
     */
    val working: StateFlow<Boolean> = workingState.asStateFlow()

    // Recomputes [busy] and [working] from the running jobs and [inFlight] under one lock, so
    // concurrent updates can't leave either stale.
    private fun updateWorking(delta: Int = 0) = synchronized(workLock) {
        inFlight += delta
        val jobs = running.value.isNotEmpty()
        busyState.value = jobs
        workingState.value = jobs || inFlight > 0
    }

    // Counts [block] in [working] until it returns, throws or is cancelled.
    private inline fun <T> counted(block: () -> T): T {
        updateWorking(+1)
        try {
            return block()
        } finally {
            updateWorking(-1)
        }
    }

    // Recycle-bin deletes held for the undo window, then written in one save. stageLock guards
    // these fields; the ids apply to stagedLocation only.
    private val stageLock = Any()
    private val pendingState = MutableStateFlow(PendingDeletes(emptyList(), emptySet()))
    private var stagedLocation: String? = null
    private var window: Job? = null

    // The running commit of staged deletes, so [commitPending] and [awaitCommit] wait for it.
    // Cleared when it ends: its result holds the decoded vault, which a lock must not keep.
    @Volatile
    private var lastCommit: Deferred<SaveResult?>? = null

    /** Holds staged deletes and deletes whose save is running. */
    val pendingDeletes: StateFlow<PendingDeletes> = pendingState.asStateFlow()

    init {
        // Drop staged deletes when the session ends or switches to another file.
        scope.launch { sessions.current.collect { u -> if (u == null || u.location != stagedLocation) undoStaged() } }
    }

    /**
     * Stages a move of [id] to the recycle bin without writing. The entry stays in
     * [PendingDeletes.hidden] until [window] elapses with no further delete, until [undoStaged],
     * or until another save, a backup open, a reload, an edit start, the move to the background
     * or a lock commits it. Returns false and stages nothing with no open session, for an open
     * backup, once a lock is pending, and for an unknown id or a delete that would be permanent
     * (that needs a confirmation).
     */
    fun stageDelete(id: String, window: Duration): Boolean {
        val unlocked = sessions.current.value ?: return false
        if (unlocked.backup != null || unlocked === locking || !unlocked.session.isOpen) return false
        if (EntryDelete.kindOf(unlocked.session.opened.document, id) != DeleteKind.TO_RECYCLE_BIN) return false
        synchronized(stageLock) {
            if (stagedLocation != unlocked.location) pendingState.update { it.copy(staged = emptyList()) }
            stagedLocation = unlocked.location
            pendingState.update { if (id in it.staged) it else it.copy(staged = it.staged + id) }
            this.window?.cancel()
            this.window = scope.launch {
                delay(window)
                commitStaged()
            }
        }
        return true
    }

    /** Clears the staged deletes (Undo); nothing was written for them. */
    fun undoStaged() = synchronized(stageLock) {
        window?.cancel()
        window = null
        pendingState.update { it.copy(staged = emptyList()) }
    }

    /**
     * Writes every staged delete in one save, after the saves started before it ([launch]), so it
     * starts from their result. A pending lock doesn't refuse it: staging stops once a lock is
     * pending, so every commit carries deletes made before it. Returns null when nothing is staged;
     * the job returns null when none of the deletes applies.
     */
    fun commitStaged(): Deferred<SaveResult?>? {
        val location = sessions.current.value?.location
        val ids = takeStaged(location)
        if (ids.isEmpty()) return null
        val job = launch(ids) {
            val basedOn = sessions.current.value?.takeIf { it.location == location } ?: return@launch null
            val opened = basedOn.session.takeIf { it.isOpen }?.opened ?: return@launch null
            perform(basedOn, opened, refused = false) {
                val document = withContext(compute) { applyDeletes(opened.document, ids) }
                if (document === opened.document) null else saver.save(it.location, opened.withDocument(document))
            }
        }
        lastCommit = job
        job.invokeOnCompletion { if (lastCommit === job) lastCommit = null }
        return job
    }

    /** Commits staged deletes and waits for that save, or for one already running. */
    suspend fun commitPending() {
        (commitStaged() ?: lastCommit)?.join()
    }

    /** Waits for a commit of staged deletes that is already running; starts none. */
    suspend fun awaitCommit() {
        lastCommit?.join()
    }

    // Moves [location]'s staged ids to committing, which stays hidden until the save's result is
    // recorded, and cancels the window.
    private fun takeStaged(location: String?): List<String> = synchronized(stageLock) {
        window?.cancel()
        window = null
        val ids = if (location != null && location == stagedLocation) pendingState.value.staged else emptyList()
        pendingState.update { PendingDeletes(emptyList(), it.committing + ids) }
        ids
    }

    private fun release(ids: List<String>) = pendingState.update { it.copy(committing = it.committing - ids.toSet()) }

    // A reload can put the entry in the bin or turn the bin off. Deleting it then is permanent and
    // unconfirmed, so it is skipped.
    private fun applyDeletes(document: VaultDocument, ids: List<String>): VaultDocument {
        val now = clock.instant()
        return ids.fold(document) { doc, id ->
            if (EntryDelete.kindOf(doc, id) == DeleteKind.TO_RECYCLE_BIN) EntryDelete.delete(doc, id, now)?.document ?: doc else doc
        }
    }

    /** True while a save or retry result is referenced; false after [cancelRunning]. */
    internal val holdsResult: Boolean get() = latest != null || retrying != null || lastCommit != null

    /** True while a save runs. */
    val isSaving: StateFlow<Boolean> get() = saver.isSaving

    /** Results to show once, in order. */
    val results: SharedFlow<SaveEvent> = events.asSharedFlow()

    private val problemState = MutableStateFlow<SaveResult?>(null)

    /** The last save that didn't succeed, until the user picks a choice or dismisses it. */
    val problem: StateFlow<SaveResult?> = problemState.asStateFlow()

    /** The last result that can be written again (Retry, Save as copy), or null. */
    val lastProblem: SaveResult? get() = problemState.value

    /** Re-reads the file before an edit of [entryId]; reloads the session when it changed. */
    suspend fun refreshForEdit(entryId: String): EditCheck = refresh { it.index.details(entryId) != null }

    /** Re-reads the file before a new entry; reloads the session when it changed. */
    suspend fun refreshForAdd(): EditCheck = refresh { true }

    // [stillThere] tells whether what the edit needs exists in a reloaded session.
    private suspend fun refresh(stillThere: (VaultSession) -> Boolean): EditCheck {
        counted {
            commitPending()
            // A lock waiting for a save releases the session once it ends; nothing derives first.
            if (lockWaiting) return EditCheck.Locked
            val unlocked = sessions.current.value ?: return EditCheck.Locked
            val refreshed = unlessLocked(unlocked, { (it as? RefreshResult.Reloaded)?.opened?.session }) {
                opener.refresh(unlocked.location, unlocked.session)
            } ?: return EditCheck.Locked
            return when (refreshed) {
                RefreshResult.Unchanged -> EditCheck.Ready
                is RefreshResult.Reloaded -> {
                    val session = refreshed.opened.session
                    val replaced = sessions.replace(
                        unlocked, session, refreshed.opened.kdf,
                        olderThan = refreshed.opened.olderThan, fileNewest = refreshed.opened.fileNewest,
                        bytesAfterEnd = refreshed.opened.bytesAfterEnd,
                    )
                    if (!replaced) return EditCheck.Locked
                    if (stillThere(session)) EditCheck.Updated else EditCheck.EntryGone
                }
                is RefreshResult.Failed -> EditCheck.Failed(refreshed.result)
            }
        }
    }

    /**
     * Saves [document], an edit of [basedOn]'s (by default the current session at the call), and
     * returns the result when known. Saves run in the order they were started ([launch]): when the
     * first of two saves from the same session writes the file, the second reports a conflict and
     * the first save's session stays shown. Staged deletes go into the same save.
     */
    fun save(document: VaultDocument, basedOn: Unlocked? = sessions.current.value): Deferred<SaveResult?> {
        // Taken at the call: a lock or reload can release the session before the save starts.
        val opened = basedOn?.session?.takeIf { it.isOpen }?.opened
        val refused = basedOn != null && basedOn === locking
        // Only a save that will run takes the staged deletes; a refused one leaves them staged.
        val ids = if (opened != null && !refused) takeStaged(basedOn.location) else emptyList()
        return run(basedOn, opened, ids, refused) {
            val withDeletes = if (ids.isEmpty()) document else withContext(compute) { applyDeletes(document, ids) }
            saver.save(it.location, opened!!.withDocument(withDeletes))
        }
    }

    /** Writes the bytes of the last failed save again; ignored while a retry runs. */
    fun retry(): Deferred<SaveResult?> {
        val prepared = lastProblem?.prepared
        val unlocked = sessions.current.value
        if (prepared == null || retrying?.isActive == true) return scope.async { null }
        return run(unlocked, unlocked?.session?.takeIf { it.isOpen }?.opened) { saver.retry(prepared) }.also { retrying = it }
    }

    @Volatile
    private var retrying: Job? = null

    // A save, or a retry, through [perform]. [refused] is set at the call: a lock requested
    // after it doesn't refuse the save, which runs under the cover.
    private fun run(
        basedOn: Unlocked?,
        opened: OpenedVault?,
        ids: List<String> = emptyList(),
        refused: Boolean = basedOn != null && basedOn === locking,
        block: suspend (Unlocked) -> SaveResult,
    ): Deferred<SaveResult?> = launch(ids) { perform(basedOn, opened, refused, block) }

    // Starts [body] as a tracked job that a lock waits for and reports; [ids] stay hidden until it
    // ends. Jobs run in start order: [body] starts once the job started before it has ended
    // (swapped in, refused, cancelled or failed), so the saver resolves overlapping saves
    // in that order and their results replace the session in that order ([SaveOrderTest]). A
    // job's end is passed on only after its predecessor's, so a cancelled job in the middle
    // doesn't let a later one overtake an earlier one.
    private fun launch(ids: List<String>, body: suspend () -> SaveResult?): Deferred<SaveResult?> {
        val done = CompletableDeferred<Unit>()
        val previous = previousDone.getAndSet(done)
        val job = scope.async(start = CoroutineStart.LAZY) {
            previous.await()
            body()
        }
        job.invokeOnCompletion { previous.invokeOnCompletion { done.complete(Unit) } }
        track(job)
        if (ids.isNotEmpty()) job.invokeOnCompletion { release(ids) }
        latest = job
        job.start()
        return job
    }

    /**
     * Runs [block] for [basedOn], whose vault [opened] was taken when the change was made; a null
     * from [block] means there was nothing to save. Nothing runs after a lock; [refused] (a lock
     * was pending when the save was requested) skips it. The result replaces the session only
     * while [basedOn] is the current session; otherwise the result is only reported, so every
     * save ends with a reported result. An exception from [block] or from the swap is reported as
     * [SaveResult.UnexpectedError]; [SaveCoordinatorTest] pins it.
     */
    private suspend fun perform(
        basedOn: Unlocked?,
        opened: OpenedVault?,
        refused: Boolean,
        block: suspend (Unlocked) -> SaveResult?,
    ): SaveResult? {
        if (refused) refusedForLock = true
        if (basedOn == null || opened == null || refused || sessions.current.value == null) return null
        val result = try {
            block(basedOn) ?: return null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // The saver can have started the write, so the file is treated as changed.
            SaveResult.UnexpectedError(opened.withBaseline(OpenedVault.Baseline.Unknown), null)
        }
        // A backstop to the [launch] order: the check, the swap and the report see one state.
        swapping.withLock {
            if (sessions.current.value == null) return null
            val reported = try {
                if (!swapIn(basedOn, opened, result)) return null
                result
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // The session stays on [basedOn], whose baseline is the file it read, so a later
                // save of a changed file stops as a conflict.
                SaveResult.UnexpectedError(opened.withBaseline(OpenedVault.Baseline.Unknown), result.prepared)
            }
            problemState.value = reported.takeIf { it !is SaveResult.Saved }
            events.tryEmit(SaveEvent(reported))
            return reported
        }
    }

    // Puts [result]'s vault in place of [basedOn] while it is the current session; false once a
    // lock came first.
    private suspend fun swapIn(basedOn: Unlocked, opened: OpenedVault, result: SaveResult): Boolean {
        if (sessions.current.value !== basedOn) return true
        // After a save the session holds what was written; after any other result it keeps the
        // document from before the edit, with the baseline the save left, so the browser never
        // shows an unsaved change and a second Save starts over.
        val kept = if (result is SaveResult.Saved) result.opened else opened.withBaseline(result.opened.baseline)
        val session = withContext(compute) { VaultSession.from(kept) }
        // A verified save is the newest version, so an older-file warning ends with it.
        val olderThan = if (result is SaveResult.Saved) null else basedOn.olderThan
        // KashPass writes nothing after the end block.
        val bytesAfterEnd = result !is SaveResult.Saved && basedOn.bytesAfterEnd
        return sessions.replace(basedOn, session, olderThan = olderThan, bytesAfterEnd = bytesAfterEnd) || sessions.current.value != null
    }

    private fun track(job: Job) {
        running.update { it + job }
        updateWorking()
        job.invokeOnCompletion {
            running.update { it - job }
            updateWorking()
        }
    }

    /** Returns the running save or retry; a lock requested now waits for it and reports it. */
    fun runningSave(): Deferred<SaveResult?>? = latest?.takeIf { it.isActive }

    /**
     * Waits until no job runs and returns what [save] (from [runningSave] at the lock request)
     * came to: its result once recorded (problem set, event sent), or null when there was none or
     * it was refused or cancelled. A job that ended with a throwable other than a cancellation
     * counts as failed ([Settled.failed]). [perform] turns an [Exception] from the save into a
     * [SaveResult], so this is the backstop for what it lets through: an [Error], or a throw
     * outside [perform]. A job's completion follows its recording, so the result is final when
     * this returns.
     */
    suspend fun settle(save: Deferred<SaveResult?>?): Settled {
        running.first { it.isEmpty() }
        // A job that threw also reports isCancelled, so the exception tells the two apart.
        val error = save?.takeIf { it.isCompleted }?.getCompletionExceptionOrNull()
        val failed = error != null && error !is CancellationException
        val result = if (save != null && save.isCompleted && error == null) save.getCompleted() else null
        return Settled(result, refusedForLock, failed)
    }

    /** Forgets the last failed save, as after "Keep editing" or a lock. */
    fun clearProblem() {
        problemState.value = null
    }

    /**
     * Writes the last failed save's bytes into [copyLocation], a file the create-document picker
     * made; the open vault stays on its own file. Null when there is nothing to copy; an exception
     * from the saver is [CopyResult.Failed].
     */
    suspend fun saveCopy(copyLocation: String): CopyResult? {
        counted {
            val prepared = lastProblem?.prepared ?: return null
            if (sessions.current.value == null || sessions.current.value === locking) return null
            // Tracked, so a lock cancels it: the copy holds the vault's key while it verifies.
            val job = scope.async { saver.saveCopy(prepared, copyLocation) }
            track(job)
            return try {
                job.await()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                CopyResult.Failed(copyLocation)
            }
        }
    }

    /** Deletes a copy file that was left empty, when its provider allows. */
    suspend fun deleteCopy(copyLocation: String): DeleteResult = counted { storage?.delete(copyLocation) ?: DeleteResult.UNSUPPORTED }

    /**
     * Drops the unsaved change and opens the file as it is on disk, with the session's key, once
     * the staged deletes are saved and no save runs, so the vault shown is the file after them.
     * Null when a lock came first, one that waits for the saves or one during the reopen, or when
     * a swap released the session during the reopen ([unlessLocked]).
     */
    suspend fun reload(): OpenResult? {
        counted {
            commitPending()
            running.first { it.isEmpty() }
            // A lock waiting for the same saves releases the session once they end.
            if (lockWaiting) return null
            val unlocked = sessions.current.value ?: return null
            val opened = unlessLocked(unlocked, ::openedSession) { opener.reopen(unlocked.location, unlocked.session) } ?: return null
            if (opened is OpenResult.Unlocked) {
                sessions.replace(unlocked, opened.session, opened.kdf, backup = null, olderThan = opened.olderThan, fileNewest = opened.fileNewest, bytesAfterEnd = opened.bytesAfterEnd)
                clearProblem()
            }
            return opened
        }
    }

    /**
     * Runs [call], an opener call on [unlocked]'s session, and returns null when a lock came during
     * it ([SessionHolder.lockCount] moved; read here, with no suspension since the caller read
     * [unlocked]) or the opener found the session released, by a lock or by a swap (its
     * IllegalStateException). A session the result opened ([sessionOf]) is released then. A
     * lock's cancel ([LockCancellation], from [cancelRunning]) also returns null while the caller
     * is active; any other CancellationException, which is an IllegalStateException on the JVM, and
     * an IllegalStateException with the session open and no lock are rethrown. Reload, refresh,
     * Open backup and Close backup use it, so a lock while the file is read is a lock to their
     * callers, never an exception that escapes a screen's coroutine. [SaveCoordinatorTest] and
     * [LockDuringFileReadTest] pin it.
     */
    private suspend fun <T : Any> unlessLocked(unlocked: Unlocked, sessionOf: (T) -> VaultSession?, call: suspend () -> T): T? {
        val locks = sessions.lockCount
        val result = try {
            // A child of the caller's job, so the caller's own cancel also reaches the opener.
            coroutineScope {
                val job = coroutineContext.job
                openerCalls.update { it + job }
                try {
                    call()
                } finally {
                    openerCalls.update { it - job }
                }
            }
        } catch (e: CancellationException) {
            // A lock cancelled the call ([cancelRunning]); an active caller gets locked.
            if (e is LockCancellation && currentCoroutineContext().isActive) return null
            throw e
        } catch (e: IllegalStateException) {
            if (sessions.lockCount == locks && unlocked.session.isOpen) throw e
            return null
        }
        if (sessions.lockCount != locks) {
            sessionOf(result)?.release()
            return null
        }
        return result
    }

    private fun openedSession(result: OpenResult): VaultSession? = (result as? OpenResult.Unlocked)?.session

    // The running opener calls ([unlessLocked]), which [cancelRunning] cancels. Kept apart
    // from [running]: busy, settle and a covered lock wait on saves, never on these.
    private val openerCalls = MutableStateFlow<Set<Job>>(emptySet())

    // The cause [cancelRunning] cancels opener calls with, so [unlessLocked] tells a lock from a
    // caller's own cancel; matched by type, since debug stack-trace recovery copies exceptions.
    private class LockCancellation : CancellationException("locked")

    /**
     * Accepts the open file although it is older than a version seen before; hides the warning.
     * Does nothing for a session-only file, which has no stored newest change.
     */
    suspend fun acceptOlderFile() {
        counted {
            val unlocked = sessions.current.value?.takeUnless { it.sessionOnly } ?: return
            val newest = unlocked.fileNewest ?: return
            opener.acceptNewest(unlocked.location, newest)
            // In place: a running save compares this object before it swaps the session. A
            // session swapped in while acceptNewest ran copied the warning, so it is cleared there
            // too.
            unlocked.olderThan = null
            sessions.current.value?.takeIf { it.location == unlocked.location && it.fileNewest == newest }?.olderThan = null
        }
    }

    /**
     * Shows [backup] read-only in place of the file, opened with the session's key; null for a
     * session-only file, which has no backups, with no session, while a lock waits for a save, or
     * when a lock or swap came during the open ([unlessLocked]).
     */
    suspend fun openBackup(backup: BackupInfo): OpenResult? {
        counted {
            commitPending()
            // A save that ends while the backup is on screen adds a copy and trims to the user's
            // count, which deletes the copy being viewed when it is the oldest; wait for it first.
            running.first { it.isEmpty() }
            if (lockWaiting) return null
            val unlocked = sessions.current.value?.takeUnless { it.sessionOnly } ?: return null
            val opened = unlessLocked(unlocked, ::openedSession) { opener.openBackup(unlocked.location, backup, unlocked.session) } ?: return null
            if (opened is OpenResult.Unlocked) sessions.replace(unlocked, opened.session, opened.kdf, backup = backup, bytesAfterEnd = opened.bytesAfterEnd)
            return opened
        }
    }

    /**
     * Writes the open backup's bytes, or the bytes of a file opened read-only for its grant
     * ([FileAccess.PROVIDER_READ_ONLY], [FileAccess.SESSION_ONLY]), into [copyLocation] with
     * [VaultSaving.saveBackupCopy]. [SaveBackupResult.BackupDamaged] when the kept bytes are
     * missing or don't hash to the backup's recorded SHA-256. A read-only file is read again:
     * [SaveBackupResult.FileChanged] when its SHA-256 differs from the bytes opened,
     * [SaveBackupResult.Failed] when it can't be read. Null when neither is open or a lock is
     * coming. Tracked like a save, so a lock cancels it. An exception from the backup store, the
     * storage or the saver is [SaveBackupResult.Failed].
     */
    suspend fun saveBackupAsNewFile(copyLocation: String): SaveBackupResult? = counted {
        try {
            backupAsNewFile(copyLocation)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            SaveBackupResult.Failed(copyLocation)
        }
    }

    private suspend fun backupAsNewFile(copyLocation: String): SaveBackupResult? {
        val unlocked = sessions.current.value ?: return null
        val backup = unlocked.backup
        val opened = unlocked.session.opened
        val bytes = if (backup != null) {
            backups?.read(unlocked.location, backup.id) ?: return SaveBackupResult.BackupDamaged
        } else {
            if (opened.access == FileAccess.READ_WRITE) return null
            val read = storage?.readFresh(unlocked.location, maxVaultBytes(maxHeapBytes()))
            (read as? ReadResult.Bytes)?.bytes ?: return SaveBackupResult.Failed(copyLocation)
        }
        // A lock during the read ends here.
        if (sessions.current.value !== unlocked || unlocked === locking) return null
        if (backup != null && Sha256.hex(bytes) != backup.sha256) return SaveBackupResult.BackupDamaged
        // Only the bytes this session decrypted are copied; the same key verifies the copy.
        if (backup == null && Sha256.hex(bytes) != (opened.baseline as? OpenedVault.Baseline.Known)?.sha256) {
            return SaveBackupResult.FileChanged
        }
        val job = scope.async { saver.saveBackupCopy(bytes, opened, copyLocation) }
        track(job)
        return when (val copied = job.await()) {
            is CopyResult.Saved -> SaveBackupResult.Saved(copied.displayName)
            is CopyResult.Failed -> SaveBackupResult.Failed(copied.location)
            is CopyResult.Refused -> SaveBackupResult.Refused
        }
    }

    /**
     * Leaves the open backup and opens the file again, with the backup's key; locks if that fails.
     * Null while a lock waits for a save or when a lock came first ([unlessLocked]); that lock is
     * not repeated.
     */
    suspend fun closeBackup(): OpenResult? {
        counted {
            commitPending()
            if (lockWaiting) return null
            val unlocked = sessions.current.value ?: return null
            val opened = unlessLocked(unlocked, ::openedSession) { opener.reopen(unlocked.location, unlocked.session) } ?: return null
            if (opened is OpenResult.Unlocked) {
                sessions.replace(unlocked, opened.session, opened.kdf, backup = null, olderThan = opened.olderThan, fileNewest = opened.fileNewest, bytesAfterEnd = opened.bytesAfterEnd)
            } else {
                sessions.lock()
            }
            return opened
        }
    }

    /** Returns the file's time and size when opened, and what the provider reports for it now. */
    suspend fun fileDetails(): FileDetails? {
        counted {
            val unlocked = sessions.current.value ?: return null
            val opened = unlocked.session.opened
            val now = storage?.metadata(unlocked.location)
            return FileDetails(opened.openedAt, opened.openedSize, now?.lastModifiedMillis?.let(Instant::ofEpochMilli), now?.size)
        }
    }

    /** Refuses saves for the current unlock; a lock is coming. */
    fun refuseNewSaves() {
        locking = sessions.current.value
        refusedForLock = false
        lockWaiting = true
    }

    /**
     * Cancels a running save and every opener call ([unlessLocked]), and forgets the last failed
     * save (its prepared bytes can't be verified without the key a lock drops). A cancelled opener
     * call stops its key derivation; a decryption already running finishes and [unlessLocked]
     * releases its result. The provider write the saver started finishes on its own; the
     * pending-save marker records it. LockController calls it when the lock completes; a lock
     * also cancels a running lock-screen unlock (LockViewModel). [SaveCoordinatorTest] pins it.
     */
    fun cancelRunning() {
        running.value.forEach { it.cancel() }
        openerCalls.value.forEach { it.cancel(LockCancellation()) }
        lockWaiting = false
        problemState.value = null
        // A finished job keeps its result, and with it the document and key: drop both.
        latest = null
        retrying = null
        lastCommit = null
    }
}

/**
 * Recycle-bin deletes not yet in the file. [staged] are held for the undo window, oldest first;
 * [committing] is being saved. The browser hides both until the save's result is recorded.
 */
data class PendingDeletes(val staged: List<String>, val committing: Set<String>) {
    /** Number of deletes Undo restores. */
    val count: Int get() = staged.size

    /** Ids the browser hides. */
    val hidden: Set<String> get() = committing + staged
}

/**
 * What [SaveCoordinator.settle] found: the newest save's [result] (null when refused, cancelled
 * or [failed]), whether any save was refused because a lock was coming, and whether the newest
 * save's job ended with a throwable other than a cancellation.
 */
class Settled(val result: SaveResult?, val refusedForLock: Boolean, val failed: Boolean = false) {
    /** True when a change the user made is not in the file. */
    val lostChange: Boolean get() = refusedForLock || failed || (result != null && result !is SaveResult.Saved)
}

/** A save result to show once. */
class SaveEvent(val result: SaveResult)

/** Outcome of [SaveCoordinator.refreshForEdit]. */
sealed interface EditCheck {
    /** The file is unchanged; edit the current version. */
    data object Ready : EditCheck

    /** The file changed; the session holds the latest version, which the editor opens. */
    data object Updated : EditCheck

    /** The entry doesn't exist in the latest version. */
    data object EntryGone : EditCheck

    /** The file couldn't be read or failed a check; [result] says why. */
    data class Failed(val result: OpenResult) : EditCheck {
        /** True when the provider didn't answer in time, so a retry can succeed. */
        val timedOut: Boolean get() = result is OpenResult.Unreadable && result.cause == StorageFailure.TIMED_OUT

        /**
         * True when the file's unlock settings became far slower; a lock and a new unlock check
         * them again.
         */
        val slow: Boolean get() = result is OpenResult.TooSlow
    }

    /** The vault locked during the check. */
    data object Locked : EditCheck
}

/** What [SaveCoordinator.fileDetails] reports; a value the provider doesn't report is null. */
data class FileDetails(val openedAt: Instant, val openedSize: Long, val nowModified: Instant?, val nowSize: Long?)

/** Outcome of [SaveCoordinator.saveBackupAsNewFile]. */
sealed interface SaveBackupResult {
    /** The copy is written and verified; [displayName] is its name if the provider gives one. */
    data class Saved(val displayName: String?) : SaveBackupResult

    /** The copy wasn't written or didn't verify; [location] is the picker's file. */
    data class Failed(val location: String) : SaveBackupResult

    /** The kept backup's bytes are missing or don't match their SHA-256; nothing was written. */
    data object BackupDamaged : SaveBackupResult

    /** The read-only file holds other bytes than the ones opened; nothing was written. */
    data object FileChanged : SaveBackupResult

    /** The picked file isn't empty or can't be read, or the copy fails a check; nothing written. */
    data object Refused : SaveBackupResult
}
