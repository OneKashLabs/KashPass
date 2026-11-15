package org.onekash.kashpass.session

import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.checkAll
import java.time.Instant
import java.util.IdentityHashMap
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.lock.LockController
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.open.VaultSession
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

/**
 * Random command sequences against [SaveCoordinator] with the real [SafeSaver], [VaultOpener] and
 * [LockController] over [FakeVaultStorage], all on one virtual scheduler that runs on the run, time
 * and unlock commands. Every other command only issues work, so saves overlap and every input a
 * command reads at its call is the model's state at that point. A model replays the jobs in start
 * order and predicts each result, the problem, the shown session, the file and the number of
 * writes; after each run the property compares all of them.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class SaveCoordinatorProperties {

    @Test
    fun `the save queue matches the model`() = runBlocking<Unit> {
        val counts = sortedMapOf<String, Int>()
        checkAll(PropertyRuns.config(iterations = 200), COMMANDS) { commands ->
            Rig(counts).use { it.play(commands + Command.Run) }
        }
        val missing = COVERAGE.filter { (counts[it] ?: 0) == 0 }
        assertTrue("never reached: $missing (reached: $counts)", missing.isEmpty())
    }

    @Test
    fun `a reload while saves are queued leaves the shown vault on the file or a problem`() = runBlocking<Unit> {
        val counts = sortedMapOf<String, Int>()
        checkAll(PropertyRuns.config(iterations = 50), Arb.list(Arb.int(0..1_000), 1..3), Arb.int(0..2)) { picks, stage ->
            Rig(counts).use { it.reloadDuringSaves(picks, stage) }
        }
    }

    // Commands, by weight: edits from the current session dominate so saves overlap often.
    sealed interface Command {
        data class Edit(val pick: Int, val add: Boolean, val older: Int?) : Command
        data class Stage(val pick: Int) : Command
        data object Undo : Command
        data object Commit : Command
        data object FailWrites : Command
        data object HalfWrites : Command
        // Writes work again; [thenRetry] retries right after, as the problem sheet's Retry does.
        data class AllowWrites(val thenRetry: Boolean) : Command
        data object DamageReadBack : Command
        data object Retry : Command
        data object Outside : Command
        data object Reload : Command
        data object UnlockAgain : Command
        data object Lock : Command
        data object Run : Command
        data object Time : Command

        // Writes fail, an edit, a run, writes work again, Retry: the path to a retry that saves,
        // which independent commands reach too rarely.
        data class FailedSaveThenRetry(val pick: Int) : Command
    }

    private data class Entry(val title: String, val inBin: Boolean) {
        override fun toString() = if (inBin) "$title (bin)" else title
    }

    // Entries by id: what a save writes and a session shows.
    private data class Content(val entries: Map<String, Entry>) {
        override fun toString() = entries.toString()

        // Entry ids in title order. Ids are random UUIDs; titles are unique here (the test
        // vault's six and T<n>), so a seed picks the same entry on every run.
        fun idsByTitle(): List<String> = entries.keys.sortedWith(compareBy({ entries.getValue(it).title }, { it }))

        // The coordinator's delete rule: an entry outside the bin moves into it (every vault here
        // has an enabled recycle bin); an unknown id or an entry already in the bin is skipped.
        fun withDeletes(ids: List<String>) = Content(
            entries.mapValues { (id, e) -> if (id in ids && !e.inBin) Entry(e.title, true) else e },
        )
    }

    // A session the model expects: what it shows and the file version its baseline names (null
    // for an unknown baseline). [real] is the Unlocked it was matched to after a run.
    private class Session(val content: Content, val baseline: Int?) {
        var real: Unlocked? = null
    }

    // The bytes a failed save keeps for Retry: their content and the version they expect.
    private class Prepared(val content: Content, val expected: Int?)

    private class Problem(val kind: String, val prepared: Prepared)

    private sealed interface Queued {
        // Null for a commit the lock controller starts, which returns no handle.
        val deferred: Deferred<SaveResult?>?

        // A save of [content] (deletes not yet applied) from [base]; [open] and [refused] as the
        // coordinator set them at the call, [ids] the staged deletes it took.
        class Save(
            override val deferred: Deferred<SaveResult?>,
            val base: Session?,
            val open: Boolean,
            val refused: Boolean,
            val content: Content,
            val ids: List<String>,
        ) : Queued

        class Retry(override val deferred: Deferred<SaveResult?>, val base: Session?, val refused: Boolean, val prepared: Prepared) : Queued

        class Commit(override val deferred: Deferred<SaveResult?>?, val ids: List<String>) : Queued
    }

    private class Rig(private val counts: MutableMap<String, Int>) : AutoCloseable {
        private val scope = TestScope(StandardTestDispatcher())
        private val io = StandardTestDispatcher(scope.testScheduler)
        private val fake = FakeVaultStorage()
        private val storage = fake
        private val state = FakeVaultStateStore()
        private val sessions = SessionHolder()
        private val opener = VaultOpener.create(storage, state, io)
        private val coordinator = SaveCoordinator(
            sessions,
            SafeSaver.create(storage, FakeBackupStore(), FakeSaveMarkerStore(), state, io, scope),
            opener,
            scope,
            compute = io,
        )
        private val controller = LockController(sessions, scope, { scope.testScheduler.currentTime }, coordinator)
        private val events = mutableListOf<SaveResult>()
        private val launched = mutableListOf<Deferred<OpenResult?>>()
        // Reloads issued since the last run.
        private val reloads = mutableListOf<Deferred<OpenResult?>>()
        private val reloadResults = mutableListOf<Pair<Deferred<OpenResult?>, Boolean>>()

        // The model.
        private var fileVersion = 0
        private var nextVersion = 1
        private var fileContent: Content? = null
        private var mode = WriteMode.OK
        private var damageArmed = false
        private var cur: Session? = null
        private var problem: Problem? = null
        private var staged = listOf<String>()
        private var lockPending = false
        private var lockingReal: Unlocked? = null
        private val queue = mutableListOf<Queued>()
        private val ignoredRetries = mutableListOf<Deferred<SaveResult?>>()
        private val expectedEvents = mutableListOf<String>()
        private var writeAttempts = 0
        private var titles = 0
        private var sinceUnlockAgain = false
        private var refusedThisLock = false
        private var lockSettled = false
        private var writesThisRun = 0

        // Sessions shown so far, for saves from an older session, with the document each showed.
        private val shown = IdentityHashMap<Unlocked, Pair<Session, VaultDocument>>()
        private val shownOrder = mutableListOf<Unlocked>()
        private val releasedByLock = mutableListOf<VaultSession>()

        suspend fun play(commands: List<Command>) {
            fake.put(TestVaults.LOCATION, TestVaults.browserVault(aesRounds = 1_000UL))
            val first = unlockedOrNull()!!
            sessions.set(first)
            scope.launch(Dispatchers.Unconfined, start = CoroutineStart.UNDISPATCHED) { coordinator.results.collect { events += it.result } }
            fileContent = contentOf(first.session)
            cur = Session(fileContent!!, fileVersion)
            drain()
            bind()
            for (command in commands) apply(command)
        }

        private suspend fun apply(command: Command) {
            count(command::class.simpleName!!)
            when (command) {
                is Command.Edit -> edit(command)
                is Command.Stage -> stage(command.pick)
                Command.Undo -> {
                    if (staged.isNotEmpty()) count("undone delete")
                    coordinator.undoStaged()
                    staged = emptyList()
                }
                Command.Commit -> commit()
                Command.FailWrites -> {
                    fake.failWrites(TestVaults.LOCATION, StorageFailure.IO_FAILURE, afterOpen = false)
                    mode = WriteMode.FAIL_BEFORE_OPEN
                }
                Command.HalfWrites -> {
                    fake.failWrites(TestVaults.LOCATION, StorageFailure.IO_FAILURE, afterOpen = true)
                    mode = WriteMode.HALF
                }
                is Command.AllowWrites -> {
                    fake.allowWrites(TestVaults.LOCATION)
                    mode = WriteMode.OK
                    if (command.thenRetry) retry()
                }
                Command.DamageReadBack -> {
                    fake.readBackDifferentOnce(TestVaults.LOCATION)
                    damageArmed = true
                }
                Command.Retry -> retry()
                Command.Outside -> outside()
                Command.Reload -> reload()
                Command.UnlockAgain -> unlockAgain()
                Command.Lock -> lock()
                Command.Run -> run()
                Command.Time -> time()
                is Command.FailedSaveThenRetry -> {
                    apply(Command.FailWrites)
                    apply(Command.Edit(command.pick, add = false, older = null))
                    apply(Command.Run)
                    apply(Command.AllowWrites(thenRetry = true))
                }
            }
        }

        // Queues a save for each of [picks] (and [stage] staged deletes first), then reloads
        // without running the queue first, and checks the outcome against the file.
        suspend fun reloadDuringSaves(picks: List<Int>, stage: Int) {
            play(emptyList())
            repeat(stage) { stage(it * 7) }
            for (pick in picks) edit(Command.Edit(pick, add = pick % 3 == 0, older = null))
            launched += scope.async { coordinator.reload() }
            scope.runCurrent()
            val bytes = fake.bytes(TestVaults.LOCATION)!!
            val real = sessions.current.value!!
            val shownIsFile = contentOf(real.session) == decode(bytes) &&
                real.session.opened.baseline == OpenedVault.Baseline.Known(Sha256.hex(bytes))
            val problem = coordinator.lastProblem?.let(::kindOf)
            count(if (shownIsFile) "shown is the file" else "shown differs, problem $problem")
            assertTrue("no problem shown, yet the shown vault is not the file", shownIsFile || problem != null)
        }

        private fun edit(command: Command.Edit) {
            val base = if (command.older == null || shownOrder.isEmpty()) cur?.real else shownOrder[command.older % shownOrder.size]
            if (base == null) return
            val (baseModel, document) = shown.getValue(base)
            val ids = baseModel.content.idsByTitle()
            val title = "T${titles++}"
            val now = Instant.ofEpochSecond(1_800_000_000L + titles)
            val (edited, content) = if (command.add || ids.isEmpty()) {
                val draft = EntryEdits.newDraft(document, ProtectedText.of("pw"))
                val added = EntryEdits.add(document, null, EntryDraft(title, draft.userName, draft.password, draft.url, draft.notes), now)
                added.document to Content(baseModel.content.entries + (added.entryId to Entry(title, false)))
            } else {
                val id = ids[command.pick % ids.size]
                val d = EntryEdits.draftOf(document, id)!!
                val changed = EntryEdits.edit(document, id, EntryDraft(title, d.userName, d.password, d.url, d.notes), now) as EditResult.Changed
                val old = baseModel.content.entries.getValue(id)
                changed.document to Content(baseModel.content.entries + (id to Entry(title, old.inBin)))
            }
            val open = base === cur?.real
            val refused = base === lockingReal
            val deferred = coordinator.save(edited, base)
            val ids2 = if (open && !refused) staged.also { staged = emptyList() } else emptyList()
            if (command.older != null) count(if (open) "edit from older that is current" else "edit from a released session")
            queue += Queued.Save(deferred, if (open) cur else baseModel, open, refused, content, ids2)
        }

        private fun stage(pick: Int) {
            val session = cur
            val ids = session?.content?.idsByTitle().orEmpty()
            val id = if (ids.isEmpty()) "unknown" else ids[pick % ids.size]
            val expected = session != null && session.real !== lockingReal && session.content.entries[id]?.inBin == false
            assertEquals("stageDelete($id)", expected, coordinator.stageDelete(id, WINDOW))
            if (expected && id !in staged) staged = staged + id
            count(if (expected) "staged" else "stage refused")
        }

        private fun commit() {
            val deferred = coordinator.commitStaged()
            if (staged.isEmpty() || cur == null) {
                assertNull(deferred)
                staged = emptyList()
                return
            }
            queue += Queued.Commit(deferred!!, staged)
            staged = emptyList()
        }

        private fun retry() {
            val deferred = coordinator.retry()
            val prepared = problem?.prepared
            if (prepared == null || queue.any { it is Queued.Retry }) {
                ignoredRetries += deferred
                count("retry ignored")
                return
            }
            val base = cur
            queue += Queued.Retry(deferred, base, base != null && base.real === lockingReal, prepared)
        }

        private suspend fun outside() {
            val bytes = TestVaults.browserVault(aesRounds = 1_000UL)
            fake.put(TestVaults.LOCATION, bytes)
            fileVersion = nextVersion++
            fileContent = decode(bytes)!!
        }

        // Issues a reload without running the queue: it starts at the next run and waits for the
        // jobs queued in it ([process]).
        private fun reload() {
            reloads += scope.async { coordinator.reload() }.also { launched += it }
        }

        private suspend fun unlockAgain() {
            run()
            if (cur != null) return
            val unlocked = unlockedOrNull()
            if (unlocked != null) sessions.set(unlocked)
            val content = fileContent
            if (content != null) {
                cur = Session(content, fileVersion)
                sinceUnlockAgain = true
                count("unlocked again")
            }
            drain()
            check(null)
        }

        private fun lock() {
            controller.lock()
            if (staged.isNotEmpty() && cur != null) queue += Queued.Commit(null, staged)
            staged = emptyList()
            if (lockPending) return
            if (queue.isEmpty()) {
                cur?.real?.let { releasedByLock += it.session }
                if (cur != null) count("lock with nothing running")
                cur = null
                problem = null
                sinceUnlockAgain = false
                assertFalse("a lock drops every result", coordinator.holdsResult)
                for (session in releasedByLock) assertFalse("released by the lock", session.isOpen)
                return
            }
            lockPending = true
            refusedThisLock = false
            lockingReal = cur?.real
            count("lock waiting for saves")
        }

        private suspend fun run() {
            val before = cur
            drain()
            process()
            check(before)
        }

        private suspend fun time() {
            run()
            scope.advanceTimeBy(WINDOW.inWholeMilliseconds + 1)
            drain()
            if (staged.isNotEmpty() && cur != null) {
                count("window commit")
                commitJob(staged)
            }
            staged = emptyList()
            check(cur)
        }

        // The model's side of a run: every queued job in start order, then a waiting lock.
        private fun process() {
            val jobs = queue.toList()
            queue.clear()
            writesThisRun = 0
            for (job in jobs) {
                val expected = when (job) {
                    is Queued.Save -> save(job)
                    is Queued.Retry -> retryJob(job)
                    is Queued.Commit -> commitResult(job.ids)
                }
                assertResult(job, expected)
            }
            if (writesThisRun >= 2) count("two saves reached the file in one run")
            // A reload commits the deletes staged when it starts, waits for every job, then opens
            // the file; with two pending the second's swap finds the first's session and is
            // dropped, which shows the same file. A lock waiting for the same jobs, or one that
            // came first, makes it return null with nothing changed.
            if (reloads.isNotEmpty() && (lockPending || cur == null)) {
                count(if (lockPending) "reload during a lock" else "reload after a lock")
                for (reloaded in reloads) reloadResults += reloaded to false
                if (cur == null) staged = emptyList()
                reloads.clear()
            }
            if (reloads.isNotEmpty()) {
                if (writesThisRun > 0) count("reload after a save that reached the file")
                if (staged.isNotEmpty() && cur != null) {
                    commitJob(staged)
                    staged = emptyList()
                }
                val content = fileContent
                for (reloaded in reloads) {
                    count("reload")
                    reloadResults += reloaded to (content != null)
                }
                if (content != null) {
                    cur = Session(content, fileVersion)
                    problem = null
                } else {
                    count("reload of a damaged file")
                }
                reloads.clear()
            }
            if (lockPending) {
                lockPending = false
                lockSettled = true
                cur?.real?.let { releasedByLock += it.session }
                cur = null
                problem = null
                sinceUnlockAgain = false
            }
        }

        private fun commitJob(ids: List<String>) {
            assertResult(null, commitResult(ids))
        }

        private fun save(job: Queued.Save): String? {
            if (job.refused) {
                count("refused for lock")
                refusedThisLock = true
                return null
            }
            val base = job.base
            if (!job.open || base == null || cur == null) {
                count("nothing to save")
                return null
            }
            if (job.ids.isNotEmpty()) count("save carried staged deletes")
            return write(base, job.content.withDeletes(job.ids), base.baseline, sameBaselineOnFailure = base.baseline)
        }

        private fun retryJob(job: Queued.Retry): String? {
            if (job.refused) {
                count("refused for lock")
                refusedThisLock = true
                return null
            }
            val base = job.base ?: return null
            if (cur == null) return null
            val kind = write(base, job.prepared.content, job.prepared.expected, sameBaselineOnFailure = job.prepared.expected, retried = job.prepared)
            count("retry $kind")
            return kind
        }

        private fun commitResult(ids: List<String>): String? {
            val base = cur ?: return null
            val content = base.content.withDeletes(ids)
            if (content == base.content) {
                count("commit with nothing to delete")
                return null
            }
            val kind = write(base, content, base.baseline, sameBaselineOnFailure = base.baseline)
            if (kind == "Saved") count("committed delete")
            return kind
        }

        // SafeSaver's steps: a file other than [expected] is a conflict; otherwise one write
        // attempt, classified by the write mode and the read-back damage. Then the coordinator's
        // swap and problem.
        private fun write(base: Session, content: Content, expected: Int?, sameBaselineOnFailure: Int?, retried: Prepared? = null): String {
            val kind = if (expected == null || expected != fileVersion) {
                "Conflict"
            } else {
                writesThisRun++
                writeAttempts += if (mode == WriteMode.FAIL_BEFORE_OPEN) 0 else 1
                // The one-shot flip applies to the next write that stores every byte.
                val damaged = damageArmed && mode == WriteMode.OK
                if (damaged) damageArmed = false
                when {
                    mode == WriteMode.FAIL_BEFORE_OPEN -> "WriteFailed"
                    mode == WriteMode.HALF -> "MaybeDamaged".also { damage() }
                    damaged -> "VerifyFailed".also { damage() }
                    else -> "Saved".also {
                        fileVersion = nextVersion++
                        fileContent = content
                    }
                }
            }
            count(kind)
            if (kind == "Saved" && sinceUnlockAgain) count("Saved after unlock again")
            if (cur === base) {
                cur = when (kind) {
                    "Saved" -> Session(content, fileVersion)
                    "Conflict", "WriteFailed" -> Session(base.content, sameBaselineOnFailure)
                    else -> Session(base.content, null)
                }
            } else {
                count("result for a replaced session")
            }
            problem = if (kind == "Saved") null else Problem(kind, retried ?: Prepared(content, expected))
            return kind
        }

        private fun damage() {
            fileVersion = nextVersion++
            fileContent = null
        }

        private val results = mutableListOf<Pair<Deferred<SaveResult?>?, String?>>()

        private fun assertResult(job: Queued?, expected: String?) {
            results += job?.deferred to expected
            if (expected != null) expectedEvents += expected
        }

        private fun drain() {
            scope.runCurrent()
            assertTrue("launched work finished without an exception", launched.all { it.isCompleted && it.getCompletionExceptionOrNull() == null })
            assertFalse("no tracked job runs", coordinator.hasRunningJobs)
        }

        // Compares the coordinator, the session and the file with the model. [before] is the
        // session shown before the run.
        private suspend fun check(before: Session?) {
            for ((deferred, expected) in results) {
                if (deferred == null) continue
                assertTrue(deferred.isCompleted)
                assertEquals("job result", expected, deferred.getCompleted()?.let(::kindOf))
            }
            results.clear()
            for ((reloaded, opens) in reloadResults) {
                assertEquals("the reload opens the file exactly when it is not damaged", opens, reloaded.getCompleted() is OpenResult.Unlocked)
            }
            reloadResults.clear()
            for (ignored in ignoredRetries) assertNull("an ignored retry", ignored.getCompleted())
            ignoredRetries.clear()
            assertEquals("events in start order", expectedEvents, events.map(::kindOf))
            expectedEvents.clear()
            events.clear()
            assertEquals("writes", writeAttempts, fake.writes)
            if (lockSettled) {
                lockSettled = false
                assertEquals("saves refused for the lock", refusedThisLock, coordinator.settle(null).refusedForLock)
                if (refusedThisLock) count("refused for lock, reported by settle")
            }

            val bytes = fake.bytes(TestVaults.LOCATION)!!
            val file = decode(bytes)
            assertEquals("file content", fileContent, file)
            assertEquals("problem", problem?.kind, coordinator.lastProblem?.let(::kindOf))
            assertEquals("staged", staged, coordinator.pendingDeletes.value.staged)
            assertTrue("committing", coordinator.pendingDeletes.value.committing.isEmpty())
            assertFalse("covering", controller.covering.value)

            val real = sessions.current.value
            val model = cur
            if (model == null) {
                assertNull("locked", real)
                for (session in releasedByLock) assertFalse("released by the lock", session.isOpen)
                // A save requested later from a released session keeps a finished job with no
                // result, which holds no vault; only the run that locks is checked.
                if (before != null) {
                    assertFalse("a lock drops every result", coordinator.holdsResult)
                    count("locked")
                }
            } else {
                assertNotNull("unlocked", real)
                real!!
                assertEquals("shown content", model.content, contentOf(real.session))
                val baseline = real.session.opened.baseline
                when (model.baseline) {
                    null -> assertEquals(OpenedVault.Baseline.Unknown, baseline)
                    fileVersion -> assertEquals(OpenedVault.Baseline.Known(Sha256.hex(bytes)), baseline)
                    else -> assertTrue("baseline names an earlier file", baseline is OpenedVault.Baseline.Known && baseline.sha256 != Sha256.hex(bytes))
                }
                if (problem == null && model.baseline == fileVersion) {
                    assertEquals("the shown vault is the file", file, contentOf(real.session))
                    count("shown is the file")
                }
                bind()
            }
        }

        private fun bind() {
            val model = cur ?: return
            val real = sessions.current.value!!
            model.real = real
            if (!shown.containsKey(real)) {
                shown[real] = model to real.session.opened.document
                shownOrder += real
            }
        }

        private suspend fun unlockedOrNull(): Unlocked? {
            val opened = VaultOpener.create(storage, state, Dispatchers.Unconfined)
                .open(TestVaults.LOCATION, TestVaults.PASSWORD.toCharArray()) as? OpenResult.Unlocked ?: return null
            return Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false)
        }

        private fun count(name: String) {
            counts[name] = (counts[name] ?: 0) + 1
        }

        override fun close() {
            scope.cancel()
        }
    }

    private enum class WriteMode { OK, FAIL_BEFORE_OPEN, HALF }

    private companion object {
        val WINDOW = 5.seconds

        val COMMANDS: Arb<List<Command>> = Arb.list(
            Arb.bind(Arb.int(0..104), Arb.int(0..1_000)) { k, p -> command(k, p) },
            1..25,
        )

        fun command(k: Int, p: Int): Command = when {
            k < 22 -> Command.Edit(p, add = p % 4 == 0, older = null)
            k < 27 -> Command.Edit(p, add = false, older = p)
            k < 39 -> Command.Stage(p)
            k < 43 -> Command.Undo
            k < 47 -> Command.Commit
            k < 51 -> Command.FailWrites
            k < 54 -> Command.HalfWrites
            k < 60 -> Command.AllowWrites(thenRetry = p % 2 == 0)
            k < 63 -> Command.DamageReadBack
            k < 70 -> Command.Retry
            k < 74 -> Command.Outside
            k < 78 -> Command.Reload
            k < 82 -> Command.UnlockAgain
            k < 88 -> Command.Lock
            k < 97 -> Command.Run
            k < 100 -> Command.FailedSaveThenRetry(p)
            else -> Command.Time
        }

        // Rules each run must reach.
        val COVERAGE = listOf(
            "Saved", "Conflict", "WriteFailed", "MaybeDamaged", "VerifyFailed", "retry Saved", "retry Conflict",
            "retry ignored", "refused for lock", "nothing to save", "committed delete",
            "save carried staged deletes", "window commit", "reload", "reload of a damaged file", "unlocked again",
            "lock with nothing running", "lock waiting for saves", "locked", "edit from a released session",
            "result for a replaced session", "stage refused", "shown is the file", "undone delete",
            "two saves reached the file in one run", "reload after a save that reached the file",
            "reload during a lock", "reload after a lock", "refused for lock, reported by settle", "Saved after unlock again",
        )

        fun kindOf(result: SaveResult): String = result::class.simpleName!!

        fun contentOf(session: VaultSession) = Content(
            session.index.rows(Chip.All, "").associate { it.id to Entry(it.title.orEmpty(), false) } +
                session.index.rows(Chip.RecycleBin, "").associate { it.id to Entry(it.title.orEmpty(), true) },
        )

        // The content of [bytes] opened with the test password, or null when they don't open.
        suspend fun decode(bytes: ByteArray): Content? {
            val storage = FakeVaultStorage().apply { put(TestVaults.LOCATION, bytes) }
            val opened = VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.Unconfined)
                .open(TestVaults.LOCATION, TestVaults.PASSWORD.toCharArray()) as? OpenResult.Unlocked ?: return null
            return contentOf(opened.session).also { opened.session.release() }
        }
    }
}
