package org.onekash.kashpass.session

import java.security.MessageDigest
import java.time.Instant
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Runnable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import org.onekash.kashpass.vault.save.VaultSaving
import org.onekash.kashpass.vault.open.VaultSession
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import org.onekash.kashpass.lock.LockController
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.open.RefreshResult
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.policy.SlowKdf
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.TestVaults

class SaveCoordinatorTest {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sessions = SessionHolder()

    private fun retitled(unlocked: Unlocked, title: String) = run {
        val doc = unlocked.session.opened.document
        val id = unlocked.session.index.rows(Chip.All, "").first().id
        val d = EntryEdits.draftOf(doc, id)!!
        (EntryEdits.edit(doc, id, EntryDraft(title, d.userName, d.password, d.url, d.notes), Instant.now()) as EditResult.Changed).document
    }

    private fun unlockWith(storage: FakeVaultStorage, bytes: ByteArray): Unlocked = runBlocking {
        storage.put(TestVaults.LOCATION, bytes)
        val opened = VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO).open(TestVaults.LOCATION, TestVaults.PASSWORD.toCharArray()) as org.onekash.kashpass.vault.open.OpenResult.Unlocked
        Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false).also(sessions::set)
    }

    @Test
    fun `every result replaces the session with the vault it carries`() = runBlocking<Unit> {
        val saver = FakeVaultSaver()
        val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), scope)
        val unlocked = unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        val saved = coordinator.save(retitled(unlocked, "Saved title")).await()
        assertTrue(saved is SaveResult.Saved)
        assertTrue(sessions.current.value!!.session.index.rows(Chip.All, "").any { it.title == "Saved title" })
        assertNull(coordinator.lastProblem)

        saver.result = { vault, prepared -> SaveResult.VerifyFailed(vault.withBaseline(OpenedVault.Baseline.Unknown), prepared) }
        val failed = coordinator.save(retitled(sessions.current.value!!, "Unverified")).await()
        assertSame(failed, coordinator.lastProblem)
        assertEquals(OpenedVault.Baseline.Unknown, sessions.current.value!!.session.opened.baseline)
    }

    @Test
    fun `after an unverified save the next save is a conflict, and saves verify with the same key`() = runBlocking<Unit> {
        val storage = FakeVaultStorage()
        val state = FakeVaultStateStore()
        val saver = SafeSaver.create(storage, FakeBackupStore(), FakeSaveMarkerStore(), state, Dispatchers.IO, scope)
        val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), scope)
        val original = TestVaults.bytes(aesRounds = 1_000UL)
        unlockWith(storage, original)
        assertTrue(coordinator.save(retitled(sessions.current.value!!, "First")).await() is SaveResult.Saved)
        assertTrue("a second save after a swap verifies with the shared key", coordinator.save(retitled(sessions.current.value!!, "Second")).await() is SaveResult.Saved)
        storage.readBackDifferent(TestVaults.LOCATION)
        assertTrue(coordinator.save(retitled(sessions.current.value!!, "Third")).await() is SaveResult.VerifyFailed)
        storage.put(TestVaults.LOCATION, original)
        assertTrue(coordinator.save(retitled(sessions.current.value!!, "Fourth")).await() is SaveResult.Conflict)
    }

    @Test
    fun `a reload requested while a save is queued shows the file with that save`() = runBlocking<Unit> {
        val storage = FakeVaultStorage()
        val state = FakeVaultStateStore()
        val saver = SafeSaver.create(storage, FakeBackupStore(), FakeSaveMarkerStore(), state, Dispatchers.IO, scope)
        val coordinator = SaveCoordinator(sessions, saver, VaultOpener.create(storage, state, Dispatchers.IO), scope)
        val unlocked = unlockWith(storage, TestVaults.bytes(aesRounds = 1_000UL))
        val queued = coordinator.save(retitled(unlocked, "Queued title"))
        assertTrue(coordinator.reload() is OpenResult.Unlocked)
        assertTrue(queued.await() is SaveResult.Saved)
        assertTrue("the reload shows the saved title", sessions.current.value!!.session.index.rows(Chip.All, "").any { it.title == "Queued title" })
        assertNull(coordinator.lastProblem)
    }

    @Test
    fun `a lock while the reload reads the file makes it return null, not throw`() = runBlocking<Unit> {
        val storage = FakeVaultStorage()
        val state = FakeVaultStateStore()
        unlockWith(storage, TestVaults.bytes(aesRounds = 1_000UL))
        // Runs the lock, as a screen-off lock does, when the opener moves to its io dispatcher:
        // after reload read the session, before the opener reads it.
        var lockOnDispatch = true
        val io = object : CoroutineDispatcher() {
            override fun dispatch(context: CoroutineContext, block: Runnable) {
                if (lockOnDispatch) {
                    lockOnDispatch = false
                    sessions.lock()
                }
                block.run()
            }
        }
        val coordinator = SaveCoordinator(sessions, FakeVaultSaver(), VaultOpener.create(storage, state, io), scope)
        assertNull(coordinator.reload())
        assertNull(sessions.current.value)
    }

    @Test
    fun `a lock after the reopen and before the swap makes the reload return null`() = runBlocking<Unit> {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL)
        unlockWith(FakeVaultStorage(), bytes)
        val again = TestVaults.unlock(bytes)
        val opener = FakeVaultOpener().apply {
            reopenResult = {
                sessions.lock()
                again
            }
        }
        assertNull(SaveCoordinator(sessions, FakeVaultSaver(), opener, scope).reload())
        assertNull(sessions.current.value)
        assertFalse("the reopened session is released", again.session.isOpen)
    }

    @Test
    fun `a lock while the reload reads a file that fails makes it return null`() = runBlocking<Unit> {
        unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        val opener = FakeVaultOpener().apply {
            reopenResult = {
                sessions.lock()
                OpenResult.TooSlow(SlowKdf(KdfSettings.AesKdf(100_000_000UL), 100, 166))
            }
        }
        assertNull(SaveCoordinator(sessions, FakeVaultSaver(), opener, scope).reload())
    }

    @Test
    fun `an error from the reopen with no lock is rethrown`() = runBlocking<Unit> {
        unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        val opener = FakeVaultOpener().apply { reopenResult = { throw IllegalStateException("opener") } }
        val thrown = runCatching { SaveCoordinator(sessions, FakeVaultSaver(), opener, scope).reload() }.exceptionOrNull()
        assertTrue("got $thrown", thrown is IllegalStateException && thrown.message == "opener")
        assertTrue("still unlocked", sessions.current.value != null)
    }

    @Test
    fun `a cancellation during the reload's reopen stays a cancellation`() = runBlocking<Unit> {
        unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        // Locked first, so a catch that took the cancellation for a released session would
        // return null.
        val opener = FakeVaultOpener().apply {
            reopenResult = {
                sessions.lock()
                throw CancellationException("cancelled")
            }
        }
        val coordinator = SaveCoordinator(sessions, FakeVaultSaver(), opener, scope)
        val thrown = runCatching { coordinator.reload() }.exceptionOrNull()
        assertTrue("got $thrown", thrown is CancellationException)
    }

    // An io dispatcher that locks, as a screen-off lock does, when the opener moves to it: after
    // the coordinator read the session, before the opener reads it.
    private fun lockingIo() = object : CoroutineDispatcher() {
        var armed = true
        override fun dispatch(context: CoroutineContext, block: Runnable) {
            if (armed) {
                armed = false
                sessions.lock()
            }
            block.run()
        }
    }

    private fun realOpenerCoordinator(): SaveCoordinator {
        val storage = FakeVaultStorage()
        val state = FakeVaultStateStore()
        unlockWith(storage, TestVaults.bytes(aesRounds = 1_000UL))
        return SaveCoordinator(sessions, FakeVaultSaver(), VaultOpener.create(storage, state, lockingIo()), scope)
    }

    @Test
    fun `a lock before the opener reads the session gives Locked to an edit, not an exception`() = runBlocking<Unit> {
        val coordinator = realOpenerCoordinator()
        val id = sessions.current.value!!.session.index.rows(Chip.All, "").first().id
        assertEquals(EditCheck.Locked, coordinator.refreshForEdit(id))
        assertNull(sessions.current.value)
    }

    @Test
    fun `a lock before the opener reads the session gives null to Open backup and Close backup`() = runBlocking<Unit> {
        val backup = BackupInfo("b", Instant.EPOCH, 1, BackupKind.OPENED, "0".repeat(64))
        assertNull(realOpenerCoordinator().openBackup(backup))
        assertNull(realOpenerCoordinator().closeBackup())
        assertNull(sessions.current.value)
    }

    @Test
    fun `a lock and a new unlock during Close backup give null and leave the new unlock open`() = runBlocking<Unit> {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL)
        unlockWith(FakeVaultStorage(), bytes)
        val again = TestVaults.unlock(bytes)
        val newUnlock = Unlocked(TestVaults.LOCATION, again.session, again.kdf, false)
        val opener = FakeVaultOpener().apply {
            reopenResult = {
                sessions.lock()
                sessions.set(newUnlock)
                OpenResult.Unreadable(StorageFailure.IO_FAILURE)
            }
        }
        val locks = sessions.lockCount
        assertNull(SaveCoordinator(sessions, FakeVaultSaver(), opener, scope).closeBackup())
        assertSame(newUnlock, sessions.current.value)
        assertEquals("only the owner's lock", locks + 1, sessions.lockCount)
    }

    @Test
    fun `a lock during Open backup gives null and releases the session the backup opened`() = runBlocking<Unit> {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL)
        unlockWith(FakeVaultStorage(), bytes)
        val again = TestVaults.unlock(bytes)
        val opener = FakeVaultOpener().apply {
            backupFor = {
                sessions.lock()
                again
            }
        }
        val backup = BackupInfo("b", Instant.EPOCH, 1, BackupKind.OPENED, "0".repeat(64))
        assertNull(SaveCoordinator(sessions, FakeVaultSaver(), opener, scope).openBackup(backup))
        assertFalse("released", again.session.isOpen)
    }

    @Test
    fun `a lock during an edit's re-read of an unchanged file gives Locked, not Ready`() = runBlocking<Unit> {
        unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        val opener = FakeVaultOpener().apply {
            refreshResult = {
                sessions.lock()
                RefreshResult.Unchanged
            }
        }
        val id = sessions.current.value!!.session.index.rows(Chip.All, "").first().id
        assertEquals(EditCheck.Locked, SaveCoordinator(sessions, FakeVaultSaver(), opener, scope).refreshForEdit(id))
    }

    private val heldBackup = BackupInfo("b", Instant.EPOCH, 1, BackupKind.OPENED, "0".repeat(64))

    // Each coordinator call into the opener, as its screen makes it.
    private val openerCalls: List<Pair<String, suspend (SaveCoordinator) -> Any?>> = listOf(
        "Reload" to { it.reload() },
        "edit check" to { it.refreshForEdit(sessions.current.value!!.session.index.rows(Chip.All, "").first().id) },
        "Open backup" to { it.openBackup(heldBackup) },
        "Close backup" to { it.closeBackup() },
    )

    private suspend fun awaitHeld(opener: FakeVaultOpener) {
        val until = System.nanoTime() + 5_000_000_000L
        while (opener.calls.isEmpty()) {
            check(System.nanoTime() < until) { "the opener was never called" }
            delay(5)
        }
    }

    @Test
    fun `a lock cancels an opener call that is running and the call returns locked`() = runBlocking<Unit> {
        for ((name, call) in openerCalls) {
            unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
            val opener = FakeVaultOpener().apply { hold() }
            val coordinator = SaveCoordinator(sessions, FakeVaultSaver(), opener, scope)
            val locker = LockController(sessions, scope, { 0L }, coordinator)
            val running = async { call(coordinator) }
            awaitHeld(opener)
            locker.lock()
            val answer = withTimeout(10_000) { running.await() }
            assertTrue("$name answers locked: $answer", answer == null || answer == EditCheck.Locked)
            assertEquals("$name: the held call is cancelled", 1, opener.cancelledHeld)
            assertNull(sessions.current.value)
        }
    }

    @Test
    fun `a caller's own cancel of an opener call stays a cancel, also in the same step as a lock`() = runBlocking<Unit> {
        for (withLock in listOf(false, true)) {
            unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
            val opener = FakeVaultOpener().apply { hold() }
            val coordinator = SaveCoordinator(sessions, FakeVaultSaver(), opener, scope)
            var returned = false
            val running = async {
                coordinator.reload()
                returned = true
            }
            awaitHeld(opener)
            // The lock's cancel comes first; the caller's own cancel lands before the call resumes.
            if (withLock) LockController(sessions, scope, { 0L }, coordinator).lock()
            running.cancel()
            val thrown = runCatching { withTimeout(10_000) { running.await() } }.exceptionOrNull()
            assertTrue("with a lock: $withLock, got $thrown", thrown is CancellationException)
            assertFalse("with a lock: $withLock, reload returned to a cancelled caller", returned)
            assertEquals(1, opener.cancelledHeld)
        }
    }

    @Test
    fun `while a lock waits for a save, edit checks and backups answer locked without the opener`() = runBlocking<Unit> {
        for ((name, call) in openerCalls.drop(1)) {
            unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
            val opener = FakeVaultOpener()
            val coordinator = SaveCoordinator(sessions, FakeVaultSaver(), opener, scope)
            // The state a lock that waits for a save leaves until the save ends.
            coordinator.refuseNewSaves()
            val answer = withTimeout(10_000) { call(coordinator) }
            assertTrue("$name answers locked: $answer", answer == null || answer == EditCheck.Locked)
            assertTrue("$name calls no opener: ${opener.calls}", opener.calls.isEmpty())
            assertNotNull("the session stays set until the lock ends", sessions.current.value)
        }
    }

    @Test
    fun `a session swapped in after a save keeps its unlock origin and unlock key`() = runBlocking<Unit> {
        val storage = FakeVaultStorage()
        val state = FakeVaultStateStore()
        val saver = SafeSaver.create(storage, FakeBackupStore(), FakeSaveMarkerStore(), state, Dispatchers.IO, scope)
        val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), scope)
        val passHash = MessageDigest.getInstance("SHA-256").digest(TestVaults.PASSWORD.toByteArray())
        storage.put(TestVaults.LOCATION, TestVaults.bytes(aesRounds = 1_000UL, keyPart = TestVaults.KEY_FILE_PART))
        val opener = VaultOpener.create(storage, state, Dispatchers.IO)
        val opened = opener.openWithKey(TestVaults.LOCATION, passHash.copyOf(), keyFile = TestVaults.KEY_FILE) as OpenResult.Unlocked
        Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false).also(sessions::set)
        assertTrue(coordinator.save(retitled(sessions.current.value!!, "Saved by key")).await() is SaveResult.Saved)
        val swapped = sessions.current.value!!.session
        assertEquals(UnlockOrigin.STORED_KEY_AND_KEY_FILE, swapped.opened.origin)
        assertTrue(passHash.contentEquals(swapped.unlockKey()!!))
        val reopened = opener.open(TestVaults.LOCATION, TestVaults.PASSWORD.toCharArray(), keyFile = TestVaults.KEY_FILE) as OpenResult.Unlocked
        assertTrue("the password and key file open the save", reopened.session.index.rows(Chip.All, "").any { it.title == "Saved by key" })
    }

    @Test
    fun `data after the end of the file stays flagged after a failed save and is gone after a saved one`() = runBlocking<Unit> {
        val saver = FakeVaultSaver()
        val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), scope)
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        val unlocked = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, bytesAfterEnd = true).also(sessions::set)
        unlocked.bytesAfterEndDismissed = true
        saver.result = { vault, prepared -> SaveResult.VerifyFailed(vault.withBaseline(OpenedVault.Baseline.Unknown), prepared) }
        coordinator.save(retitled(unlocked, "Not saved")).await()
        assertTrue(sessions.current.value!!.bytesAfterEnd)
        assertTrue("the dismissal stays with the unlock", sessions.current.value!!.bytesAfterEndDismissed)
        saver.result = { vault, _ -> SaveResult.Saved(vault) }
        assertTrue(coordinator.save(retitled(sessions.current.value!!, "Saved")).await() is SaveResult.Saved)
        assertFalse(sessions.current.value!!.bytesAfterEnd)
    }

    @Test
    fun `a lock before the result arrives discards it`() = runBlocking<Unit> {
        val saver = FakeVaultSaver().apply { hold() }
        val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), scope)
        val unlocked = unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        val pending = coordinator.save(retitled(unlocked, "Too late"))
        while (!saver.isSaving.value) Thread.sleep(10)
        sessions.lock()
        saver.release()
        assertNull(pending.await())
        assertNull(sessions.current.value)
    }


    @Test
    fun `Use this version during a running save keeps that save's result on screen`() = runBlocking<Unit> {
        val opener = FakeVaultOpener()
        val saver = FakeVaultSaver()
        val coordinator = SaveCoordinator(sessions, saver, opener, scope)
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        val unlocked = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false,
            olderThan = Instant.parse("2026-06-01T00:00:00Z"), fileNewest = Instant.parse("2026-01-01T00:00:00Z")).also(sessions::set)
        saver.hold()
        val save = coordinator.save(retitled(unlocked, "Saved meanwhile"))
        while (!saver.isSaving.value) Thread.sleep(10)
        coordinator.acceptOlderFile()
        saver.release()
        assertTrue(save.await() is SaveResult.Saved)
        assertTrue(sessions.current.value!!.session.index.rows(Chip.All, "").any { it.title == "Saved meanwhile" })
        assertNull(sessions.current.value!!.olderThan)
    }

    @Test
    fun `an older file from an edit check or reload warns, a save clears it, and accepting records its time`() = runBlocking<Unit> {
        val opener = FakeVaultOpener()
        val coordinator = SaveCoordinator(sessions, FakeVaultSaver(), opener, scope)
        val seen = Instant.parse("2026-06-01T00:00:00Z")
        val fileNewest = Instant.parse("2026-01-01T00:00:00Z")
        val unlocked = unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        val older = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        opener.refreshResult = {
            org.onekash.kashpass.vault.open.RefreshResult.Reloaded(
                org.onekash.kashpass.vault.open.OpenResult.Unlocked(older.session, older.kdf, false, olderThan = seen, fileNewest = fileNewest),
            )
        }
        coordinator.refreshForEdit(unlocked.session.index.rows(Chip.All, "").first().id)
        assertEquals(seen, sessions.current.value!!.olderThan)
        assertEquals(fileNewest, sessions.current.value!!.fileNewest)

        val again = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        opener.reopenResult = { org.onekash.kashpass.vault.open.OpenResult.Unlocked(again.session, again.kdf, false, olderThan = seen, fileNewest = fileNewest) }
        coordinator.reload()
        assertEquals(seen, sessions.current.value!!.olderThan)

        coordinator.acceptOlderFile()
        assertEquals(listOf(fileNewest), opener.accepted)
        assertNull(sessions.current.value!!.olderThan)
        assertTrue("the session is still usable", sessions.current.value!!.session.isOpen)

        val third = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        opener.reopenResult = { org.onekash.kashpass.vault.open.OpenResult.Unlocked(third.session, third.kdf, false, olderThan = seen, fileNewest = fileNewest) }
        coordinator.reload()
        assertTrue(coordinator.save(retitled(sessions.current.value!!, "Saved")).await() is SaveResult.Saved)
        assertNull("a verified save holds the newest version", sessions.current.value!!.olderThan)
    }

    private fun throwingSaver() = FakeVaultSaver().apply {
        result = { _, _ -> throw IllegalStateException("unexpected") }
        copyResult = { throw IllegalStateException("unexpected") }
    }

    @Test
    fun `a save that throws is reported as not saved, and the next save starts over`() = runBlocking<Unit> {
        val saver = throwingSaver()
        val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), scope)
        val unlocked = unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        val events = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { coordinator.results.first() }
        val result = coordinator.save(retitled(unlocked, "Edited")).await()
        val failed = result as SaveResult.UnexpectedError
        assertNull(failed.prepared)
        assertSame(failed, coordinator.lastProblem)
        assertSame(failed, events.await().result)
        assertFalse(coordinator.hasRunningJobs)
        val current = sessions.current.value!!
        assertEquals("the file can have changed", OpenedVault.Baseline.Unknown, current.session.opened.baseline)
        assertTrue("the session keeps the document from before the edit", current.session.index.rows(Chip.All, "").none { it.title == "Edited" })
    }

    @Test
    fun `a retry that throws is reported as not saved`() = runBlocking<Unit> {
        val saver = FakeVaultSaver().apply { result = { vault, prepared -> SaveResult.WriteFailed(vault, prepared) } }
        val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), scope)
        unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        coordinator.save(retitled(sessions.current.value!!, "Edited")).await()
        saver.result = { _, _ -> throw IllegalStateException("unexpected") }
        assertTrue(coordinator.retry().await() is SaveResult.UnexpectedError)
        assertTrue(coordinator.lastProblem is SaveResult.UnexpectedError)
    }

    @Test
    fun `staged deletes whose save throws are reported as not saved and shown again`() = runBlocking<Unit> {
        val coordinator = SaveCoordinator(sessions, throwingSaver(), FakeVaultOpener(), scope)
        val unlocked = unlockWith(FakeVaultStorage(), TestVaults.browserVault(aesRounds = 1_000UL))
        val id = unlocked.session.index.rows(Chip.All, "").first { it.title == "Router" }.id
        assertTrue(coordinator.stageDelete(id, kotlin.time.Duration.parse("1h")))
        assertTrue(coordinator.commitStaged()!!.await() is SaveResult.UnexpectedError)
        assertTrue(coordinator.lastProblem is SaveResult.UnexpectedError)
        assertTrue(coordinator.pendingDeletes.value.hidden.isEmpty())
    }

    @Test
    fun `a copy that throws is a failed copy`() = runBlocking<Unit> {
        val saver = FakeVaultSaver().apply { result = { vault, prepared -> SaveResult.WriteFailed(vault, prepared) } }
        val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), scope)
        unlockWith(FakeVaultStorage(), TestVaults.bytes(aesRounds = 1_000UL))
        coordinator.save(retitled(sessions.current.value!!, "Edited")).await()
        saver.copyResult = { throw IllegalStateException("unexpected") }
        assertEquals(org.onekash.kashpass.vault.save.CopyResult.Failed("content://fake/copy"), coordinator.saveCopy("content://fake/copy"))
        assertFalse(coordinator.hasRunningJobs)
    }

    @Test
    fun `a backup saved as a new file whose copy or read throws is a failed copy`() = runBlocking<Unit> {
        val backups = FakeBackupStore()
        val bytes = TestVaults.bytes(aesRounds = 1_000UL)
        val info = (backups.add(TestVaults.LOCATION, bytes, org.onekash.kashpass.vault.backup.BackupKind.BEFORE_SAVE) as org.onekash.kashpass.vault.backup.BackupResult.Added).info
        val coordinator = SaveCoordinator(sessions, throwingSaver(), FakeVaultOpener(), scope, backups = backups)
        val opened = TestVaults.unlock(bytes)
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, backup = info))
        assertEquals(SaveBackupResult.Failed("content://fake/copy"), coordinator.saveBackupAsNewFile("content://fake/copy"))
        val unreadable = object : org.onekash.kashpass.vault.backup.BackupStore by backups {
            override suspend fun read(location: String, id: String): ByteArray = throw IllegalStateException("unexpected")
        }
        val reading = SaveCoordinator(sessions, FakeVaultSaver(), FakeVaultOpener(), scope, backups = unreadable)
        assertEquals(SaveBackupResult.Failed("content://fake/copy"), reading.saveBackupAsNewFile("content://fake/copy"))
    }

    @Test
    fun `a save job that failed with an exception settles as a lost change`() = runBlocking<Unit> {
        val coordinator = SaveCoordinator(sessions, FakeVaultSaver(), FakeVaultOpener(), scope)
        val failed = kotlinx.coroutines.CompletableDeferred<SaveResult?>().apply { completeExceptionally(IllegalStateException("unexpected")) }
        assertTrue(coordinator.settle(failed).lostChange)
        val cancelled = kotlinx.coroutines.CompletableDeferred<SaveResult?>().apply { cancel() }
        assertFalse("a cancelled save is not reported here", coordinator.settle(cancelled).lostChange)
    }
}

class SaveCoordinatorChoicesTest {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sessions = SessionHolder()
    private val storage = FakeVaultStorage()
    private val saver = FakeVaultSaver()
    private val opener = FakeVaultOpener()
    private val coordinator = SaveCoordinator(sessions, saver, opener, scope, storage)

    private fun unlock(): Unlocked = runBlocking {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false).also(sessions::set)
    }

    @Test
    fun `save as copy reuses the failed save and keeps the vault on its file`() = runBlocking<Unit> {
        val unlocked = unlock()
        saver.result = { vault, prepared -> SaveResult.Conflict(vault, prepared) }
        coordinator.save(unlocked.session.opened.document).await()
        assertEquals(org.onekash.kashpass.vault.save.CopyResult.Saved("copy.kdbx"), coordinator.saveCopy("content://fake/copy"))
        assertEquals(listOf("save" to TestVaults.LOCATION, "copy" to "content://fake/copy"), saver.calls)
        assertEquals(TestVaults.LOCATION, sessions.current.value!!.location)
        coordinator.clearProblem()
        assertNull(coordinator.saveCopy("content://fake/copy2"))
    }

    @Test
    fun `reload drops the change and clears the problem`() = runBlocking<Unit> {
        val unlocked = unlock()
        saver.result = { vault, prepared -> SaveResult.Conflict(vault, prepared) }
        coordinator.save(unlocked.session.opened.document).await()
        coordinator.reload()
        assertNull(coordinator.problem.value)
        assertEquals(listOf("reopen"), opener.calls)
    }

    @Test
    fun `file details report the opened file and the provider's current metadata`() = runBlocking<Unit> {
        val unlocked = unlock()
        storage.put(TestVaults.LOCATION, ByteArray(4_096))
        storage.describe(TestVaults.LOCATION, "Vault.kdbx", null)
        val details = coordinator.fileDetails()!!
        assertEquals(unlocked.session.opened.openedSize, details.openedSize)
        assertEquals(4_096L, details.nowSize)
        assertNull(details.nowModified)
    }

    @Test
    fun `an empty copy file is deleted when the provider allows`() = runBlocking<Unit> {
        val made = storage.createDocument("Vault (phone).kdbx")
        assertEquals(org.onekash.kashpass.vault.storage.DeleteResult.DELETED, coordinator.deleteCopy(made))
        val kept = storage.createDocument("Other.kdbx", deletable = false)
        assertEquals(org.onekash.kashpass.vault.storage.DeleteResult.UNSUPPORTED, coordinator.deleteCopy(kept))
    }
}

class SaveCoordinatorFailureTest {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sessions = SessionHolder()
    private val saver = FakeVaultSaver()
    private val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), scope)

    private fun unlock(): Unlocked = runBlocking {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false).also(sessions::set)
    }

    private fun titles() = sessions.current.value!!.session.index.rows(Chip.All, "").map { it.title }

    private fun added(unlocked: Unlocked, title: String) =
        EntryEdits.add(unlocked.session.opened.document, null, EntryDraft(title, "", org.onekash.kashpass.vault.doc.ProtectedText.of("p"), "", ""), Instant.now()).document

    @Test
    fun `a failed save leaves the session on the document before the edit`() = runBlocking<Unit> {
        val unlocked = unlock()
        saver.result = { vault, prepared -> SaveResult.Conflict(vault, prepared) }
        coordinator.save(added(unlocked, "New one")).await()
        assertTrue("the unsaved entry isn't shown as if it were saved", "New one" !in titles())
        // Saving again after "Keep editing" adds the entry once.
        saver.result = { vault, _ -> SaveResult.Saved(vault.withBaseline(OpenedVault.Baseline.Known("1".repeat(64)))) }
        coordinator.save(added(sessions.current.value!!, "New one")).await()
        assertEquals(1, titles().count { it == "New one" })
    }

    @Test
    fun `a retry that fails again leaves a usable session`() = runBlocking<Unit> {
        val unlocked = unlock()
        saver.result = { vault, prepared -> SaveResult.WriteFailed(vault, prepared) }
        coordinator.save(added(unlocked, "x")).await()
        coordinator.retry().await()
        coordinator.retry().await()
        assertEquals(org.onekash.kashpass.vault.doc.Saveability.Saveable, sessions.current.value!!.session.saveability)
    }

    @Test
    fun `a save started from an older session reports its result`() = runBlocking<Unit> {
        val unlocked = unlock()
        // As the real saver: the first call writes, a later one finds the file changed under it.
        saver.result = { vault, prepared -> if (saver.calls.size == 1) SaveResult.Saved(vault) else SaveResult.Conflict(vault, prepared) }
        saver.hold()
        val first = coordinator.save(added(unlocked, "First"))
        val second = coordinator.save(added(unlocked, "Second"))
        saver.release()
        val early = first.await()
        assertTrue("got $early", early is SaveResult.Saved)
        val late = second.await()
        assertTrue("got $late", late is SaveResult.Conflict)
        assertTrue("titles ${titles()}", "First" in titles())
    }

    @Test
    fun `a lock cancels every running save`() = runBlocking<Unit> {
        val unlocked = unlock()
        saver.hold()
        val a = coordinator.save(added(unlocked, "a"))
        val b = coordinator.save(added(unlocked, "b"))
        while (!saver.isSaving.value) Thread.sleep(10)
        coordinator.cancelRunning()
        assertTrue(a.isCancelled)
        assertTrue(b.isCancelled)
        saver.release()
    }

    @Test
    fun `a second Retry while one runs is ignored`() = runBlocking<Unit> {
        val unlocked = unlock()
        saver.result = { vault, prepared -> SaveResult.WriteFailed(vault, prepared) }
        coordinator.save(added(unlocked, "x")).await()
        saver.hold()
        val first = coordinator.retry()
        while (!saver.isSaving.value) Thread.sleep(10)
        org.junit.Assert.assertNull(coordinator.retry().await())
        saver.release()
        first.await()
        assertEquals(2, saver.calls.size)
    }

    @Test
    fun `a lock cancels a copy being written`() = runBlocking<Unit> {
        val unlocked = unlock()
        saver.result = { vault, prepared -> SaveResult.Conflict(vault, prepared) }
        coordinator.save(added(unlocked, "x")).await()
        saver.hold()
        val copy = kotlinx.coroutines.CoroutineScope(Dispatchers.IO).async { coordinator.saveCopy("content://fake/copy") }
        while (!saver.isSaving.value) Thread.sleep(10)
        coordinator.cancelRunning()
        saver.release()
        org.junit.Assert.assertTrue(runCatching { copy.await() }.exceptionOrNull() is kotlinx.coroutines.CancellationException)
    }
}

/**
 * Overlapping saves: each reaches the saver and replaces the session in the order it was started,
 * so the session shown is the one the file holds.
 */
class SaveOrderTest {

    private class Rig(saver: (CoroutineScope, FakeVaultStorage) -> VaultSaving, vault: ByteArray, compute: kotlinx.coroutines.CoroutineDispatcher = Dispatchers.Default) {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val storage = FakeVaultStorage()
        val sessions = SessionHolder()
        val saver = saver(scope, storage)
        val coordinator = SaveCoordinator(sessions, this.saver, FakeVaultOpener(), scope, compute = compute)
        val unlocked: Unlocked

        init {
            storage.put(TestVaults.LOCATION, vault)
            val opened = runBlocking { VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO).open(TestVaults.LOCATION, TestVaults.PASSWORD.toCharArray()) as OpenResult.Unlocked }
            unlocked = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false).also(sessions::set)
        }

        /** Collects the next [n] reported results; call before starting the saves. */
        fun expect(n: Int) = scope.async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
            kotlinx.coroutines.withTimeout(30_000) { coordinator.results.take(n).map { it.result }.toList() }
        }

        fun titles() = sessions.current.value!!.session.index.rows(Chip.All, "").map { it.title }

        /**
         * Returns [unlocked]'s document with an entry [title] added. Call it, and start every save
         * based on [unlocked], while the first save is held: a save that ends swaps in its result
         * and releases [unlocked]'s session, and a later save from it has nothing to save.
         */
        fun added(title: String) =
            EntryEdits.add(unlocked.session.opened.document, null, EntryDraft(title, "", org.onekash.kashpass.vault.doc.ProtectedText.of("p"), "", ""), Instant.now()).document

        fun close() = scope.cancel()
    }

    private fun safeSaver(scope: CoroutineScope, storage: FakeVaultStorage): VaultSaving =
        SafeSaver.create(storage, FakeBackupStore(), FakeSaveMarkerStore(), FakeVaultStateStore(), Dispatchers.IO, scope)

    private fun SaveResult.has(title: String) = VaultSession.from(opened).index.rows(Chip.All, "").any { it.title == title }

    @Test
    fun `of two overlapping saves the first is saved and shown and the second is a conflict, every time`() = runBlocking<Unit> {
        repeat(50) { round ->
            // The real SafeSaver, held until both saves are started, so the two overlap.
            val started = kotlinx.coroutines.CompletableDeferred<Unit>()
            val rig = Rig({ scope, storage ->
                val real = safeSaver(scope, storage)
                object : VaultSaving by real {
                    override suspend fun save(location: String, vault: OpenedVault): SaveResult {
                        started.await()
                        return real.save(location, vault)
                    }
                }
            }, TestVaults.bytes(aesRounds = 1_000UL))
            try {
                val events = rig.expect(2)
                val firstDoc = rig.added("First")
                val secondDoc = rig.added("Second")
                val first = rig.coordinator.save(firstDoc, rig.unlocked)
                val second = rig.coordinator.save(secondDoc, rig.unlocked)
                started.complete(Unit)
                val a = first.await()
                val b = second.await()
                assertTrue("round $round: first got $a", a is SaveResult.Saved)
                assertTrue("round $round: second got $b", b is SaveResult.Conflict)
                assertTrue("round $round: titles ${rig.titles()}", "First" in rig.titles() && "Second" !in rig.titles())
                assertTrue("round $round: the file holds the first save", rig.storage.bytes(TestVaults.LOCATION)!!.let { bytes ->
                    (runBlocking { TestVaults.unlock(bytes) }).session.index.rows(Chip.All, "").any { it.title == "First" }
                })
                assertEquals("round $round: results in start order", listOf(true, false), events.await().map { it is SaveResult.Saved })
            } finally {
                rig.close()
            }
        }
    }

    @Test
    fun `a first save that carries staged deletes reaches the file before a later save`() = runBlocking<Unit> {
        // Holds the first job sent to compute (the staged deletes) until the second save has
        // reached the saver, or for 2 s when it never does: with the start order kept the test
        // takes the full 2 s.
        val secondReachedSaver = kotlinx.coroutines.CompletableDeferred<Unit>()
        val heldOnce = java.util.concurrent.atomic.AtomicBoolean(false)
        val compute = object : kotlinx.coroutines.CoroutineDispatcher() {
            override fun dispatch(context: kotlin.coroutines.CoroutineContext, block: Runnable) {
                if (heldOnce.compareAndSet(false, true)) {
                    Dispatchers.IO.dispatch(context, Runnable {
                        runBlocking { kotlinx.coroutines.withTimeoutOrNull(2_000) { secondReachedSaver.await() } }
                        block.run()
                    })
                } else {
                    Dispatchers.Default.dispatch(context, block)
                }
            }
        }
        var saves = 0
        // A spy over the real SafeSaver that only counts its calls; the shared fake's scripted
        // results can't show which save the saver let write first.
        val rig = Rig({ scope, storage ->
            val real = safeSaver(scope, storage)
            object : VaultSaving by real {
                override suspend fun save(location: String, vault: OpenedVault): SaveResult {
                    if (synchronized(this) { ++saves } == 2) secondReachedSaver.complete(Unit)
                    return real.save(location, vault)
                }
            }
        }, TestVaults.browserVault(aesRounds = 1_000UL), compute)
        try {
            val router = rig.unlocked.session.index.rows(Chip.All, "").first { it.title == "Router" }.id
            assertTrue(rig.coordinator.stageDelete(router, kotlin.time.Duration.parse("1h")))
            val firstDoc = rig.added("First")
            val secondDoc = rig.added("Second")
            val first = rig.coordinator.save(firstDoc, rig.unlocked)
            val second = rig.coordinator.save(secondDoc, rig.unlocked)
            assertTrue("first got ${first.await()}", first.await() is SaveResult.Saved)
            assertTrue("second got ${second.await()}", second.await() is SaveResult.Conflict)
            assertTrue(rig.titles().toString(), "First" in rig.titles() && "Router" !in rig.titles())
        } finally {
            rig.close()
        }
    }

    @Test
    fun `a save started before a lock request saves`() = runBlocking<Unit> {
        val fake = FakeVaultSaver()
        val rig = Rig({ _, _ -> fake }, TestVaults.bytes(aesRounds = 1_000UL))
        try {
            fake.hold()
            rig.coordinator.save(rig.added("A"), rig.unlocked)
            val second = rig.coordinator.save(rig.added("B"), rig.unlocked)
            rig.coordinator.refuseNewSaves()
            fake.release()
            val settled = rig.coordinator.settle(second)
            assertFalse("no save was refused", settled.refusedForLock)
            assertTrue("the second save ran, got ${settled.result}", settled.result is SaveResult.Saved)
            assertEquals(2, fake.calls.size)
        } finally {
            rig.close()
        }
    }

    @Test
    fun `a lock that cancels two chained saves settles`() = runBlocking<Unit> {
        val fake = FakeVaultSaver()
        val rig = Rig({ _, _ -> fake }, TestVaults.bytes(aesRounds = 1_000UL))
        try {
            fake.hold()
            rig.coordinator.save(rig.added("A"), rig.unlocked)
            val b = rig.coordinator.save(rig.added("B"), rig.unlocked)
            rig.coordinator.refuseNewSaves()
            rig.coordinator.cancelRunning()
            val settled = kotlinx.coroutines.withTimeout(10_000) { rig.coordinator.settle(b) }
            assertNull(settled.result)
            assertFalse(rig.coordinator.hasRunningJobs)
            fake.release()
        } finally {
            rig.close()
        }
    }

    @Test
    fun `cancelling a middle save keeps the order of the others`() = runBlocking<Unit> {
        val fake = FakeVaultSaver()
        val aJob = kotlinx.coroutines.CompletableDeferred<Deferred<SaveResult?>>()
        val cAtSaver = kotlinx.coroutines.CompletableDeferred<Boolean>()
        // A spy over the shared fake that records, when C calls the saver, whether A's job (its
        // swap included) has ended.
        val rig = Rig({ _, _ ->
            object : VaultSaving by fake {
                override suspend fun save(location: String, vault: OpenedVault): SaveResult {
                    if (VaultSession.from(vault).index.rows(Chip.All, "").any { it.title == "C" }) cAtSaver.complete(aJob.await().isCompleted)
                    return fake.save(location, vault)
                }
            }
        }, TestVaults.bytes(aesRounds = 1_000UL))
        try {
            val events = rig.expect(2)
            fake.hold()
            val a = rig.coordinator.save(rig.added("A"), rig.unlocked).also(aJob::complete)
            val b = rig.coordinator.save(rig.added("B"), rig.unlocked)
            val c = rig.coordinator.save(rig.added("C"), rig.unlocked)
            b.cancel()
            // While A is held, C must not reach the saver; an overtaking C has 1 s to reach it.
            kotlinx.coroutines.withTimeoutOrNull(1_000) { cAtSaver.await() }
            fake.release()
            a.await()
            c.await()
            assertEquals("A's job, swap included, ended before C called the saver", true, cAtSaver.await())
            assertEquals("A then C reach the saver", listOf("A", "C"), fake.saved.map { v -> listOf("A", "B", "C").first { VaultSession.from(v).index.rows(Chip.All, "").any { r -> r.title == it } } })
            assertEquals(listOf("A", "C"), events.await().map { r -> listOf("A", "C").first { r.has(it) } })
        } finally {
            rig.close()
        }
    }

    @Test
    fun `an earlier save that fails, is refused or has nothing to save lets the next one finish`() = runBlocking<Unit> {
        val fake = FakeVaultSaver()
        val rig = Rig({ _, _ -> fake }, TestVaults.bytes(aesRounds = 1_000UL))
        try {
            fake.result = { vault, prepared -> if (VaultSession.from(vault).index.rows(Chip.All, "").any { it.title == "Throws" }) throw IllegalStateException("saver") else SaveResult.Saved(vault) }
            // Documents are built before any save: a swap releases the session they come from.
            val throws = rig.added("Throws")
            val nextDoc = rig.added("Next")
            val none = rig.added("None")
            val afterDoc = rig.added("After")
            fake.hold()
            val thrown = rig.coordinator.save(throws, rig.unlocked)
            val nothing = rig.coordinator.save(none, null)
            val next = rig.coordinator.save(nextDoc, rig.unlocked)
            val after = rig.coordinator.save(afterDoc, rig.unlocked)
            fake.release()
            thrown.await().let { assertTrue("thrown got $it", it is SaveResult.UnexpectedError) }
            assertNull(nothing.await())
            kotlinx.coroutines.withTimeout(10_000) { next.await() }.let { assertTrue("next got $it", it is SaveResult.Saved) }
            kotlinx.coroutines.withTimeout(10_000) { after.await() }.let { assertTrue("after got $it", it != null) }
            // Refused: requested after a lock request for its session; a save from a new unlock
            // after it runs.
            val current = rig.sessions.current.value!!
            val laterDoc = EntryEdits.add(current.session.opened.document, null, EntryDraft("Later", "", org.onekash.kashpass.vault.doc.ProtectedText.of("p"), "", ""), Instant.now()).document
            rig.coordinator.refuseNewSaves()
            val refused = rig.coordinator.save(laterDoc, current)
            val reopened = VaultOpener.create(rig.storage, FakeVaultStateStore(), Dispatchers.IO).open(TestVaults.LOCATION, TestVaults.PASSWORD.toCharArray()) as OpenResult.Unlocked
            val relocked = Unlocked(TestVaults.LOCATION, reopened.session, reopened.kdf, false).also(rig.sessions::set)
            val later = rig.coordinator.save(EntryEdits.add(relocked.session.opened.document, null, EntryDraft("Later", "", org.onekash.kashpass.vault.doc.ProtectedText.of("p"), "", ""), Instant.now()).document, relocked)
            assertNull(refused.await())
            assertTrue(kotlinx.coroutines.withTimeout(10_000) { later.await() } is SaveResult.Saved)
        } finally {
            rig.close()
        }
    }

    @Test
    fun `staged deletes committed after two running saves are written last`() = runBlocking<Unit> {
        val fake = FakeVaultSaver()
        val rig = Rig({ _, _ -> fake }, TestVaults.browserVault(aesRounds = 1_000UL))
        try {
            val events = rig.expect(3)
            fake.hold()
            val a = rig.coordinator.save(rig.added("A"), rig.unlocked)
            val b = rig.coordinator.save(rig.added("B"), rig.unlocked)
            val router = rig.unlocked.session.index.rows(Chip.All, "").first { it.title == "Router" }.id
            assertTrue(rig.coordinator.stageDelete(router, kotlin.time.Duration.parse("1h")))
            val commit = rig.coordinator.commitStaged()!!
            assertFalse("the commit waits for the running saves", commit.isCompleted)
            fake.release()
            a.await()
            b.await()
            kotlinx.coroutines.withTimeout(10_000) { commit.await() }
            assertEquals(3, fake.saved.size)
            assertTrue("the commit is the last result", events.await().last().let { !it.has("Router") })
        } finally {
            rig.close()
        }
    }
}
