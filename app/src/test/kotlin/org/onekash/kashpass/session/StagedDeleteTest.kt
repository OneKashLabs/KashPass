package org.onekash.kashpass.session

import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.lock.LockController
import org.onekash.kashpass.vault.edit.EntryDelete
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.open.VaultSession
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

/** Deletes to the recycle bin save once, when the undo window ends. */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class StagedDeleteTest {

    private val dispatcher = StandardTestDispatcher()
    private val scope = TestScope(dispatcher)
    private val sessions = SessionHolder()
    private val saver = FakeVaultSaver()
    private val opener = FakeVaultOpener(dispatcher)
    private val coordinator = SaveCoordinator(
        sessions, saver, opener, CoroutineScope(SupervisorJob() + dispatcher), compute = dispatcher,
    )
    private val window = 4.seconds

    init {
        val opened = runBlocking { TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL)) }
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
    }

    private fun index() = sessions.current.value!!.session.index
    private fun id(title: String, chip: Chip = Chip.All) = index().rows(chip, "").first { it.title == title }.id
    private fun titles(chip: Chip = Chip.All) = index().rows(chip, "").map { it.title }
    private fun saves() = saver.calls.count { it.first == "save" }

    @Test
    fun `staged deletes write nothing until the window ends, then save once together`() = scope.runTest {
        val router = id("Router")
        val mail = id("Example Mail")
        assertTrue(coordinator.stageDelete(router, window))
        assertTrue(coordinator.stageDelete(mail, window))
        assertEquals(PendingDeletes(listOf(router, mail), emptySet()), coordinator.pendingDeletes.value)
        advanceTimeBy(window.inWholeMilliseconds - 1)
        runCurrent()
        assertEquals("the window restarts with each delete", 0, saves())
        advanceUntilIdle()
        assertEquals(1, saves())
        assertFalse("Router" in titles())
        assertFalse("Example Mail" in titles())
        assertTrue("Router" in titles(Chip.RecycleBin))
        assertEquals(PendingDeletes(emptyList(), emptySet()), coordinator.pendingDeletes.value)
    }

    @Test
    fun `the rows stay hidden while the commit save runs`() = scope.runTest {
        val router = id("Router")
        saver.hold()
        coordinator.stageDelete(router, window)
        advanceTimeBy(window.inWholeMilliseconds + 1)
        runCurrent()
        assertTrue(saver.isSaving.value)
        assertEquals(setOf(router), coordinator.pendingDeletes.value.hidden)
        assertEquals(0, coordinator.pendingDeletes.value.count)
        saver.release()
        advanceUntilIdle()
        assertEquals(emptySet<String>(), coordinator.pendingDeletes.value.hidden)
        assertFalse("Router" in titles())
    }

    @Test
    fun `undo writes nothing`() = scope.runTest {
        coordinator.stageDelete(id("Router"), window)
        coordinator.undoStaged()
        advanceUntilIdle()
        assertEquals(0, saves())
        assertTrue("Router" in titles())
        assertEquals(0, coordinator.pendingDeletes.value.count)
    }

    @Test
    fun `another save carries the staged deletes, and the window then saves nothing`() = scope.runTest {
        coordinator.stageDelete(id("Router"), window)
        val doc = sessions.current.value!!.session.opened.document
        val mail = id("Example Mail")
        val d = EntryEdits.draftOf(doc, mail)!!
        val edited = (EntryEdits.edit(doc, mail, EntryDraft("Mail renamed", d.userName, d.password, d.url, d.notes), java.time.Instant.now()) as EditResult.Changed).document
        coordinator.save(edited)
        advanceUntilIdle()
        assertEquals(1, saves())
        assertTrue("Mail renamed" in titles())
        assertFalse("Router" in titles())
    }

    @Test
    fun `a permanent delete can't be staged, and a delete that became permanent is dropped`() = scope.runTest {
        assertFalse(coordinator.stageDelete(id("Old Bank", Chip.RecycleBin), window))
        val router = id("Router")
        coordinator.stageDelete(router, window)
        // The file changed: Router is in the bin, so a delete would be permanent.
        val unlocked = sessions.current.value!!
        val moved = EntryDelete.delete(unlocked.session.opened.document, router, java.time.Instant.now())!!.document
        sessions.replace(unlocked, VaultSession.from(unlocked.session.opened.withDocument(moved)))
        advanceUntilIdle()
        assertEquals("nothing left to save", 0, saves())
        assertTrue("Router" in titles(Chip.RecycleBin))
    }

    @Test
    fun `opening a backup and starting an add commit staged deletes first`() = scope.runTest {
        coordinator.stageDelete(id("Router"), window)
        coordinator.refreshForAdd()
        assertEquals(1, saves())
        coordinator.stageDelete(id("Example Mail"), window)
        coordinator.openBackup(org.onekash.kashpass.vault.backup.BackupInfo("b", java.time.Instant.EPOCH, 10L, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "00"))
        assertEquals(2, saves())
        assertEquals(listOf("save", "save"), saver.calls.map { it.first })
    }

    @Test
    fun `a session ending without a commit drops the staged deletes`() = scope.runTest {
        coordinator.stageDelete(id("Router"), window)
        sessions.lock()
        advanceUntilIdle()
        assertEquals(0, saves())
        assertEquals(0, coordinator.pendingDeletes.value.count)
    }

    @Test
    fun `a lock saves staged deletes behind the cover and reports no lost change`() = scope.runTest {
        val locker = LockController(sessions, this, { testScheduler.currentTime }, coordinator)
        coordinator.stageDelete(id("Router"), window)
        locker.lock()
        assertTrue(locker.covering.value)
        advanceUntilIdle()
        assertEquals(1, saves())
        assertEquals(null, sessions.current.value)
        assertEquals(null, locker.lostChange.value)
    }

    @Test
    fun `leaving the app commits staged deletes and the coordinator reads busy until done`() = scope.runTest {
        val locker = LockController(sessions, this, { testScheduler.currentTime }, coordinator)
        coordinator.stageDelete(id("Router"), window)
        locker.onBackground()
        assertTrue(coordinator.busy.value)
        runCurrent()
        assertEquals(1, saves())
        advanceTimeBy(1_000)
        runCurrent()
        assertFalse(coordinator.busy.value)
    }

    @Test
    fun `a commit started on leaving the app isn't refused by the lock that follows`() = scope.runTest {
        val locker = LockController(sessions, this, { testScheduler.currentTime }, coordinator)
        coordinator.stageDelete(id("Router"), window)
        locker.onBackground()
        locker.lock()
        advanceUntilIdle()
        assertEquals(1, saves())
        assertEquals(null, locker.lostChange.value)
    }

    @Test
    fun `a second commit waits for the first instead of deadlocking`() = scope.runTest {
        saver.hold()
        coordinator.stageDelete(id("Router"), window)
        val first = coordinator.commitStaged()!!
        runCurrent()
        coordinator.stageDelete(id("Example Mail"), window)
        val second = coordinator.commitStaged()!!
        runCurrent()
        saver.release()
        advanceUntilIdle()
        assertTrue(first.isCompleted && second.isCompleted)
        assertEquals(2, saves())
        assertFalse("Example Mail" in titles())
    }

    @Test
    fun `opening a backup waits for a commit already running`() = scope.runTest {
        saver.hold()
        coordinator.stageDelete(id("Router"), window)
        coordinator.commitStaged()
        runCurrent()
        val open = async { coordinator.openBackup(backup) }
        runCurrent()
        assertFalse("waits for the commit's save", open.isCompleted)
        saver.release()
        advanceUntilIdle()
        assertTrue(open.isCompleted)
        assertEquals(listOf("save"), saver.calls.map { it.first })
    }

    @Test
    fun `an entry gone by commit time is skipped`() = scope.runTest {
        val router = id("Router")
        coordinator.stageDelete(router, window)
        val unlocked = sessions.current.value!!
        val doc = unlocked.session.opened.document
        val gone = EntryDelete.delete(EntryDelete.delete(doc, router, java.time.Instant.now())!!.document, router, java.time.Instant.now())!!.document
        sessions.replace(unlocked, VaultSession.from(unlocked.session.opened.withDocument(gone)))
        advanceUntilIdle()
        assertEquals(0, saves())
    }

    @Test
    fun `a failed commit brings the rows back and reports the failure`() = scope.runTest {
        val router = id("Router")
        saver.result = { vault, prepared -> org.onekash.kashpass.vault.save.SaveResult.WriteFailed(vault, prepared) }
        coordinator.stageDelete(router, window)
        advanceUntilIdle()
        assertEquals(1, saves())
        assertEquals(emptySet<String>(), coordinator.pendingDeletes.value.hidden)
        assertTrue("Router" in titles())
        assertTrue(coordinator.problem.value is org.onekash.kashpass.vault.save.SaveResult.WriteFailed)
    }

    @Test
    fun `a save refused for a coming lock leaves the staged deletes for the lock to save`() = scope.runTest {
        coordinator.stageDelete(id("Router"), window)
        coordinator.refuseNewSaves()
        coordinator.save(sessions.current.value!!.session.opened.document)
        runCurrent()
        assertEquals(1, coordinator.pendingDeletes.value.count)
        coordinator.commitStaged()
        advanceUntilIdle()
        assertEquals(1, saves())
    }

    @Test
    fun `opening a backup waits for a save already running`() = scope.runTest {
        saver.hold()
        coordinator.save(sessions.current.value!!.session.opened.document)
        runCurrent()
        val open = async { coordinator.openBackup(backup) }
        runCurrent()
        assertFalse("waits for the save, whose trim could delete the copy", open.isCompleted)
        saver.release()
        advanceUntilIdle()
        assertTrue(open.isCompleted)
    }

    private val backup = org.onekash.kashpass.vault.backup.BackupInfo("b", java.time.Instant.EPOCH, 10L, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "00")

    @Test
    fun `after a lock the coordinator keeps no commit result, so nothing holds the vault`() = scope.runTest {
        val locker = LockController(sessions, this, { testScheduler.currentTime }, coordinator)
        coordinator.stageDelete(id("Router"), window)
        locker.lock()
        advanceUntilIdle()
        assertEquals(1, saves())
        assertFalse(coordinator.holdsResult)
    }

    @Test
    fun `a commit cancelled by a lock doesn't block the next edit start`() = scope.runTest {
        saver.hold()
        coordinator.stageDelete(id("Router"), window)
        coordinator.commitStaged()
        runCurrent()
        coordinator.cancelRunning()
        saver.release()
        advanceUntilIdle()
        assertFalse(coordinator.holdsResult)
        val check = async { coordinator.refreshForAdd() }
        advanceUntilIdle()
        assertTrue(check.isCompleted && !check.isCancelled)
    }
}
