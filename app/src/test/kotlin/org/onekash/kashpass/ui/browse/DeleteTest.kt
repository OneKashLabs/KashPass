package org.onekash.kashpass.ui.browse

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.edit.DeleteKind
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class DeleteTest {

    private val dispatcher = StandardTestDispatcher()
    private val sessions = SessionHolder()
    private val saver = FakeVaultSaver()
    private lateinit var vm: BrowseViewModel
    private lateinit var coordinator: SaveCoordinator

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
        val opened = runBlocking { TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL)) }
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), CoroutineScope(SupervisorJob() + dispatcher), compute = dispatcher)
        vm = BrowseViewModel(sessions, FakeVaultOpener(), coordinator, compute = dispatcher) { true }
    }

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun titles(chip: Chip = Chip.All) = sessions.current.value!!.session.index.rows(chip, "").map { it.title }
    private fun id(title: String, chip: Chip = Chip.All) = sessions.current.value!!.session.index.rows(chip, "").first { it.title == title }.id

    private val window = 4.seconds

    private fun shown() = vm.uiState.value!!.rows.map { it.title }

    @Test
    fun `a delete hides the row at once and saves once when the window ends`() = runTest(dispatcher) {
        assertEquals(DeleteKind.TO_RECYCLE_BIN, vm.deleteKind(id("Router")))
        vm.delete(id("Router"), window)
        runCurrent()
        assertFalse("Router" in shown())
        assertEquals(1, vm.uiState.value!!.pendingDeletes)
        assertEquals(0, saver.calls.size)
        advanceUntilIdle()
        assertEquals(1, saver.calls.size)
        assertTrue("Router" in titles(Chip.RecycleBin))
        assertFalse("Router" in shown())
        assertEquals(0, vm.uiState.value!!.pendingDeletes)
    }

    @Test
    fun `Undo brings every staged row back and saves nothing`() = runTest(dispatcher) {
        vm.delete(id("Router"), window)
        vm.delete(id("Example Mail"), window)
        runCurrent()
        assertEquals(2, vm.uiState.value!!.pendingDeletes)
        vm.undoDeletes()
        advanceUntilIdle()
        assertEquals(0, saver.calls.size)
        assertTrue("Router" in shown())
        assertTrue("Example Mail" in shown())
    }

    @Test
    fun `two deletes in one window save once`() = runTest(dispatcher) {
        vm.delete(id("Router"), window)
        advanceTimeBy(window.inWholeMilliseconds - 1)
        vm.delete(id("Example Mail"), window)
        advanceUntilIdle()
        assertEquals(1, saver.calls.size)
        assertTrue(titles(Chip.RecycleBin).containsAll(listOf("Router", "Example Mail")))
    }

    @Test
    fun `a permanent delete saves at once and carries staged deletes`() = runTest(dispatcher) {
        val events = mutableListOf<DeleteEvent>()
        backgroundScope.launch { vm.deletes.collect { events += it } }
        runCurrent()
        vm.delete(id("Router"), window)
        val old = id("Old Bank", Chip.RecycleBin)
        assertEquals(DeleteKind.PERMANENT, vm.deleteKind(old))
        vm.delete(old, window)
        runCurrent()
        assertTrue("a permanent delete is never staged", "Old Bank" in titles(Chip.RecycleBin))
        vm.deletePermanently(old)
        runCurrent()
        assertEquals(1, saver.calls.size)
        runCurrent()
        assertEquals(listOf(DeleteEvent.Deleted), events)
        assertFalse("Old Bank" in titles(Chip.RecycleBin))
        assertTrue("Router" in titles(Chip.RecycleBin))
        advanceUntilIdle()
        assertEquals("the window has nothing left to save", 1, saver.calls.size)
    }

    @Test
    fun `a permanent delete that isn't saved says so`() = runTest(dispatcher) {
        val events = mutableListOf<DeleteEvent>()
        backgroundScope.launch { vm.deletes.collect { events += it } }
        runCurrent()
        saver.result = { vault, prepared -> SaveResult.WriteFailed(vault, prepared) }
        vm.deletePermanently(id("Old Bank", Chip.RecycleBin))
        advanceUntilIdle()
        runCurrent()
        assertEquals(listOf(DeleteEvent.NotSaved), events)
        assertTrue("Old Bank" in titles(Chip.RecycleBin))
    }

    @Test
    fun `edit, add and delete are off while a save runs`() = runTest(dispatcher) {
        saver.hold()
        vm.delete(id("Router"), window)
        advanceTimeBy(window.inWholeMilliseconds + 1)
        runCurrent()
        assertEquals(false, vm.uiState.value!!.canEdit)
        assertFalse("hidden while its save runs", "Router" in shown())
        saver.release()
        advanceUntilIdle()
        assertEquals(true, vm.uiState.value!!.canEdit)
    }

    @Test
    fun `a delete closes its open entry, and the vault reads empty when every entry is staged`() = runTest(dispatcher) {
        val router = id("Router")
        vm.openEntry(router)
        vm.delete(router, window)
        runCurrent()
        assertEquals(null, vm.uiState.value!!.openEntry)
        for (row in sessions.current.value!!.session.index.rows(Chip.All, "")) vm.delete(row.id, window)
        runCurrent()
        assertTrue(vm.uiState.value!!.vaultEmpty)
        vm.undoDeletes()
        runCurrent()
        assertFalse(vm.uiState.value!!.vaultEmpty)
    }

    @Test
    fun `a tag closes the entry and searches for that tag`() = runTest(dispatcher) {
        vm.openEntry(id("Router"))
        vm.searchTag("network")
        runCurrent()
        assertEquals("network", vm.uiState.value!!.query)
        assertEquals(null, vm.uiState.value!!.openEntry)
    }

    @Test
    fun `a tag with spaces or a leading minus searches as one phrase`() = runTest(dispatcher) {
        vm.searchTag("home network")
        runCurrent()
        assertEquals("\"home network\"", vm.uiState.value!!.query)
        vm.searchTag("-urgent")
        runCurrent()
        assertEquals("\"urgent\"", vm.uiState.value!!.query)
    }

    @Test
    fun `a lock saves staged deletes behind the cover`() = runTest(dispatcher) {
        val locker = org.onekash.kashpass.lock.LockController(sessions, backgroundScope, { testScheduler.currentTime }, coordinator)
        vm.delete(id("Router"), window)
        locker.lock()
        advanceUntilIdle()
        assertEquals(1, saver.calls.size)
        assertEquals(null, sessions.current.value)
    }

    @Test
    fun `a new entry goes to the selected group, else to the top level`() = runTest(dispatcher) {
        val chips = sessions.current.value!!.session.index.chips
        val group = chips.filterIsInstance<Chip.Group>().first()
        vm.selectChip(group)
        assertEquals(group.id, vm.addTarget())
        vm.selectChip(Chip.All)
        assertEquals(null, vm.addTarget())
        vm.selectChip(Chip.RecycleBin)
        assertEquals(null, vm.addTarget())
        vm.selectChip(group)
        vm.setQuery("mail")
        assertEquals("a search shows entries from every group", null, vm.addTarget())
    }

}
