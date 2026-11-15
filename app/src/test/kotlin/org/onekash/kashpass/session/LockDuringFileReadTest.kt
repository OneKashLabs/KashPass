package org.onekash.kashpass.session

import java.time.Instant
import java.util.concurrent.Executors
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.browse.BrowseViewModel
import org.onekash.kashpass.ui.edit.EditorViewModel
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

/**
 * A lock (screen off) while the opener reads the file on its own thread, as a slow cloud read
 * holds it, is a lock to the screen that called, never an exception that escapes its coroutine
 * (VaultOpening.refresh and reopen stop, SaveCoordinator returns locked). The opener runs on a real
 * thread whose read is held; the view models run on the test main dispatcher.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class LockDuringFileReadTest {

    private val main = StandardTestDispatcher()
    private val ioThread = Executors.newSingleThreadExecutor()
    private val io = ioThread.asCoroutineDispatcher()
    private val storage = FakeVaultStorage()
    private val state = FakeVaultStateStore()
    private val sessions = SessionHolder()

    @Before
    fun setUp() {
        Dispatchers.setMain(main)
        storage.put(TestVaults.LOCATION, TestVaults.browserVault(aesRounds = 1_000UL))
        val opened = runBlocking { VaultOpener.create(storage, state, Dispatchers.Unconfined).open(TestVaults.LOCATION, TestVaults.PASSWORD.toCharArray()) as OpenResult.Unlocked }
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        ioThread.shutdownNow()
    }

    private fun coordinator() = SaveCoordinator(sessions, FakeVaultSaver(), VaultOpener.create(storage, state, io), CoroutineScope(SupervisorJob() + main), compute = main)

    // Waits until the opener's thread is inside a held read.
    private fun awaitHeldRead(before: Int) {
        val end = System.nanoTime() + 10_000_000_000L
        while (storage.reads + storage.prefixReads.size == before) {
            check(System.nanoTime() < end) { "the opener never read the file" }
            Thread.sleep(5)
        }
    }

    // Lets the held read finish and waits for the opener's thread to finish its work.
    private fun releaseAndDrainIo() {
        storage.releaseReads()
        ioThread.submit {}.get()
    }

    @Test
    fun `a lock while the editor re-reads a file another device changed`() = runTest(main) {
        val coordinator = coordinator()
        val editor = EditorViewModel(sessions, coordinator, { Instant.now() }, main)
        val id = sessions.current.value!!.session.index.rows(Chip.All, "").first().id
        // Another device saved: the file differs from the one the session opened.
        storage.put(TestVaults.LOCATION, TestVaults.browserVault(aesRounds = 1_000UL))
        storage.blockReads()
        val before = storage.reads + storage.prefixReads.size
        editor.startEdit(id)
        runCurrent()
        awaitHeldRead(before)
        sessions.lock()
        runCurrent()
        releaseAndDrainIo()
        runCurrent()
        assertNull(sessions.current.value)
        // Reaching the end with no uncaught exception reported to runTest means no crash.
    }

    @Test
    fun `a lock while the browser closes a backup and reopens the file`() = runTest(main) {
        val coordinator = coordinator()
        val browse = BrowseViewModel(sessions, VaultOpener.create(storage, state, io), coordinator, compute = main, copyToClipboard = { true })
        storage.blockReads()
        val before = storage.reads + storage.prefixReads.size
        browse.closeBackup()
        runCurrent()
        awaitHeldRead(before)
        sessions.lock()
        runCurrent()
        releaseAndDrainIo()
        runCurrent()
        assertTrue(sessions.current.value == null)
    }
}
