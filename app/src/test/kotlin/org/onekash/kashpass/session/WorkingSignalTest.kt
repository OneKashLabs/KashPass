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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

/**
 * Checks [SaveCoordinator.working] for re-reads, reopens, closing a backup and the staged-delete
 * commit. Only saves, the commit among them, set [SaveCoordinator.busy].
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class WorkingSignalTest {

    private val dispatcher = StandardTestDispatcher()
    private val scope = TestScope(dispatcher)
    private val sessions = SessionHolder()
    private val saver = FakeVaultSaver()
    private val opener = FakeVaultOpener(dispatcher)
    private val coordinator = SaveCoordinator(
        sessions, saver, opener, CoroutineScope(SupervisorJob() + dispatcher), compute = dispatcher,
    )

    init {
        val opened = runBlocking { TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL)) }
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
    }

    private fun id(title: String) = sessions.current.value!!.session.index.rows(Chip.All, "").first { it.title == title }.id

    @Test
    fun `the re-read before an edit is working, not busy`() = scope.runTest {
        assertFalse(coordinator.working.value)
        opener.hold()
        val check = async { coordinator.refreshForEdit(id("Router")) }
        runCurrent()
        assertTrue(coordinator.working.value)
        assertFalse("busy stays for saves only", coordinator.busy.value)
        opener.release()
        check.await()
        assertFalse(coordinator.working.value)
    }

    @Test
    fun `a cancelled re-read ends working`() = scope.runTest {
        opener.hold()
        val check = async { coordinator.refreshForAdd() }
        runCurrent()
        assertTrue(coordinator.working.value)
        check.cancel()
        runCurrent()
        assertFalse(coordinator.working.value)
        opener.release()
    }

    @Test
    fun `reopening the file is working`() = scope.runTest {
        opener.hold()
        val reload = async { coordinator.reload() }
        runCurrent()
        assertTrue(coordinator.working.value)
        opener.release()
        reload.await()
        assertFalse(coordinator.working.value)
    }

    @Test
    fun `the undo window is not working, its commit is`() = scope.runTest {
        val window = 4.seconds
        saver.hold()
        coordinator.stageDelete(id("Router"), window)
        runCurrent()
        assertFalse("the window only waits", coordinator.working.value)
        advanceTimeBy(window.inWholeMilliseconds + 1)
        runCurrent()
        assertTrue(coordinator.working.value)
        saver.release()
        advanceUntilIdle()
        assertFalse(coordinator.working.value)
    }

    @Test
    fun `closing a backup is working until the file reopens`() = scope.runTest {
        opener.hold()
        val close = async { coordinator.closeBackup() }
        runCurrent()
        assertTrue(coordinator.working.value)
        opener.release()
        close.await()
        assertFalse(coordinator.working.value)
    }
}
