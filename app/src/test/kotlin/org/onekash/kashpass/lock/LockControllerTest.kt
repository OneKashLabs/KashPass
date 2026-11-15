package org.onekash.kashpass.lock

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.session.LostChange
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class LockControllerTest {

    private val scope = TestScope(StandardTestDispatcher())
    private val sessions = SessionHolder()

    // Elapsed time since boot: virtual time plus [frozenFor], the time a frozen process misses.
    private var frozenFor = 0L
    private fun elapsed() = scope.testScheduler.currentTime + frozenFor

    private val controller = LockController(sessions, scope, ::elapsed)

    private suspend fun unlock() {
        val result = TestVaults.unlock(vault)
        sessions.set(Unlocked(TestVaults.LOCATION, result.session, result.kdf, result.showWeakWarning))
    }

    @Test
    fun `lock releases the session`() = runTest {
        unlock()
        val session = sessions.current.value!!.session
        controller.lock()
        assertNull(sessions.current.value)
        assertEquals(false, session.isOpen)
    }

    @Test
    fun `60 seconds in the background lock through the timer`() = runTest {
        unlock()
        controller.onBackground()
        scope.advanceTimeBy(59_999)
        scope.runCurrent()
        assertNotNull(sessions.current.value)
        scope.advanceTimeBy(2)
        scope.runCurrent()
        assertNull(sessions.current.value)
    }

    @Test
    fun `returning within 60 seconds keeps the vault and cancels the timer`() = runTest {
        unlock()
        controller.onBackground()
        scope.advanceTimeBy(59_000)
        controller.onForeground()
        scope.advanceUntilIdle()
        assertNotNull(sessions.current.value)
    }

    @Test
    fun `a frozen process whose timer never ran locks on return`() = runTest {
        unlock()
        controller.onBackground()
        frozenFor = 61_000
        controller.onForeground()
        assertNull(sessions.current.value)
    }

    @Test
    fun `leaving again restarts the full 60 seconds`() = runTest {
        unlock()
        controller.onBackground()
        scope.advanceTimeBy(50_000)
        controller.onForeground()
        controller.onBackground()
        scope.advanceTimeBy(50_000)
        scope.runCurrent()
        assertNotNull(sessions.current.value)
        controller.onForeground()
        assertNotNull(sessions.current.value)
    }

    // Focus loss (another window in split screen or a desktop window) calls onBackground, and
    // onStop calls it again if the app then leaves the screen.
    @Test
    fun `focus lost for 61 seconds locks through the timer`() = runTest {
        unlock()
        controller.onBackground()
        scope.advanceTimeBy(61_000)
        scope.runCurrent()
        assertNull(sessions.current.value)
    }

    @Test
    fun `focus lost for 30 seconds and regained keeps the vault`() = runTest {
        unlock()
        controller.onBackground()
        scope.advanceTimeBy(30_000)
        controller.onForeground()
        scope.advanceTimeBy(120_000)
        scope.runCurrent()
        assertNotNull(sessions.current.value)
    }

    @Test
    fun `a stop after a focus loss measures from the focus loss`() = runTest {
        unlock()
        controller.onBackground()
        scope.advanceTimeBy(30_000)
        controller.onBackground()
        scope.advanceTimeBy(30_001)
        scope.runCurrent()
        assertNull("the timer counts from the focus loss", sessions.current.value)
    }

    @Test
    fun `a frozen process returning 61 seconds after the focus loss locks on start`() = runTest {
        unlock()
        controller.onBackground()
        frozenFor = 30_000
        controller.onBackground()
        frozenFor = 61_000
        controller.onForeground()
        assertNull(sessions.current.value)
    }

    @Test
    fun `regaining focus after the start checks nothing twice`() = runTest {
        unlock()
        controller.onBackground()
        controller.onBackground()
        frozenFor = 30_000
        controller.onForeground()
        assertNotNull(sessions.current.value)
        frozenFor = 200_000
        controller.onForeground()
        assertNotNull("the away period ended at the first return", sessions.current.value)
    }

    @Test
    fun `a stop after a focus loss with a picker open keeps the 2 minute allowance`() = runTest {
        unlock()
        controller.onPickerOpened()
        controller.onBackground()
        controller.onPickerClosed()
        controller.onBackground()
        scope.advanceTimeBy(LockController.TIMEOUT_MS + 1)
        scope.runCurrent()
        assertNotNull(sessions.current.value)
        scope.advanceTimeBy(LockController.PICKER_TIMEOUT_MS - LockController.TIMEOUT_MS)
        scope.runCurrent()
        assertNull(sessions.current.value)
    }

    @Test
    fun `screen off locks immediately, also during an unlock`() = runTest {
        unlock()
        controller.onScreenOff()
        assertNull(sessions.current.value)

        // No session yet: an unlock in progress compares lockCount and discards itself.
        val before = sessions.lockCount
        controller.onScreenOff()
        assertEquals(before + 1, sessions.lockCount)
    }

    private companion object {
        val vault: ByteArray by lazy { TestVaults.bytes() }
    }

    private val saver = org.onekash.kashpass.vault.testing.FakeVaultSaver()
    private val coordinator = org.onekash.kashpass.session.SaveCoordinator(sessions, saver, org.onekash.kashpass.vault.testing.FakeVaultOpener(), scope, compute = StandardTestDispatcher(scope.testScheduler))
    private val waiting = LockController(sessions, scope, ::elapsed, coordinator)

    private fun startSave() = coordinator.save(sessions.current.value!!.session.opened.document)

    @Test
    fun `a lock during a save waits for the save to end`() = runTest {
        unlock()
        saver.hold()
        startSave()
        scope.runCurrent()
        waiting.lock()
        scope.runCurrent()
        assertNotNull("still unlocked while the save runs", sessions.current.value)
        saver.release()
        scope.advanceUntilIdle()
        assertNull(sessions.current.value)
    }

    @Test
    fun `a lock waits at most 30 seconds, then cancels the save and locks`() = runTest {
        unlock()
        saver.hold()
        val pending = startSave()
        scope.runCurrent()
        waiting.onScreenOff()
        scope.advanceTimeBy(LockController.SAVE_WAIT_MS - 1)
        scope.runCurrent()
        assertNotNull(sessions.current.value)
        scope.advanceTimeBy(2)
        scope.runCurrent()
        assertNull(sessions.current.value)
        assertEquals(true, pending.isCancelled)
        assertNull(coordinator.lastProblem)
    }

    @Test
    fun `saves requested after a lock request are refused`() = runTest {
        unlock()
        saver.hold()
        startSave()
        scope.runCurrent()
        waiting.lock()
        val refused = startSave()
        scope.runCurrent()
        assertEquals(1, saver.calls.size)
        saver.release()
        scope.advanceUntilIdle()
        assertNull(refused.await())
        assertNull(sessions.current.value)
    }

    @Test
    fun `without a save running the lock is immediate`() = runTest {
        unlock()
        waiting.lock()
        assertNull(sessions.current.value)
    }

    @Test
    fun `a lock during a save covers the vault at once and uncovers after the lock`() = runTest {
        unlock()
        saver.hold()
        startSave()
        scope.runCurrent()
        waiting.lock()
        assertEquals(true, waiting.covering.value)
        assertNotNull(sessions.current.value)
        saver.release()
        scope.advanceUntilIdle()
        assertNull(sessions.current.value)
        assertEquals(false, waiting.covering.value)
        assertNull("a save that ended Saved loses nothing", waiting.lostChange.value)
    }

    @Test
    fun `a save that fails behind the cover is reported as not saved`() = runTest {
        unlock()
        saver.hold()
        saver.result = { vault, prepared -> org.onekash.kashpass.vault.save.SaveResult.WriteFailed(vault, prepared) }
        startSave()
        scope.runCurrent()
        waiting.lock()
        saver.release()
        scope.advanceUntilIdle()
        assertNull(sessions.current.value)
        assertEquals(LostChange.NOT_SAVED, waiting.lostChange.value)
        assertNull("nothing is kept across the lock", coordinator.lastProblem)
        waiting.acknowledgeLostChange()
        assertNull(waiting.lostChange.value)
    }

    @Test
    fun `the 30 second cap reports the change as maybe not saved`() = runTest {
        unlock()
        saver.hold()
        startSave()
        scope.runCurrent()
        waiting.lock()
        scope.advanceTimeBy(LockController.SAVE_WAIT_MS + 1)
        scope.runCurrent()
        assertNull(sessions.current.value)
        assertEquals(LostChange.MAYBE_NOT_SAVED, waiting.lostChange.value)
    }

    @Test
    fun `a failed save with its choices open at the lock is reported`() = runTest {
        unlock()
        saver.result = { vault, prepared -> org.onekash.kashpass.vault.save.SaveResult.WriteFailed(vault, prepared) }
        startSave()
        scope.advanceUntilIdle()
        assertNotNull(coordinator.lastProblem)
        waiting.lock()
        scope.advanceUntilIdle()
        assertNull(sessions.current.value)
        assertEquals(LostChange.NOT_SAVED, waiting.lostChange.value)
    }

    @Test
    fun `a save refused because a lock was coming is reported`() = runTest {
        unlock()
        saver.hold()
        startSave()
        scope.runCurrent()
        waiting.lock()
        startSave()
        saver.release()
        scope.advanceUntilIdle()
        assertEquals(LostChange.NOT_SAVED, waiting.lostChange.value)
    }

    @Test
    fun `a lock during recording of the saved result waits for it`() = runTest {
        // A compute dispatcher that holds the index rebuild until the test runs it.
        val held = ArrayDeque<Runnable>()
        val compute = object : kotlinx.coroutines.CoroutineDispatcher() {
            override fun dispatch(context: kotlin.coroutines.CoroutineContext, block: Runnable) {
                held += block
            }
        }
        val slow = org.onekash.kashpass.session.SaveCoordinator(sessions, saver, org.onekash.kashpass.vault.testing.FakeVaultOpener(), scope, compute = compute)
        val locker = LockController(sessions, scope, ::elapsed, slow)
        unlock()
        saver.result = { vault, prepared -> org.onekash.kashpass.vault.save.SaveResult.WriteFailed(vault, prepared) }
        slow.save(sessions.current.value!!.session.opened.document)
        scope.runCurrent()
        assertEquals("the saver returned", false, slow.isSaving.value)
        assertNull("the result isn't recorded yet", slow.lastProblem)
        locker.lock()
        assertEquals(true, locker.covering.value)
        assertNotNull(sessions.current.value)
        while (held.isNotEmpty()) held.removeFirst().run()
        scope.advanceUntilIdle()
        assertNull(sessions.current.value)
        assertEquals(LostChange.NOT_SAVED, locker.lostChange.value)
    }

    @Test
    fun `nothing pending means nothing lost`() = runTest {
        unlock()
        waiting.lock()
        assertNull(waiting.lostChange.value)
        assertEquals(false, waiting.covering.value)
    }

    @Test
    fun `a KashPass picker allows 2 minutes away instead of 1`() = runTest {
        unlock()
        controller.onPickerOpened()
        controller.onBackground()
        scope.advanceTimeBy(LockController.PICKER_TIMEOUT_MS - 1)
        scope.runCurrent()
        assertNotNull(sessions.current.value)
        scope.advanceTimeBy(2)
        scope.runCurrent()
        assertNull(sessions.current.value)
    }

    @Test
    fun `the picker allowance also holds for the elapsed check on return, and ends with the picker`() = runTest {
        unlock()
        controller.onPickerOpened()
        controller.onBackground()
        frozenFor = 90_000
        controller.onForeground()
        assertNotNull(sessions.current.value)
        controller.onPickerClosed()
        controller.onBackground()
        frozenFor += 61_000
        controller.onForeground()
        assertNull(sessions.current.value)
    }

    @Test
    fun `screen off locks at once while a picker is open, and every lock ends the allowance`() = runTest {
        unlock()
        controller.onPickerOpened()
        controller.onScreenOff()
        assertNull(sessions.current.value)
        unlock()
        controller.onBackground()
        scope.advanceTimeBy(LockController.TIMEOUT_MS + 1)
        scope.runCurrent()
        assertNull("the allowance ended with the lock", sessions.current.value)
    }

    @Test
    fun `a lock request clears the clipboard before waiting for the save, and once per lock`() = runTest {
        var clears = 0
        sessions.onLock = { clears++ }
        unlock()
        saver.hold()
        startSave()
        scope.runCurrent()
        waiting.lock()
        assertEquals(true, waiting.covering.value)
        assertEquals(1, clears)
        saver.release()
        scope.advanceUntilIdle()
        assertNull(sessions.current.value)
        assertEquals(1, clears)
        unlock()
        waiting.lock()
        assertEquals("a lock without a save clears once too", 2, clears)
    }

    @Test
    fun `after a lock the coordinator holds no save result, so no vault or key`() = runTest {
        unlock()
        saver.result = { vault, prepared -> org.onekash.kashpass.vault.save.SaveResult.WriteFailed(vault, prepared) }
        startSave()
        scope.advanceUntilIdle()
        waiting.lock()
        scope.advanceUntilIdle()
        assertNull(coordinator.settle(coordinator.runningSave()).result)
        assertNull(coordinator.lastProblem)
        assertEquals("no save or retry is still referenced", false, coordinator.holdsResult)
    }

    @Test
    fun `a lock waiting on a save that throws locks and reports the change as not saved`() = runTest {
        unlock()
        saver.hold()
        saver.result = { _, _ -> throw IllegalStateException("unexpected") }
        startSave()
        scope.runCurrent()
        waiting.lock()
        assertEquals(true, waiting.covering.value)
        saver.release()
        scope.advanceUntilIdle()
        assertNull(sessions.current.value)
        assertEquals(false, waiting.covering.value)
        assertEquals(LostChange.NOT_SAVED, waiting.lostChange.value)
        assertNull(coordinator.lastProblem)
    }

    @Test
    fun `a cleared failure is not reported by a later lock`() = runTest {
        unlock()
        saver.result = { vault, prepared -> org.onekash.kashpass.vault.save.SaveResult.WriteFailed(vault, prepared) }
        startSave()
        scope.advanceUntilIdle()
        // A copy (not a save) runs when the lock comes, and the failure is cleared before the lock.
        saver.hold()
        val copy = scope.async { coordinator.saveCopy("content://fake/copy") }
        scope.runCurrent()
        coordinator.clearProblem()
        waiting.lock()
        assertEquals(true, waiting.covering.value)
        saver.release()
        scope.advanceUntilIdle()
        copy.cancel()
        assertNull(sessions.current.value)
        assertNull(waiting.lostChange.value)
    }
}
