package org.onekash.kashpass.lock

import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.checkAll
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.session.LostChange
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.open.VaultSession
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

/**
 * Random sequences of unlock, background, foreground, picker, screen off, lock, time passing, a
 * frozen process and held saves against [LockController] with a [SaveCoordinator] over
 * [FakeVaultSaver], on virtual time. A model of the lock rules predicts after each event whether
 * the vault is unlocked, whether the lock covers it, the problem and the lost change; when locked,
 * no session remains open.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class LockControllerProperties {

    @Test
    fun `the vault locks exactly when the lock rules say`() = runBlocking<Unit> {
        val counts = sortedMapOf<String, Int>()
        checkAll(PropertyRuns.config(iterations = 1_000), EVENTS) { events ->
            Rig(counts).use { rig -> events.forEach { rig.apply(it) } }
        }
        val missing = COVERAGE.filter { (counts[it] ?: 0) == 0 }
        assertTrue("never reached: $missing (reached: $counts)", missing.isEmpty())
    }

    sealed interface Event {
        data object Unlock : Event
        data object Background : Event
        data object Foreground : Event
        data object PickerOpened : Event
        data object PickerClosed : Event
        data object ScreenOff : Event
        data object Lock : Event
        data class Time(val ms: Long) : Event
        data class Freeze(val ms: Long) : Event
        data object Save : Event
        data class Release(val outcome: Outcome) : Event
    }

    enum class Outcome { SAVED, WRITE_FAILED, MAYBE_DAMAGED, THROWS, ERROR }

    private class Away(val start: Long, val allowance: Long, val picker: Boolean)

    private class Rig(private val counts: MutableMap<String, Int>) : AutoCloseable {
        private val scope = TestScope(StandardTestDispatcher())
        private var frozen = 0L
        private val sessions = SessionHolder()
        private val saver = FakeVaultSaver()
        // A supervisor, as the app's scope is, so a save job that fails with an Error ends that job
        // only.
        private val saves = CoroutineScope(scope.coroutineContext + SupervisorJob(scope.coroutineContext[Job]))
        private val coordinator = SaveCoordinator(sessions, saver, FakeVaultOpener(), saves, compute = StandardTestDispatcher(scope.testScheduler))
        private val controller = LockController(sessions, scope, { scope.testScheduler.currentTime + frozen }, coordinator)
        private var held = false
        private val opened = mutableListOf<VaultSession>()

        // The model.
        private var now = 0L
        private var unlocked = false
        private var covering = false
        private var away: Away? = null
        private var picker = false
        private var timerAt: Long? = null
        private var lockDeadline: Long? = null
        // Saves not yet ended, in start order; true for one refused because a lock was coming.
        private val running = mutableListOf<Boolean>()
        private var problem = false
        private var refusedForLock = false
        private var lost: LostChange? = null
        // How the awaited lock started, for the coverage counts.
        private var lockCause = ""

        init {
            unlockNow()
        }

        private fun elapsed() = now + frozen

        fun apply(event: Event) {
            when (event) {
                Event.Unlock -> if (!unlocked && !covering && away == null) {
                    unlockNow()
                    count("unlocked again")
                }
                Event.Background -> {
                    controller.onBackground()
                    if (away == null) {
                        val allowance = if (picker) LockController.PICKER_TIMEOUT_MS else LockController.TIMEOUT_MS
                        away = Away(elapsed(), allowance, picker)
                        timerAt = now + allowance
                    } else {
                        count("second background keeps the first start")
                    }
                }
                Event.Foreground -> {
                    controller.onForeground()
                    timerAt = null
                    away?.let { a ->
                        away = null
                        if (elapsed() - a.start >= a.allowance) {
                            lock(if (a.picker) "return after the picker allowance" else "return after the allowance")
                        } else if (unlocked) {
                            count("return before the allowance keeps the vault")
                        }
                    }
                }
                Event.PickerOpened -> {
                    controller.onPickerOpened()
                    picker = true
                }
                Event.PickerClosed -> {
                    controller.onPickerClosed()
                    picker = false
                }
                Event.ScreenOff -> {
                    controller.onScreenOff()
                    lock("screen off")
                }
                Event.Lock -> {
                    controller.lock()
                    lock("explicit lock")
                }
                is Event.Time -> time(event.ms)
                is Event.Freeze -> {
                    frozen += event.ms
                    count("frozen")
                }
                Event.Save -> if (unlocked) {
                    if (!held) {
                        saver.hold()
                        held = true
                    }
                    coordinator.save(sessions.current.value!!.session.opened.document)
                    running += covering
                    if (covering) count("save asked for during a lock")
                }
                is Event.Release -> {
                    saver.result = when (event.outcome) {
                        Outcome.SAVED -> DEFAULT_RESULT
                        Outcome.WRITE_FAILED -> { vault, prepared -> SaveResult.WriteFailed(vault, prepared) }
                        Outcome.MAYBE_DAMAGED -> { vault, prepared -> SaveResult.MaybeDamaged(vault.withBaseline(OpenedVault.Baseline.Unknown), prepared) }
                        Outcome.THROWS -> { _, _ -> throw IllegalStateException("provider") }
                        // Not an Exception, so the coordinator doesn't turn it into a result: the
                        // job fails and records nothing.
                        Outcome.ERROR -> { _, _ -> throw AssertionError("provider") }
                    }
                    saver.release()
                    held = false
                    if (running.isNotEmpty()) {
                        // The awaited save is the newest one started before the lock.
                        val failed = event.outcome == Outcome.ERROR && running.any { !it }
                        for (refused in running) {
                            if (refused) refusedForLock = true else if (event.outcome != Outcome.ERROR) problem = event.outcome != Outcome.SAVED
                        }
                        running.clear()
                        if (covering) {
                            count("covered lock ended with the save")
                            when {
                                refusedForLock -> count("not saved: refused")
                                failed -> count("not saved: ERROR")
                                problem -> count("not saved: ${event.outcome}")
                            }
                            finish(if (refusedForLock || failed || problem) LostChange.NOT_SAVED else null)
                        }
                    }
                }
            }
            scope.runCurrent()
            check()
        }

        // The controller's lock(): an immediate lock with no save running, otherwise a cover that
        // waits for the saves or SAVE_WAIT_MS.
        private fun lock(cause: String) {
            timerAt = null
            picker = false
            if (running.isEmpty()) {
                if (unlocked) count(cause)
                if (problem) count("not saved: problem pending")
                finish(if (problem) LostChange.NOT_SAVED else null)
                return
            }
            if (covering) return
            covering = true
            refusedForLock = false
            lockDeadline = now + LockController.SAVE_WAIT_MS
            lockCause = cause
            count("covered: $cause")
        }

        private fun finish(lostChange: LostChange?) {
            lockDeadline = null
            covering = false
            unlocked = false
            problem = false
            running.clear()
            if (lostChange != null) lost = lostChange
        }

        private fun time(ms: Long) {
            val target = now + ms
            while (true) {
                val timer = timerAt?.takeIf { it <= target }
                val deadline = lockDeadline?.takeIf { it <= target }
                val next = listOfNotNull(timer, deadline).minOrNull() ?: break
                scope.advanceTimeBy(next - now)
                scope.runCurrent()
                now = next
                if (next == deadline) {
                    count("lock after SAVE_WAIT_MS ($lockCause)")
                    finish(LostChange.MAYBE_NOT_SAVED)
                } else {
                    timerAt = null
                    lock(if (away?.picker == true) "timer after the picker allowance" else "timer")
                }
                check()
            }
            scope.advanceTimeBy(target - now)
            now = target
        }

        private fun check() {
            assertEquals("unlocked", unlocked, sessions.current.value != null)
            assertEquals("covering", covering, controller.covering.value)
            assertEquals("lost change", lost, controller.lostChange.value)
            if (!covering) assertEquals("problem", problem, coordinator.lastProblem != null)
            if (unlocked) {
                // Every session shown, including those a save result swapped in.
                sessions.current.value?.session?.let { if (opened.none { o -> o === it }) opened += it }
            } else {
                assertFalse("no session stays open", opened.any { it.isOpen })
            }
        }

        private fun unlockNow() {
            val result = runBlocking { TestVaults.unlock(VAULT) }
            opened += result.session
            sessions.set(Unlocked(TestVaults.LOCATION, result.session, result.kdf, result.showWeakWarning))
            controller.acknowledgeLostChange()
            unlocked = true
            lost = null
        }

        private fun count(name: String) {
            counts[name] = (counts[name] ?: 0) + 1
        }

        override fun close() {
            scope.cancel()
        }
    }

    private companion object {
        val VAULT: ByteArray by lazy { TestVaults.bytes(aesRounds = 1_000UL) }

        val DEFAULT_RESULT = FakeVaultSaver().result

        val TIMES = listOf(1_000L, 29_999L, 30_000L, 30_001L, 59_999L, 60_000L, 60_001L, 119_999L, 120_000L, 120_001L, 200_000L)

        val EVENTS: Arb<List<Event>> = Arb.list(Arb.bind(Arb.int(0..94), Arb.int(0..1_000)) { k, p -> event(k, p) }, 1..30)

        fun event(k: Int, p: Int): Event = when {
            k < 8 -> Event.Unlock
            k < 20 -> Event.Background
            k < 32 -> Event.Foreground
            k < 37 -> Event.PickerOpened
            k < 41 -> Event.PickerClosed
            k < 46 -> Event.ScreenOff
            k < 50 -> Event.Lock
            k < 64 -> Event.Time(TIMES[p % TIMES.size])
            k < 70 -> Event.Freeze(TIMES[p % TIMES.size])
            k < 83 -> Event.Save
            else -> Event.Release(Outcome.entries[p % Outcome.entries.size])
        }

        val COVERAGE = listOf(
            "timer", "timer after the picker allowance", "return after the allowance", "return after the picker allowance",
            "return before the allowance keeps the vault", "second background keeps the first start", "screen off", "explicit lock",
            "covered: screen off", "covered: explicit lock", "covered: timer", "covered lock ended with the save",
            "lock after SAVE_WAIT_MS (screen off)", "save asked for during a lock", "not saved: refused", "not saved: WRITE_FAILED",
            "not saved: THROWS", "not saved: MAYBE_DAMAGED", "not saved: ERROR", "not saved: problem pending", "unlocked again", "frozen",
        )
    }
}
