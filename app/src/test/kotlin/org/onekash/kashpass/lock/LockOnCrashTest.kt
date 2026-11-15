package org.onekash.kashpass.lock

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.testing.TestVaults

class LockOnCrashTest {

    private val error = IllegalStateException("crash")

    @Test
    fun `an uncaught exception locks the session, then reaches the previous handler`() = runBlocking<Unit> {
        val sessions = SessionHolder()
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        val reached = mutableListOf<Throwable>()
        var lockedFirst = false
        val handler = LockOnCrash({ _, e ->
            lockedFirst = sessions.current.value == null
            reached += e
        }, sessions::lock)
        handler.uncaughtException(Thread.currentThread(), error)
        assertNull(sessions.current.value)
        assertFalse(opened.session.isOpen)
        assertTrue("the vault is locked before the previous handler ends the process", lockedFirst)
        assertEquals(listOf<Throwable>(error), reached)
    }

    @Test
    fun `a lock that throws reaches the previous handler`() {
        val reached = mutableListOf<Throwable>()
        val handler = LockOnCrash({ _, e -> reached += e }) { throw IllegalStateException("lock") }
        runCatching { handler.uncaughtException(Thread.currentThread(), error) }
        assertEquals(listOf<Throwable>(error), reached)
    }

    @Test
    fun `install chains to the handler before it and replaces an earlier install`() {
        val before = Thread.getDefaultUncaughtExceptionHandler()
        try {
            val first = Thread.UncaughtExceptionHandler { _, _ -> }
            Thread.setDefaultUncaughtExceptionHandler(first)
            LockOnCrash.install {}
            LockOnCrash.install {}
            val installed = Thread.getDefaultUncaughtExceptionHandler() as LockOnCrash
            assertSame(first, installed.previous)
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(before)
        }
    }
}
