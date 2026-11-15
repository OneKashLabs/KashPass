package org.onekash.kashpass.lock

/**
 * Locks the vault when an exception reaches no handler, then passes the exception to [previous],
 * which on Android ends the process; [previous] runs also when [lock] throws. [lock] runs on the
 * crashing thread and must not log, block or write beyond what a lock writes (the clipboard
 * deadline clear). A coroutine launched in the app's scopes, which have no
 * CoroutineExceptionHandler, passes its uncaught exception to the thread's handler and so to this
 * one. [LockOnCrashTest] pins it.
 */
class LockOnCrash(
    internal val previous: Thread.UncaughtExceptionHandler?,
    internal val lock: () -> Unit,
) : Thread.UncaughtExceptionHandler {

    override fun uncaughtException(thread: Thread, error: Throwable) {
        try {
            lock()
        } finally {
            previous?.uncaughtException(thread, error)
        }
    }

    companion object {
        /**
         * Makes a [LockOnCrash] running [lock] the default handler, chained to the handler before
         * it; a second install replaces the first, so the chain holds one [LockOnCrash].
         */
        fun install(lock: () -> Unit) {
            val current = Thread.getDefaultUncaughtExceptionHandler()
            val previous = if (current is LockOnCrash) current.previous else current
            Thread.setDefaultUncaughtExceptionHandler(LockOnCrash(previous, lock))
        }
    }
}
