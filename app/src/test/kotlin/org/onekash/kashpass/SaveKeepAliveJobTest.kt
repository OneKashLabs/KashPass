package org.onekash.kashpass

import android.app.job.JobScheduler
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class SaveKeepAliveJobTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val scheduler = context.getSystemService(JobScheduler::class.java)

    @Test
    fun `leaving the app during a save schedules one expedited job`() {
        assertTrue(SaveKeepAlive.scheduleIfBusy(context, busy = true))
        val job = scheduler.allPendingJobs.single()
        assertEquals(SaveKeepAlive.JOB_ID, job.id)
        assertTrue(job.isExpedited)
        assertEquals(SaveKeepAliveJob::class.java.name, job.service.className)
    }

    @Test
    fun `leaving the app with no save running schedules nothing`() {
        assertFalse(SaveKeepAlive.scheduleIfBusy(context, busy = false))
        assertEquals(emptyList<Any>(), scheduler.allPendingJobs)
    }

    @Test
    fun `a refused job is not an error`() {
        shadowOf(scheduler).failOnJob(SaveKeepAlive.JOB_ID)
        assertFalse(SaveKeepAlive.scheduleIfBusy(context, busy = true))
    }

    @Test
    fun `the job ends when the save ends`() = runBlocking {
        val saving = MutableStateFlow(true)
        val waiting = async { SaveKeepAlive.awaitIdle(saving) }
        yield()
        assertFalse(waiting.isCompleted)
        saving.value = false
        waiting.await()
        assertTrue(waiting.isCompleted)
    }
}
