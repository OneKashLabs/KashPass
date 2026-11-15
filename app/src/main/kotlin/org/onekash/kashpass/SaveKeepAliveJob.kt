package org.onekash.kashpass

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Keeps the process running, as an expedited job, while a save job (a save, retry, copy, or the
 * staged deletes committed on leaving the foreground) finishes after the app leaves the
 * foreground. The save runs in the app's scope; the job only marks the process busy, so the system
 * doesn't freeze it as a cached app. Expedited jobs need no uses-permission or notification
 * (Android developer guide, "Define work requests", expedited work). The system can decline to run
 * it; the pending-save marker covers that case. [SaveKeepAliveJobTest] pins scheduling and
 * finishing.
 */
class SaveKeepAliveJob : JobService() {

    private var waiting: Job? = null

    // Returns at once: onStartJob runs on the main thread and must not block (Android 14 ANR
    // rules).
    override fun onStartJob(params: JobParameters): Boolean {
        val graph = applicationContext.graph
        val busy = graph.saves.busy
        if (!busy.value) return false
        waiting = graph.appScope.launch {
            SaveKeepAlive.awaitIdle(busy)
            jobFinished(params, false)
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        waiting?.cancel()
        waiting = null
        return false
    }
}

/** Schedules [SaveKeepAliveJob] when the app leaves the foreground while a save job runs. */
object SaveKeepAlive {

    const val JOB_ID = 4_201

    /**
     * Schedules the expedited job when [busy]; returns true when the system accepted it. A
     * refusal (quota, a scheduler error) is not a failure: the save goes on, and the marker
     * covers a process the system stops.
     */
    fun scheduleIfBusy(context: Context, busy: Boolean): Boolean {
        if (!busy) return false
        val info = JobInfo.Builder(JOB_ID, ComponentName(context, SaveKeepAliveJob::class.java))
            .setExpedited(true)
            .build()
        return try {
            context.getSystemService(JobScheduler::class.java).schedule(info) == JobScheduler.RESULT_SUCCESS
        } catch (e: RuntimeException) {
            false
        }
    }

    /** Suspends until [busy] turns false. */
    suspend fun awaitIdle(busy: StateFlow<Boolean>) {
        busy.first { !it }
    }
}
