package org.onekash.kashpass.testing

import org.onekash.kashpass.platform.ClearAlarm

/**
 * Shared fake of [ClearAlarm]. It records each scheduled time in [scheduled], counts cancels in
 * [cancels] and holds the time of the alarm set in [pending] (null after a cancel); with
 * [failSchedule] set, [schedule] throws as AlarmManager does past its per-app alarm limit.
 */
class RecordingAlarm : ClearAlarm {
    val scheduled = mutableListOf<Long>()
    var cancels = 0
    var failSchedule = false
    var pending: Long? = null

    override fun schedule(atMillis: Long) {
        if (failSchedule) throw IllegalStateException("too many alarms")
        scheduled += atMillis
        pending = atMillis
    }

    override fun cancel() {
        cancels++
        pending = null
    }
}
