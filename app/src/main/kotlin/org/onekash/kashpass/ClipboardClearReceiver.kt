package org.onekash.kashpass

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.onekash.kashpass.platform.AlarmClearAlarm

/** Clears the clipboard when [AlarmClearAlarm] fires and the deadline has passed. */
class ClipboardClearReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = context.graph.clipboard.clearIfDue()
}
