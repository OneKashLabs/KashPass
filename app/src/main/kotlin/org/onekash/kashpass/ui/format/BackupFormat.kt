package org.onekash.kashpass.ui.format

import android.content.Context
import android.text.format.Formatter
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/** Formats dates and file sizes as the screens show them. */
object BackupFormat {

    /** Returns a medium date with a short time in the phone's zone, as "Oct 20, 2026, 9:05 AM". */
    fun dateTime(instant: Instant, zone: ZoneId = ZoneId.systemDefault()): String =
        DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT).withZone(zone).format(instant)

    /** Returns a short file size, as "1.9 kB". */
    fun size(context: Context, bytes: Long): String = Formatter.formatShortFileSize(context, bytes)
}
