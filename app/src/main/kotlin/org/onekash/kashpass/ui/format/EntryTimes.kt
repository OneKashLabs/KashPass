package org.onekash.kashpass.ui.format

import android.content.res.Resources
import java.time.Duration
import java.time.Instant
import java.time.Period
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.time.temporal.ChronoUnit
import org.onekash.kashpass.R

/** Elapsed time, in the units the entry sheet, the read-only banner and the lock screen show. */
sealed interface Ago {
    data object JustNow : Ago
    data class Minutes(val count: Int) : Ago
    data class Hours(val count: Int) : Ago
    data object Yesterday : Ago
    data class Days(val count: Int) : Ago
    data class Weeks(val count: Int) : Ago
    data class Months(val count: Int) : Ago
}

/** Expiry state of an entry. [Soon.days] counts local calendar days: 0 today, 1 tomorrow. */
sealed interface Expiry {
    data object None : Expiry
    data class Expired(val at: Instant) : Expiry
    data class Soon(val at: Instant, val days: Int) : Expiry
    data class Later(val at: Instant) : Expiry
}

/**
 * Formats entry times for the screens. Days count on the phone's local calendar; under 24 hours
 * reads in hours, across midnight too. An expiry within [SOON_DAYS] is soon. [EntryTimesTest]
 * covers every boundary.
 */
object EntryTimes {

    const val SOON_DAYS = 7L

    /** Returns how long before [now] [time] was, or null beyond 11 months (show the date). */
    fun ago(time: Instant, now: Instant, zone: ZoneId): Ago? {
        val elapsed = Duration.between(time, now)
        if (elapsed.seconds < 60) return Ago.JustNow
        if (elapsed.toMinutes() < 60) return Ago.Minutes(elapsed.toMinutes().toInt())
        if (elapsed.toHours() < 24) return Ago.Hours(elapsed.toHours().toInt())
        val then = time.atZone(zone).toLocalDate()
        val today = now.atZone(zone).toLocalDate()
        val days = ChronoUnit.DAYS.between(then, today)
        return when {
            // A 25-hour day at a clock change: 24 hours or more ago on the same local date.
            days == 0L -> Ago.Hours(elapsed.toHours().toInt())
            days == 1L -> Ago.Yesterday
            days < 7 -> Ago.Days(days.toInt())
            days < 35 -> Ago.Weeks((days / 7).toInt())
            else -> Period.between(then, today).toTotalMonths().takeIf { it < 12 }?.let { Ago.Months(it.coerceAtLeast(1).toInt()) }
        }
    }

    /** Returns true when [expiry] is at or before [now]; a null [expiry] never expires. */
    fun isExpired(expiry: Instant?, now: Instant): Boolean = expiry != null && !expiry.isAfter(now)

    /** Returns the state of [expiry] at [now]; a null [expiry] means the entry doesn't expire. */
    fun expiry(expiry: Instant?, now: Instant, zone: ZoneId): Expiry = when {
        expiry == null -> Expiry.None
        isExpired(expiry, now) -> Expiry.Expired(expiry)
        Duration.between(now, expiry) < Duration.ofDays(SOON_DAYS) ->
            Expiry.Soon(expiry, ChronoUnit.DAYS.between(now.atZone(zone).toLocalDate(), expiry.atZone(zone).toLocalDate()).toInt())
        else -> Expiry.Later(expiry)
    }

    /** Returns [ago] as a lowercase phrase that fits inside a sentence ("3 days ago"). */
    fun phrase(resources: Resources, ago: Ago): String = when (ago) {
        Ago.JustNow -> resources.getString(R.string.ago_just_now)
        is Ago.Minutes -> resources.getQuantityString(R.plurals.ago_minutes, ago.count, ago.count)
        is Ago.Hours -> resources.getQuantityString(R.plurals.ago_hours, ago.count, ago.count)
        Ago.Yesterday -> resources.getString(R.string.ago_yesterday)
        is Ago.Days -> resources.getQuantityString(R.plurals.ago_days, ago.count, ago.count)
        is Ago.Weeks -> resources.getQuantityString(R.plurals.ago_weeks, ago.count, ago.count)
        is Ago.Months -> resources.getQuantityString(R.plurals.ago_months, ago.count, ago.count)
    }

    /** Returns how long before [now] [time] was as a phrase, or the date beyond 11 months. */
    fun past(resources: Resources, time: Instant, now: Instant, zone: ZoneId): String =
        ago(time, now, zone)?.let { phrase(resources, it) } ?: date(time, zone)

    /** Returns a medium local date, as "Oct 21, 2026". */
    fun date(instant: Instant, zone: ZoneId): String =
        DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withZone(zone).format(instant)

    /** Returns [time] for the sheet's footer: a phrase within a week, else the date. */
    fun footer(resources: Resources, time: Instant, now: Instant, zone: ZoneId): String =
        when (val ago = ago(time, now, zone)) {
            null, is Ago.Weeks, is Ago.Months -> date(time, zone)
            else -> phrase(resources, ago)
        }

    /** Returns the line for [expiry] ("Expires tomorrow · Oct 22, 2026"), or null for none. */
    fun expiryLine(resources: Resources, expiry: Expiry, now: Instant, zone: ZoneId): String? = when (expiry) {
        Expiry.None -> null
        is Expiry.Expired -> ago(expiry.at, now, zone)
            ?.let { resources.getString(R.string.entry_expired, phrase(resources, it), date(expiry.at, zone)) }
            ?: resources.getString(R.string.entry_expired_on, date(expiry.at, zone))
        is Expiry.Soon -> when (expiry.days) {
            0 -> resources.getString(R.string.entry_expires_today, date(expiry.at, zone))
            1 -> resources.getString(R.string.entry_expires_tomorrow, date(expiry.at, zone))
            else -> resources.getQuantityString(R.plurals.entry_expires_in, expiry.days, expiry.days, date(expiry.at, zone))
        }
        is Expiry.Later -> resources.getString(R.string.entry_expires_later, date(expiry.at, zone))
    }
}
