package org.onekash.kashpass.ui.format

import androidx.test.core.app.ApplicationProvider
import java.time.Duration
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class EntryTimesTest {

    private val utc = ZoneOffset.UTC
    private val la = ZoneId.of("America/Los_Angeles")
    private val resources = ApplicationProvider.getApplicationContext<android.content.Context>().resources

    private fun at(text: String, zone: ZoneId): Instant = LocalDateTime.parse(text).atZone(zone).toInstant()

    private fun ago(time: Instant, now: Instant, zone: ZoneId) = EntryTimes.ago(time, now, zone)

    @Test
    fun `past times step from minutes to months on the local calendar`() {
        for (zone in listOf(utc, la)) {
            val now = at("2026-10-21T23:00:00", zone)
            assertEquals(Ago.JustNow, ago(now.minusSeconds(59), now, zone))
            assertEquals(Ago.Minutes(1), ago(now.minusSeconds(60), now, zone))
            assertEquals(Ago.Minutes(59), ago(now.minus(Duration.ofMinutes(59)), now, zone))
            assertEquals(Ago.Hours(1), ago(now.minus(Duration.ofMinutes(60)), now, zone))
            assertEquals(Ago.Hours(22), ago(at("2026-10-21T01:00:00", zone), now, zone))
            // The previous local day, under 24 hours ago, reads in hours.
            val late = at("2026-10-21T08:00:00", zone)
            assertEquals(Ago.Hours(20), ago(at("2026-10-20T12:00:00", zone), late, zone))
            assertEquals(Ago.Yesterday, ago(at("2026-10-20T22:00:00", zone), now, zone))
            assertEquals(Ago.Days(2), ago(at("2026-10-19T23:30:00", zone), now, zone))
            assertEquals(Ago.Days(6), ago(at("2026-10-15T08:00:00", zone), now, zone))
            assertEquals(Ago.Weeks(1), ago(at("2026-10-14T08:00:00", zone), now, zone))
            assertEquals(Ago.Weeks(4), ago(at("2026-09-17T08:00:00", zone), now, zone))
            assertEquals(Ago.Months(1), ago(at("2026-09-16T08:00:00", zone), now, zone))
            assertEquals(Ago.Months(11), ago(at("2025-10-22T08:00:00", zone), now, zone))
            assertNull(ago(at("2025-10-21T08:00:00", zone), now, zone))
            // A time ahead of this phone's clock reads as now, not in the future.
            assertEquals(Ago.JustNow, ago(now.plusSeconds(300), now, zone))
        }
    }

    @Test
    fun `on a 25-hour day an earlier time of the same date reads in hours, not yesterday`() {
        // America/Los_Angeles falls back on 2026-11-01.
        val time = at("2026-11-01T00:10:00", la)
        val now = at("2026-11-01T23:30:00", la)
        assertEquals(Ago.Hours(24), ago(time, now, la))
    }

    @Test
    fun `yesterday starts at local midnight, not 24 hours ago`() {
        val now = at("2026-10-21T00:30:00", la)
        assertEquals(Ago.Hours(1), ago(at("2026-10-20T23:30:00", la), now, la))
        // The same instant read in UTC is on the same day.
        assertEquals(Ago.Hours(1), ago(at("2026-10-20T23:30:00", la), now, utc))
    }

    @Test
    fun `expiry is none, expired at or before now, soon within 7 days, later after`() {
        val zone = la
        val now = at("2026-10-21T10:00:00", zone)
        assertEquals(Expiry.None, EntryTimes.expiry(null, now, zone))
        assertEquals(Expiry.Expired(now), EntryTimes.expiry(now, now, zone))
        val past = at("2026-10-01T00:00:00", zone)
        assertEquals(Expiry.Expired(past), EntryTimes.expiry(past, now, zone))
        val tonight = at("2026-10-21T23:00:00", zone)
        assertEquals(Expiry.Soon(tonight, 0), EntryTimes.expiry(tonight, now, zone))
        val tomorrow = at("2026-10-22T09:00:00", zone)
        assertEquals(Expiry.Soon(tomorrow, 1), EntryTimes.expiry(tomorrow, now, zone))
        val sixDays = at("2026-10-27T09:00:00", zone)
        assertEquals(Expiry.Soon(sixDays, 6), EntryTimes.expiry(sixDays, now, zone))
        val sevenDays = now.plus(Duration.ofDays(7))
        assertEquals(Expiry.Later(sevenDays), EntryTimes.expiry(sevenDays, now, zone))
    }

    @Test
    fun `phrases embed in a sentence and plurals come from resources`() {
        assertEquals("just now", EntryTimes.phrase(resources, Ago.JustNow))
        assertEquals("1 minute ago", EntryTimes.phrase(resources, Ago.Minutes(1)))
        assertEquals("5 minutes ago", EntryTimes.phrase(resources, Ago.Minutes(5)))
        assertEquals("1 hour ago", EntryTimes.phrase(resources, Ago.Hours(1)))
        assertEquals("yesterday", EntryTimes.phrase(resources, Ago.Yesterday))
        assertEquals("3 days ago", EntryTimes.phrase(resources, Ago.Days(3)))
        assertEquals("3 weeks ago", EntryTimes.phrase(resources, Ago.Weeks(3)))
        assertEquals("1 month ago", EntryTimes.phrase(resources, Ago.Months(1)))
    }

    @Test
    fun `the footer uses a phrase within a week, then the date`() {
        val zone = utc
        val now = at("2026-10-21T12:00:00", zone)
        assertEquals("just now", EntryTimes.footer(resources, now, now, zone))
        assertEquals("3 days ago", EntryTimes.footer(resources, at("2026-10-18T12:00:00", zone), now, zone))
        assertEquals(EntryTimes.date(at("2024-03-12T09:30:00", zone), zone), EntryTimes.footer(resources, at("2024-03-12T09:30:00", zone), now, zone))
        assertEquals(EntryTimes.date(at("2026-10-13T12:00:00", zone), zone), EntryTimes.footer(resources, at("2026-10-13T12:00:00", zone), now, zone))
    }

    @Test
    fun `expiry lines give the time passed or left, then the date`() {
        val zone = utc
        val now = at("2026-10-21T12:00:00", zone)
        val past = at("2026-10-01T00:00:00", zone)
        val date = EntryTimes.date(past, zone)
        assertEquals("Expired 2 weeks ago · $date", EntryTimes.expiryLine(resources, Expiry.Expired(past), now, zone))
        val old = at("2024-01-01T00:00:00", zone)
        assertEquals("Expired on ${EntryTimes.date(old, zone)}", EntryTimes.expiryLine(resources, Expiry.Expired(old), now, zone))
        val today = at("2026-10-21T20:00:00", zone)
        assertEquals("Expires today · ${EntryTimes.date(today, zone)}", EntryTimes.expiryLine(resources, Expiry.Soon(today, 0), now, zone))
        assertEquals("Expires tomorrow · ${EntryTimes.date(today, zone)}", EntryTimes.expiryLine(resources, Expiry.Soon(today, 1), now, zone))
        assertEquals("Expires in 5 days · ${EntryTimes.date(today, zone)}", EntryTimes.expiryLine(resources, Expiry.Soon(today, 5), now, zone))
        assertEquals("Expires ${EntryTimes.date(today, zone)}", EntryTimes.expiryLine(resources, Expiry.Later(today), now, zone))
        assertNull(EntryTimes.expiryLine(resources, Expiry.None, now, zone))
    }
}
