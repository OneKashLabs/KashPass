package org.onekash.kashpass.vault.doc

import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.jupiter.api.Test

class KdbxTimeTest {

    @Test
    fun `KDBX 4 times are little-endian seconds since year 1 in base64`() {
        assertEquals("AAAAAAAAAAA=", KdbxTime.format(Instant.parse("0001-01-01T00:00:00Z")))
        // 62135596800 = 0x0E7791F700, little-endian.
        assertEquals("APeRdw4AAAA=", KdbxTime.format(Instant.EPOCH))
        assertEquals(Instant.EPOCH, KdbxTime.parse("APeRdw4AAAA="))
    }

    @Test
    fun `formatting drops fractions and round-trips`() {
        val now = Instant.parse("2026-10-20T13:45:07.987Z")
        assertEquals(Instant.parse("2026-10-20T13:45:07Z"), KdbxTime.parse(KdbxTime.format(now)))
    }

    @Test
    fun `ISO 8601 times are read`() {
        assertEquals(Instant.parse("2019-05-01T10:00:00Z"), KdbxTime.parse("2019-05-01T10:00:00Z"))
    }

    @Test
    fun `a count Instant can't hold is unreadable, not a crash`() {
        val huge = java.util.Base64.getEncoder().encodeToString(java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(Long.MAX_VALUE).array())
        val negative = java.util.Base64.getEncoder().encodeToString(java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(-1).array())
        assertNull(KdbxTime.parse(huge))
        assertNull(KdbxTime.parse(negative))
        assertEquals(Instant.parse("9999-12-31T23:59:59Z"), KdbxTime.parse(KdbxTime.format(Instant.parse("9999-12-31T23:59:59Z"))))
    }

    @Test
    fun `anything else is null`() {
        for (text in listOf("", "not a time", "AAAA", "2019-13-45T99:00:00Z")) assertNull(KdbxTime.parse(text), text)
    }

    private fun b64(seconds: Long) = java.util.Base64.getEncoder().encodeToString(java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(seconds).array())

    @Test
    fun `KDBX 4 times read as KeePass 2 reads them`() {
        val start = java.time.Instant.parse("0001-01-01T00:00:00Z")
        assertEquals(start, KdbxTime.readKdbx4(""))
        assertEquals(java.time.Instant.parse("2026-10-25T00:00:00Z"), KdbxTime.readKdbx4(KdbxTime.format(java.time.Instant.parse("2026-10-25T00:00:00Z"))))
        // Short values are zero-padded, long ones cut to 8 bytes.
        assertEquals(start.plusSeconds(1), KdbxTime.readKdbx4("AQ=="))
        assertEquals(start.plusSeconds(2), KdbxTime.readKdbx4(java.util.Base64.getEncoder().encodeToString(byteArrayOf(2, 0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9))))
        assertEquals(java.time.Instant.parse("9999-12-31T23:59:59Z"), KdbxTime.readKdbx4(b64(315_537_897_599L)))
    }

    @Test
    fun `KDBX 4 times KeePass 2 refuses read as null`() {
        assertNull(KdbxTime.readKdbx4("2026-10-25T12:00:00Z"))
        assertNull(KdbxTime.readKdbx4("not*base64"))
        assertNull(KdbxTime.readKdbx4(b64(-1L)))
        assertNull(KdbxTime.readKdbx4(b64(315_537_897_600L)))
    }

    @Test
    fun `KDBX 4 seconds wrap as dot NET's unchecked multiply does`() {
        // 1,844,674,407,371 x 10^7 passes 2^64 by 448,384: C# reads 448,384 ticks after 0001-01-01.
        assertEquals(Instant.ofEpochSecond(-62_135_596_800L, 44_838_400L), KdbxTime.readKdbx4(b64(1_844_674_407_371L)))
        // One second less wraps to a negative tick count, which DateTime refuses.
        assertNull(KdbxTime.readKdbx4(b64(1_844_674_407_370L)))
    }
}
