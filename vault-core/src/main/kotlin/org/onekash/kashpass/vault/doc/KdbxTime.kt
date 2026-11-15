package org.onekash.kashpass.vault.doc

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.time.format.DateTimeParseException
import java.util.Base64

/**
 * KDBX times. A KDBX 4 file stores seconds since 0001-01-01T00:00:00Z as a little-endian 64-bit
 * integer in Base64, and a KDBX 4 read accepts only that form ([readKdbx4]); ISO 8601 text is the
 * KDBX 3 and unencrypted-XML form. [parse] reads either form for display. KashPass writes only
 * the KDBX 4 form.
 */
object KdbxTime {

    // Seconds from 0001-01-01T00:00:00Z to 1970-01-01T00:00:00Z.
    private const val EPOCH_OFFSET = 62_135_596_800L

    // 9999-12-31T23:59:59Z, the latest KDBX date (.NET DateTime.MaxValue), in KDBX 4 seconds.
    private const val MAX_SECONDS = 315_537_897_599L

    /** Parses either form; null when [text] is neither. */
    fun parse(text: String): Instant? {
        val trimmed = text.trim()
        if (trimmed.contains('-')) {
            return try {
                Instant.parse(trimmed)
            } catch (e: DateTimeParseException) {
                null
            }
        }
        val bytes = try {
            Base64.getDecoder().decode(trimmed)
        } catch (e: IllegalArgumentException) {
            return null
        }
        if (bytes.size != 8) return null
        val seconds = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).long
        // A count past 9999-12-31T23:59:59Z is no .NET DateTime, and Instant can't hold every
        // 64-bit count; such a time, or a negative one, is unreadable.
        if (seconds < 0 || seconds > MAX_SECONDS) return null
        return Instant.ofEpochSecond(seconds - EPOCH_OFFSET)
    }

    // DateTime.MaxValue.Ticks: 9999-12-31T23:59:59.9999999Z in 100 ns ticks since 0001-01-01.
    private const val MAX_TICKS = 3_155_378_975_999_999_999L
    private const val TICKS_PER_SECOND = 10_000_000L

    /**
     * Reads a KDBX 4 time: [text] is Base64 ([ConvertBase64]); an empty value is 0001-01-01; fewer
     * than 8 bytes are zero-padded and more are cut to 8; the seconds times 10^7 (wrapping on
     * overflow, as C#'s unchecked multiply does) must be a .NET DateTime's ticks. Returns null,
     * which fails the open, for text that is not Base64, an ISO date included, or ticks outside
     * 0..DateTime.MaxValue.
     */
    fun readKdbx4(text: String): Instant? {
        val bytes = ConvertBase64.decode(text) ?: return null
        val eight = bytes.copyOf(8)
        val seconds = ByteBuffer.wrap(eight).order(ByteOrder.LITTLE_ENDIAN).long
        val ticks = seconds * TICKS_PER_SECOND
        if (ticks < 0 || ticks > MAX_TICKS) return null
        return Instant.ofEpochSecond(ticks / TICKS_PER_SECOND - EPOCH_OFFSET, (ticks % TICKS_PER_SECOND) * 100)
    }

    /** Formats [instant] as KDBX 4 base64 seconds, dropping fractions. */
    fun format(instant: Instant): String {
        val seconds = instant.epochSecond + EPOCH_OFFSET
        val bytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(seconds).array()
        return Base64.getEncoder().encodeToString(bytes)
    }
}
