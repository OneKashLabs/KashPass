package org.onekash.kashpass.vault.kdbx

import java.util.zip.Adler32
import java.util.zip.CRC32
import java.util.zip.Checksum
import java.util.zip.DataFormatException
import java.util.zip.Inflater

/**
 * Decompresses a KDBX payload, and each `Meta/Binaries` item marked `Compressed="True"`, as .NET
 * Framework's GZipStream reads it. GZipStream passes window bits 47 to zlib: zlib then reads a
 * gzip member (RFC 1952) or a zlib stream (RFC 1950), chosen by the first two bytes, and inflates
 * only that one stream. This reader follows zlib's inflate state machine for that setting:
 * - Bytes 1F 8B start a gzip member: a method other than 8 or a reserved flag bit is refused,
 *   MTIME, XFL and OS are ignored, FEXTRA, FNAME and FCOMMENT are skipped, and FHCRC is checked.
 * - Any other start is a zlib header: (CMF x 256 + FLG) must be a multiple of 31, CM 8, CINFO at
 *   most 7, and FDICT is refused once its 4-byte dictionary id is present.
 * - Bytes after the end of the first stream are never read.
 * - Each trailer word (CRC-32 and ISIZE for gzip, Adler-32 for zlib) is checked when all 4 of its
 *   bytes are present; a missing or partial word is accepted, as zlib waits for more input and
 *   GZipStream ends quietly when there is none.
 * - Input that ends inside the header or the deflate data is not an error here either: the
 *   result holds what inflated so far, and the inner header or XML parse refuses incomplete
 *   content.
 *
 * The output buffer comes from [Buffers]. For a gzip member it starts one byte past the ISIZE the
 * last 4 input bytes state, capped at the limit and at 1,032 times the input (deflate's largest
 * ratio), so a member whose ISIZE is right inflates into one buffer with no copy; a zlib stream
 * starts at 64 KiB. A buffer that fills before the stream ends doubles, up to the limit; each one
 * it replaces is zero-filled and released ([Buffers.release]).
 *
 * java.util.zip.Inflater keeps its 32 KiB window of decompressed data in native memory until
 * `end()`, which frees it without clearing it; the reader calls `end()` before it returns.
 */
internal object GzipReader {

    /** How the input ended. */
    enum class Ending {
        /** The stream ended and every trailer word was present and correct. */
        TRAILER_CHECKED,

        /** The stream ended; at least one trailer word was missing or cut, and was not checked. */
        TRAILER_INCOMPLETE,

        /** The input ended inside the header or the deflate data. */
        INPUT_ENDED,
    }

    /**
     * The first [size] bytes of [bytes] are the decompressed data. [bytes] is the reader's only
     * live output buffer; the caller zero-fills it.
     */
    class Inflated(val bytes: ByteArray, val size: Int, val ending: Ending)

    private const val FHCRC = 0x02
    private const val FEXTRA = 0x04
    private const val FNAME = 0x08
    private const val FCOMMENT = 0x10
    private const val FRESERVED = 0xE0
    private const val DEFLATE = 8
    private const val INITIAL_BUFFER = 64 * 1024
    private const val TRAILER = 8
    private const val MAX_RATIO = 1032L

    /**
     * Decompresses [length] bytes of [data] from [offset] into at most [limit] bytes. Throws
     * [KdbxException.CompressedData] for invalid data, [KdbxException.InflatedTooLarge] as soon
     * as the output would pass [limit], and [KdbxException.InvalidLength] for a [limit] below 1
     * or a range outside [data]. Every buffer it allocated is zero-filled when it throws,
     * OutOfMemoryError included.
     */
    fun inflate(data: ByteArray, offset: Int, length: Int, limit: Int, buffers: Buffers = Buffers.Default): Inflated {
        if (limit < 1) throw KdbxException.InvalidLength(KdbxException.Field.LIMIT)
        Bytes.checkRange(data.size, offset, length)
        val end = offset + length
        if (length < 2) return Inflated(buffers.bytes(0), 0, Ending.INPUT_ENDED)
        val gzip = (data[offset].toInt() and 0xFF) == 0x1F && (data[offset + 1].toInt() and 0xFF) == 0x8B
        val bodyStart = (if (gzip) gzipHeader(data, offset, end) else zlibHeader(data, offset, end))
            ?: return Inflated(buffers.bytes(0), 0, Ending.INPUT_ENDED)
        val initial = if (gzip && length >= TRAILER) {
            val stated = Bytes.readLe32(data, end - 4).toUInt().toLong()
            minOf(stated, length * MAX_RATIO) + 1
        } else {
            INITIAL_BUFFER.toLong()
        }
        return inflateBody(data, bodyStart, end, limit, gzip, minOf(initial, limit.toLong()).toInt(), buffers)
    }

    // Returns where the deflate data starts, or null when the input ends inside the header.
    private fun gzipHeader(data: ByteArray, offset: Int, end: Int): Int? {
        if (end - offset < 4) return null
        if (data[offset + 2].toInt() and 0xFF != DEFLATE) throw KdbxException.CompressedData(KdbxException.Fault.GZIP_METHOD)
        val flags = data[offset + 3].toInt() and 0xFF
        if (flags and FRESERVED != 0) throw KdbxException.CompressedData(KdbxException.Fault.GZIP_FLAGS)
        var p = offset + 10
        if (p > end) return null
        if (flags and FEXTRA != 0) {
            if (p + 2 > end) return null
            p += 2 + Bytes.readLe16(data, p)
            if (p > end) return null
        }
        for (flag in listOf(FNAME, FCOMMENT)) {
            if (flags and flag == 0) continue
            while (p < end && data[p].toInt() != 0) p++
            if (p >= end) return null
            p++
        }
        if (flags and FHCRC != 0) {
            if (p + 2 > end) return null
            val crc = CRC32().apply { update(data, offset, p - offset) }.value.toInt() and 0xFFFF
            if (Bytes.readLe16(data, p) != crc) throw KdbxException.CompressedData(KdbxException.Fault.HEADER_CRC)
            p += 2
        }
        return p
    }

    private fun zlibHeader(data: ByteArray, offset: Int, end: Int): Int? {
        val cmf = data[offset].toInt() and 0xFF
        val flg = data[offset + 1].toInt() and 0xFF
        if ((cmf * 256 + flg) % 31 != 0) throw KdbxException.CompressedData(KdbxException.Fault.ZLIB_HEADER)
        if (cmf and 0x0F != DEFLATE) throw KdbxException.CompressedData(KdbxException.Fault.ZLIB_METHOD)
        if (cmf ushr 4 > 7) throw KdbxException.CompressedData(KdbxException.Fault.ZLIB_WINDOW)
        if (flg and 0x20 != 0) {
            if (end - offset < 6) return null
            throw KdbxException.CompressedData(KdbxException.Fault.ZLIB_DICTIONARY)
        }
        return offset + 2
    }

    private fun inflateBody(data: ByteArray, start: Int, end: Int, limit: Int, gzip: Boolean, initial: Int, buffers: Buffers): Inflated {
        val inflater = Inflater(true)
        val check: Checksum = if (gzip) CRC32() else Adler32()
        var buf = buffers.bytes(initial)
        var probe: ByteArray? = null
        var size = 0
        try {
            inflater.setInput(data, start, end - start)
            while (!inflater.finished()) {
                if (size == buf.size) {
                    if (size == limit) {
                        val p = probe ?: buffers.bytes(1).also { probe = it }
                        // A full buffer at the limit: one more byte means the output passes it.
                        if (inflate(inflater, p, 0, 1) > 0) throw KdbxException.InflatedTooLarge(limit)
                        if (inflater.finished()) break
                        return Inflated(buf, size, Ending.INPUT_ENDED)
                    }
                    val grown = buffers.bytes(minOf(limit.toLong(), buf.size * 2L).toInt())
                    buf.copyInto(grown, 0, 0, size)
                    buf.fill(0)
                    buffers.release(buf)
                    buf = grown
                }
                val n = inflate(inflater, buf, size, buf.size - size)
                check.update(buf, size, n)
                size += n
                // Raw deflate never needs a dictionary, so 0 bytes means the input ended.
                if (n == 0 && inflater.needsInput()) {
                    return Inflated(buf, size, Ending.INPUT_ENDED)
                }
            }
            val left = inflater.remaining
            val trailer = end - left
            val ending = if (gzip) {
                if (left >= 4 && Bytes.readLe32(data, trailer) != check.value.toInt()) throw KdbxException.CompressedData(KdbxException.Fault.CRC)
                if (left >= 8 && Bytes.readLe32(data, trailer + 4) != size) throw KdbxException.CompressedData(KdbxException.Fault.ISIZE)
                if (left >= 8) Ending.TRAILER_CHECKED else Ending.TRAILER_INCOMPLETE
            } else {
                if (left >= 4 && readBe32(data, trailer) != check.value.toInt()) throw KdbxException.CompressedData(KdbxException.Fault.ADLER)
                if (left >= 4) Ending.TRAILER_CHECKED else Ending.TRAILER_INCOMPLETE
            }
            return Inflated(buf, size, ending)
        } catch (e: Throwable) {
            // OutOfMemoryError while the buffer grows included: the buffer holds plaintext.
            buf.fill(0)
            throw e
        } finally {
            probe?.fill(0)
            inflater.end()
        }
    }

    private fun inflate(inflater: Inflater, out: ByteArray, offset: Int, length: Int): Int = try {
        inflater.inflate(out, offset, length)
    } catch (e: DataFormatException) {
        throw KdbxException.CompressedData(KdbxException.Fault.DEFLATE_DATA)
    }

    private fun readBe32(b: ByteArray, at: Int): Int =
        ((b[at].toInt() and 0xFF) shl 24) or ((b[at + 1].toInt() and 0xFF) shl 16) or
            ((b[at + 2].toInt() and 0xFF) shl 8) or (b[at + 3].toInt() and 0xFF)
}
