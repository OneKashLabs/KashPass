package org.onekash.kashpass.vault.kdbx

import java.util.zip.CRC32
import java.util.zip.Deflater

/**
 * Compresses a KDBX payload into one gzip member (RFC 1952): a 10-byte header (no flags, MTIME 0,
 * XFL 4, OS 0), raw deflate data (RFC 1951) at java.util.zip.Deflater's default level, then the
 * CRC-32 and ISIZE of the input, each 4 bytes little-endian. [GzipReader] reads it back;
 * [GzipWriterTest] pins the layout.
 *
 * The output buffer comes from [Buffers]: it starts at a quarter of zlib's bound for the input,
 * at least 64 KiB and at most the bound, and doubles up to that bound; each buffer it replaces is
 * zero-filled and released ([Buffers.release]). Starting at the bound would hold a buffer three
 * times too large for text that gzip shrinks to a third; starting at 64 KiB would hold two copies
 * near the payload's size while incompressible attachments grow the buffer past half the bound.
 * java.util.zip.Deflater keeps its window of input and its pending output in native memory, which
 * `end()` frees without clearing; KashPass cannot zero-fill that memory, and the writer calls
 * `end()` before it returns or throws.
 */
internal object GzipWriter {

    /**
     * The first [size] bytes of [bytes] are the member; [bytes] is the writer's only live buffer
     * and the caller zero-fills it.
     */
    class Deflated(val bytes: ByteArray, val size: Int)

    private val HEADER = byteArrayOf(0x1F, 0x8B.toByte(), 8, 0, 0, 0, 0, 0, 4, 0)
    private const val TRAILER = 8
    private const val INITIAL_BUFFER = 64 * 1024

    /**
     * Compresses [length] bytes of [data] from [offset] into one gzip member, with at least
     * [spare] unused bytes after it in [Deflated.bytes] (room for the AES padding
     * [AesCbc.encrypt] writes in place). Throws [KdbxException.InvalidLength] with
     * [KdbxException.Field.RANGE] for a range outside [data], a negative [spare] or a member
     * larger than an array can hold. Every buffer it allocated is zero-filled when it throws,
     * OutOfMemoryError included.
     */
    fun compress(data: ByteArray, offset: Int, length: Int, spare: Int = 0, buffers: Buffers = Buffers.Default): Deflated {
        Bytes.checkRange(data.size, offset, length)
        if (spare < 0) throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        // zlib's deflateBound for raw deflate at the default window and memory level; output
        // past it grows the buffer further.
        val bound = length.toLong() + (length shr 12) + (length shr 14) + (length shr 25) + 7
        val target = HEADER.size + bound + TRAILER + spare
        var buf = buffers.bytes(minOf(target, maxOf(INITIAL_BUFFER.toLong(), target / 4)).toInt())
        var created: Deflater? = null
        try {
            val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, true).also { created = it }
            HEADER.copyInto(buf)
            var size = HEADER.size
            deflater.setInput(data, offset, length)
            deflater.finish()
            while (!deflater.finished()) {
                if (size == buf.size) buf = grow(buf, size, size + 1L, target, buffers)
                size += deflater.deflate(buf, size, buf.size - size)
            }
            if (buf.size - size < TRAILER + spare) buf = grow(buf, size, size.toLong() + TRAILER + spare, target, buffers)
            val crc = CRC32().apply { update(data, offset, length) }
            Bytes.writeLe32(buf, size, crc.value.toInt())
            Bytes.writeLe32(buf, size + 4, length)
            return Deflated(buf, size + TRAILER)
        } catch (e: Throwable) {
            // OutOfMemoryError while the buffer grows included: the buffer holds compressed
            // plaintext.
            buf.fill(0)
            throw e
        } finally {
            created?.end()
        }
    }

    // Returns a buffer of at least [atLeast] bytes holding the first [used] bytes of [buf], and
    // zero-fills [buf]. It doubles, capped at [target] while [target] is ahead of the buffer.
    private fun grow(buf: ByteArray, used: Int, atLeast: Long, target: Long, buffers: Buffers): ByteArray {
        val doubled = buf.size * 2L
        val size = maxOf(atLeast, if (target > buf.size) minOf(doubled, target) else doubled)
        if (size > Int.MAX_VALUE) throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        val grown = buffers.bytes(size.toInt())
        buf.copyInto(grown, 0, 0, used)
        buf.fill(0)
        buffers.release(buf)
        return grown
    }
}
