package org.onekash.kashpass.vault.kdbx

import org.onekash.kashpass.vault.kdbx.InnerHeaderReader.BINARY
import org.onekash.kashpass.vault.kdbx.InnerHeaderReader.END
import org.onekash.kashpass.vault.kdbx.InnerHeaderReader.PROTECTED_FLAG
import org.onekash.kashpass.vault.kdbx.InnerHeaderReader.STREAM_ID
import org.onekash.kashpass.vault.kdbx.InnerHeaderReader.STREAM_KEY

/**
 * Writes the KDBX 4 inner header: field 1 is the inner stream id 3 (ChaCha20), field 2 the
 * 64-byte stream key, then one field 3 per attachment in the order given (a flag byte, 0x01 when
 * protected and 0x00 otherwise, then the data), then field 0 with an empty value. Each field is
 * an id byte, a 4-byte little-endian length and the value. Attachment data is written as given:
 * the inner stream never runs over it, and equal attachments are not merged. [InnerHeaderReader]
 * reads it back; [InnerHeaderWriterTest] pins each rule.
 */
internal object InnerHeaderWriter {

    private const val NO_FLAGS: Byte = 0x00
    private const val KEY_BYTES = 64
    private const val FIELD = 5
    private const val STREAM_FIELDS = FIELD + 4 + FIELD + KEY_BYTES

    /**
     * Returns the size of the inner header for [streamKey] and [attachments]. Throws
     * [KdbxException.InvalidLength] with [KdbxException.Field.KEY] for a key that is not 64
     * bytes, and with [KdbxException.Field.RANGE] for a header larger than an array can hold.
     */
    fun size(streamKey: ByteArray, attachments: List<Attachment>): Int {
        if (streamKey.size != KEY_BYTES) throw KdbxException.InvalidLength(KdbxException.Field.KEY)
        val size = size(attachments)
        if (size > Int.MAX_VALUE) throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        return size.toInt()
    }

    /** Returns the size of the inner header a save writes for [attachments], uncapped. */
    fun size(attachments: List<Attachment>): Long =
        STREAM_FIELDS + FIELD + attachments.sumOf { FIELD + 1L + it.data.size }

    /**
     * Passes the inner header to [piece] in order, as pieces of an array, an offset and a length,
     * without building it in one array: the stream id and key fields in an array from [buffers],
     * zero-filled and released ([Buffers.release]) once [piece] returns; then per attachment its
     * field id, length and flag, and its data array itself; then field 0. [piece] copies each
     * piece and keeps no reference to it. Throws as [size] does, before [piece] runs.
     */
    fun write(streamKey: ByteArray, attachments: List<Attachment>, buffers: Buffers, piece: (ByteArray, Int, Int) -> Unit) {
        size(streamKey, attachments)
        val stream = buffers.bytes(STREAM_FIELDS)
        try {
            var p = field(stream, 0, STREAM_ID, 4)
            Bytes.writeLe32(stream, p, InnerStream.CHACHA20)
            p = field(stream, p + 4, STREAM_KEY, KEY_BYTES)
            streamKey.copyInto(stream, p)
            piece(stream, 0, STREAM_FIELDS)
        } finally {
            stream.fill(0)
            buffers.release(stream)
        }
        val prefix = ByteArray(FIELD + 1)
        for (a in attachments) {
            field(prefix, 0, BINARY, 1 + a.data.size)
            prefix[FIELD] = if (a.protected) PROTECTED_FLAG.toByte() else NO_FLAGS
            piece(prefix, 0, prefix.size)
            piece(a.data, 0, a.data.size)
        }
        val end = ByteArray(FIELD)
        field(end, 0, END, 0)
        piece(end, 0, end.size)
    }

    /**
     * Writes the inner header into [out] from [offset] and returns the offset after field 0.
     * Throws as [size] does, and with [KdbxException.Field.RANGE] for fewer than [size] bytes
     * after [offset], before anything is written. The bytes written hold the stream key and the
     * attachments; the caller zero-fills them.
     */
    fun write(streamKey: ByteArray, attachments: List<Attachment>, out: ByteArray, offset: Int, buffers: Buffers = Buffers.Default): Int {
        Bytes.checkRange(out.size, offset, size(streamKey, attachments))
        var p = offset
        write(streamKey, attachments, buffers) { bytes, from, length ->
            bytes.copyInto(out, p, from, from + length)
            p += length
        }
        return p
    }

    /**
     * Returns the inner header in an array from [buffers], which the caller zero-fills. Throws as
     * [size] does.
     */
    fun write(streamKey: ByteArray, attachments: List<Attachment>, buffers: Buffers): ByteArray {
        val out = buffers.bytes(size(streamKey, attachments))
        try {
            write(streamKey, attachments, out, 0, buffers)
        } catch (e: Throwable) {
            // The array holds the stream key and attachments; nothing is returned to own it.
            out.fill(0)
            throw e
        }
        return out
    }

    // Writes a field's id and length at [p] and returns where its value starts.
    private fun field(out: ByteArray, p: Int, id: Int, length: Int): Int {
        out[p] = id.toByte()
        Bytes.writeLe32(out, p + 1, length)
        return p + FIELD
    }
}
