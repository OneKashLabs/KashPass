package org.onekash.kashpass.vault.kdbx

/**
 * Reads the KDBX 4 inner header at the start of the decrypted payload: fields of an id byte, a
 * 4-byte little-endian length and data, ended by field 0, whose value is ignored. An unknown id
 * is skipped; the last stream id (1) and stream key (2) win; each attachment (3) is kept in file
 * order with its protection flag, never merged. The outer fields 10 and 8 stand in for a missing
 * stream id and key, and with no stream id in either header the stream is the ArcFour variant
 * (1). [InnerHeaderReaderTest] pins each rule.
 */
internal object InnerHeaderReader {

    /** The inner header and where the XML starts in the payload. */
    class Read(val header: InnerHeader, val xmlOffset: Int)

    // Field ids and the protected flag, shared with [InnerHeaderWriter].
    internal const val END = 0
    internal const val STREAM_ID = 1
    internal const val STREAM_KEY = 2
    internal const val BINARY = 3
    internal const val PROTECTED_FLAG = 0x01

    /**
     * Reads the inner header from the first [length] bytes of [payload]. Throws [KdbxFailure] with
     * Damaged([KdbxDamage.INNER_HEADER]) for a cut field, a negative or overlong length (nothing is
     * allocated from it) or an attachment without its flag byte; Damaged([KdbxDamage.INNER_STREAM])
     * for a stream id that is not 4 bytes or a stream key that is missing from both headers or
     * empty; and Unsupported for a stream id other than 1, 2 or 3. An id above 3 is refused as the
     * field is read, and an id of 0 (no stream) only at the end-of-header field and after
     * the stream key check, so the checks run in that order. The stream key and the attachment
     * bytes are copied into [buffers] arrays that belong to the caller once [read] returns; when it
     * throws, they are zero-filled.
     */
    fun read(payload: ByteArray, length: Int, outer: OuterHeader, buffers: Buffers = Buffers.Default): Read {
        Bytes.checkRange(payload.size, 0, length)
        var streamId: Int? = null
        var streamKey: ByteArray? = null
        val attachments = ArrayList<Attachment>()
        try {
            var p = 0
            while (true) {
                if (length - p < 5) damaged(KdbxDamage.INNER_HEADER)
                val id = payload[p].toInt() and 0xFF
                val size = Bytes.readLe32(payload, p + 1)
                p += 5
                if (size < 0 || size > length - p) damaged(KdbxDamage.INNER_HEADER)
                val start = p
                p += size
                when (id) {
                    END -> break
                    STREAM_ID -> {
                        if (size != 4) damaged(KdbxDamage.INNER_STREAM)
                        val value = Bytes.readLe32(payload, start).toUInt().toLong()
                        if (value >= InnerStream.COUNT) throw KdbxFailure(KdbxResult.Unsupported(KdbxUnsupported.InnerStream(value.toInt())))
                        streamId = value.toInt()
                    }
                    STREAM_KEY -> {
                        streamKey?.fill(0)
                        streamKey = copy(payload, start, p, buffers)
                    }
                    BINARY -> {
                        if (size < 1) damaged(KdbxDamage.INNER_HEADER)
                        val protected = payload[start].toInt() and PROTECTED_FLAG != 0
                        attachments += Attachment(protected, copy(payload, start + 1, p, buffers))
                    }
                }
            }
            val fallback = outer.innerStreamKeyFallback
            val key = streamKey ?: fallback?.let { copy(it, 0, it.size, buffers) }
            streamKey = key
            if (key == null || key.isEmpty()) damaged(KdbxDamage.INNER_STREAM)
            val id = streamId ?: outer.innerStreamIdFallback ?: InnerStream.ARCFOUR_VARIANT
            if (id == 0) throw KdbxFailure(KdbxResult.Unsupported(KdbxUnsupported.InnerStream(0)))
            return Read(InnerHeader(id, key, attachments), p)
        } catch (e: Throwable) {
            // Attachments and the stream key are plaintext; nothing is returned to own them.
            streamKey?.fill(0)
            for (a in attachments) a.data.fill(0)
            throw e
        }
    }

    private fun copy(from: ByteArray, start: Int, end: Int, buffers: Buffers): ByteArray =
        buffers.bytes(end - start).also { from.copyInto(it, 0, start, end) }
}
