package org.onekash.kashpass.vault.kdbx

/**
 * Reads the KDBX 4 HMAC block stream: from [read]'s start, block i is a 32-byte HMAC, a 4-byte
 * little-endian length and that many bytes of ciphertext, with i counted as a Long from 0. Every
 * block's HMAC ([KeySchedule.blockMac]) is checked over the input in place, before any byte of it
 * is used. A block of length 0 is the end block, and its HMAC is checked too; bytes after it are
 * never read. [BlockStreamTest] pins each rule.
 */
internal object BlockStream {

    /**
     * The ciphertext of all blocks: the first [length] bytes of [ciphertext], an array from the
     * caller's [Buffers] that the caller zero-fills once it holds plaintext. [bytesAfterEnd] is
     * true when the file goes on after the end block.
     */
    class Blocks(val ciphertext: ByteArray, val length: Int, val bytesAfterEnd: Boolean)

    // A block's HMAC and length before its data, shared with [BlockStreamWriter].
    internal const val HMAC = 32
    internal const val FRAME = HMAC + 4

    /**
     * Checks every block of [bytes] from [start] and copies their data into one array. Throws
     * [KdbxFailure] with Damaged: [KdbxDamage.END_BLOCK_MISSING] when the input ends before a block
     * header or before the end block, [KdbxDamage.BLOCK_LENGTH] for a negative length or one
     * beyond the bytes left (nothing is allocated from it), [KdbxDamage.BLOCK_HMAC] for an HMAC
     * that differs. The HMACs are compared in constant time.
     */
    fun read(bytes: ByteArray, start: Int, keys: KeySchedule, buffers: Buffers = Buffers.Default): Blocks {
        Bytes.checkRange(bytes.size, start, bytes.size - start)
        var p = start
        var index = 0L
        var total = 0
        while (true) {
            if (bytes.size - p < FRAME) throw KdbxFailure(KdbxResult.Damaged(KdbxDamage.END_BLOCK_MISSING))
            val length = Bytes.readLe32(bytes, p + HMAC)
            if (length < 0 || length > bytes.size - p - FRAME) throw KdbxFailure(KdbxResult.Damaged(KdbxDamage.BLOCK_LENGTH))
            val expected = keys.blockMac(index, bytes, p + FRAME, length)
            val stored = bytes.copyOfRange(p, p + HMAC)
            if (!Bytes.constantTimeEquals(expected, stored)) throw KdbxFailure(KdbxResult.Damaged(KdbxDamage.BLOCK_HMAC))
            p += FRAME + length
            index++
            if (length == 0) break
            // Each length is at most the bytes left, so the sum never passes the input's size.
            total += length
        }
        val end = p
        val ciphertext = buffers.bytes(total)
        p = start
        var at = 0
        while (at < total) {
            val length = Bytes.readLe32(bytes, p + HMAC)
            bytes.copyInto(ciphertext, at, p + FRAME, p + FRAME + length)
            at += length
            p += FRAME + length
        }
        return Blocks(ciphertext, total, bytesAfterEnd = end < bytes.size)
    }
}
