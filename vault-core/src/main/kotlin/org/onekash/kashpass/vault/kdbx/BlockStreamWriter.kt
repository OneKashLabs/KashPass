package org.onekash.kashpass.vault.kdbx

import org.onekash.kashpass.vault.kdbx.BlockStream.FRAME
import org.onekash.kashpass.vault.kdbx.BlockStream.HMAC

/**
 * Writes the KDBX 4 HMAC block stream: the ciphertext is cut into blocks of [BLOCK_SIZE] bytes,
 * and block i is its HMAC ([KeySchedule.blockMac] with i counted from 0), its length as 4 bytes
 * little-endian and its data. A full block is written only when more data follows it, so the last
 * data block holds 1 to [BLOCK_SIZE] bytes; the stream ends with an empty block and its HMAC.
 * Ciphertext of 0, 1 MiB - 1, 1 MiB, 1 MiB + 1 and 3 MiB bytes gives 1, 2, 2, 3 and 4 blocks, the
 * end block included. [BlockStream] reads it back; [BlockStreamWriterTest] pins each rule.
 *
 * The writer takes no array from [Buffers]: its input and output are ciphertext. Each block key
 * lives inside one [KeySchedule.blockMac] call.
 */
internal object BlockStreamWriter {

    /** The data bytes of every block but the last data block and the end block. */
    const val BLOCK_SIZE = 1024 * 1024

    /**
     * Returns the size of the block stream for [length] bytes of ciphertext. Throws
     * [KdbxException.InvalidLength] with [KdbxException.Field.RANGE] for a negative [length] or
     * one whose stream is larger than an array can hold.
     */
    fun size(length: Int): Int {
        if (length < 0) throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        val blocks = (length.toLong() + BLOCK_SIZE - 1) / BLOCK_SIZE + 1
        val size = length + blocks * FRAME
        if (size > Int.MAX_VALUE) throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        return size.toInt()
    }

    /**
     * Writes the block stream for [length] bytes of [data] from [offset] into [out] from
     * [outOffset] and returns the offset after the end block. [data] and [out] are different
     * arrays. Throws [KdbxException.InvalidLength] with [KdbxException.Field.RANGE] for a range
     * outside [data] or fewer than [size] bytes after [outOffset], before anything is written.
     */
    fun write(data: ByteArray, offset: Int, length: Int, keys: KeySchedule, out: ByteArray, outOffset: Int): Int {
        Bytes.checkRange(data.size, offset, length)
        Bytes.checkRange(out.size, outOffset, size(length))
        var p = outOffset
        var at = offset
        val end = offset + length
        var index = 0L
        while (true) {
            val n = minOf(BLOCK_SIZE, end - at)
            keys.blockMac(index, data, at, n).copyInto(out, p)
            Bytes.writeLe32(out, p + HMAC, n)
            data.copyInto(out, p + FRAME, at, at + n)
            p += FRAME + n
            at += n
            index++
            if (n == 0) return p
        }
    }

    /** Returns the block stream for [length] bytes of [data] from [offset] as a new array. */
    fun write(data: ByteArray, offset: Int, length: Int, keys: KeySchedule): ByteArray {
        Bytes.checkRange(data.size, offset, length)
        return ByteArray(size(length)).also { write(data, offset, length, keys, it, 0) }
    }
}
