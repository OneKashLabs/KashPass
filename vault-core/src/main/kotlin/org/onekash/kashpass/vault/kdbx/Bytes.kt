package org.onekash.kashpass.vault.kdbx

import java.security.MessageDigest

/** Zero-fill, constant-time compare, range checks and little-endian integers for the container. */
internal object Bytes {

    /** Zero-fills every array in [arrays]; null entries are skipped. */
    fun zeroFill(vararg arrays: ByteArray?) {
        for (a in arrays) a?.fill(0)
    }

    /** Zero-fills every array in [arrays]; null entries are skipped. */
    fun zeroFill(vararg arrays: IntArray?) {
        for (a in arrays) a?.fill(0)
    }

    /**
     * Returns true when [a] and [b] hold the same bytes. The time depends only on the lengths
     * (MessageDigest.isEqual, constant-time since JDK 6u17 and in Android's libcore), so a MAC
     * check leaks nothing about where the bytes differ.
     */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    /**
     * Throws [KdbxException.InvalidLength] with [KdbxException.Field.RANGE] unless [offset] and
     * [length] are non-negative and `offset + length` (computed as a Long) is at most [size].
     */
    fun checkRange(size: Int, offset: Int, length: Int) {
        if (offset < 0 || length < 0 || offset.toLong() + length > size) {
            throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        }
    }

    /** Reads the little-endian 16-bit value at [offset] of [b], as an Int from 0 to 65535. */
    fun readLe16(b: ByteArray, offset: Int): Int {
        checkRange(b.size, offset, 2)
        return (b[offset].toInt() and 0xFF) or ((b[offset + 1].toInt() and 0xFF) shl 8)
    }

    /** Reads the little-endian 32-bit value at [offset] of [b]. */
    fun readLe32(b: ByteArray, offset: Int): Int {
        checkRange(b.size, offset, 4)
        var v = 0
        for (i in 3 downTo 0) v = (v shl 8) or (b[offset + i].toInt() and 0xFF)
        return v
    }

    /** Reads the little-endian 64-bit value at [offset] of [b]. */
    fun readLe64(b: ByteArray, offset: Int): Long {
        checkRange(b.size, offset, 8)
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[offset + i].toLong() and 0xFF)
        return v
    }

    /** Writes the low 16 bits of [value] little-endian at [offset] of [b]. */
    fun writeLe16(b: ByteArray, offset: Int, value: Int) {
        checkRange(b.size, offset, 2)
        b[offset] = value.toByte()
        b[offset + 1] = (value ushr 8).toByte()
    }

    /** Writes [value] little-endian at [offset] of [b]. */
    fun writeLe32(b: ByteArray, offset: Int, value: Int) {
        checkRange(b.size, offset, 4)
        for (i in 0 until 4) b[offset + i] = (value ushr (8 * i)).toByte()
    }

    /** Writes [value] little-endian at [offset] of [b]. */
    fun writeLe64(b: ByteArray, offset: Int, value: Long) {
        checkRange(b.size, offset, 8)
        for (i in 0 until 8) b[offset + i] = (value ushr (8 * i)).toByte()
    }
}
