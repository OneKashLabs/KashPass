package org.onekash.kashpass.vault.testing

import org.onekash.kashpass.vault.kdbx.Buffers

/**
 * A [Buffers] that keeps every array it hands out, so a test can check that a primitive
 * zero-filled them. Call [assertRecorded] first, so an empty recording never passes
 * [assertAllZero].
 */
internal class RecordingBuffers : Buffers {

    private val byteArrays = mutableListOf<ByteArray>()
    private val intArrays = mutableListOf<IntArray>()

    @Synchronized
    override fun bytes(size: Int) = ByteArray(size).also { byteArrays += it }

    @Synchronized
    override fun ints(size: Int) = IntArray(size).also { intArrays += it }

    private val releasedArrays = mutableListOf<ByteArray>()

    /** Records [array] as released; fails unless it came from [bytes] and is zero-filled. */
    @Synchronized
    override fun release(array: ByteArray) {
        check(byteArrays.any { it === array }) { "released an array of ${array.size} bytes it did not hand out" }
        check(array.all { it.toInt() == 0 }) { "released an array of ${array.size} bytes that is not zero-filled" }
        releasedArrays += array
    }

    /** Sizes of the byte arrays released, in order. */
    @get:Synchronized
    val releasedSizes: List<Int> get() = releasedArrays.map { it.size }

    /** True when [array] itself (by identity) was released. */
    @Synchronized
    fun released(array: ByteArray): Boolean = releasedArrays.any { it === array }

    /** Sizes of the byte arrays handed out, in order. */
    @get:Synchronized
    val byteSizes: List<Int> get() = byteArrays.map { it.size }

    /** Sizes of the int arrays handed out, in order. */
    @get:Synchronized
    val intSizes: List<Int> get() = intArrays.map { it.size }

    /**
     * Fails unless the byte and int arrays handed out have the sizes [bytes] and [ints],
     * in any order.
     */
    fun assertRecorded(bytes: List<Int>, ints: List<Int> = emptyList()) {
        check(byteSizes.sorted() == bytes.sorted()) { "byte arrays allocated: $byteSizes, expected $bytes" }
        check(intSizes.sorted() == ints.sorted()) { "int arrays allocated: $intSizes, expected $ints" }
    }

    /** Fails naming the size of the first array handed out that holds a non-zero element. */
    fun assertAllZero() = assertAllZeroExcept()

    /**
     * Fails naming the size of the first array handed out that holds a non-zero element, skipping
     * the byte arrays that are [kept] themselves (compared by identity): arrays a result returns
     * to its caller.
     */
    @Synchronized
    fun assertAllZeroExcept(vararg kept: ByteArray) {
        byteArrays.firstOrNull { a -> kept.none { it === a } && a.any { it.toInt() != 0 } }
            ?.let { error("a byte array of ${it.size} bytes is not zero-filled") }
        intArrays.firstOrNull { a -> a.any { it != 0 } }?.let { error("an int array of ${it.size} ints is not zero-filled") }
    }
}
