package org.onekash.kashpass.vault.kdbx

import java.util.Collections
import java.util.IdentityHashMap

/**
 * Allocates every key, keystream state and plaintext array a container primitive owns. Each
 * primitive zero-fills what it allocated here when it returns, throws or closes, except an array
 * it returns, which the caller zero-fills; tests pass a recording implementation and check that
 * every recorded array is zero afterwards.
 */
internal interface Buffers {
    fun bytes(size: Int): ByteArray
    fun ints(size: Int): IntArray

    /**
     * Takes back [array], which came from [bytes], is zero-filled and is never used again, so a
     * caller that tracks its arrays drops it before the step ends ([KdbxDecoder], [KdbxEncoder]).
     */
    fun release(array: ByteArray) {}

    /** Plain arrays, used outside tests. */
    object Default : Buffers {
        override fun bytes(size: Int) = ByteArray(size)
        override fun ints(size: Int) = IntArray(size)
    }
}

/**
 * Passes every call to [buffers] and keeps each byte array it hands out in [owned] until it is
 * released, so a step can zero-fill the arrays it holds when it ends ([KdbxDecoder],
 * [KdbxEncoder]).
 */
internal class TrackingBuffers(private val buffers: Buffers) : Buffers {
    /** The byte arrays handed out and not released, by identity. */
    val owned: MutableSet<ByteArray> = Collections.newSetFromMap(IdentityHashMap())

    override fun bytes(size: Int) = buffers.bytes(size).also { owned += it }

    override fun ints(size: Int) = buffers.ints(size)

    override fun release(array: ByteArray) {
        owned -= array
        buffers.release(array)
    }
}
