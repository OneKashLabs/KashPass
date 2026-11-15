package org.onekash.kashpass.vault.testing

import kotlin.test.assertFailsWith
import org.junit.jupiter.api.Test

class RecordingBuffersTest {

    @Test
    fun `assertAllZeroExcept skips only the kept arrays`() {
        val buffers = RecordingBuffers()
        val kept = buffers.bytes(4).also { it[0] = 1 }
        val other = buffers.bytes(4)
        buffers.assertAllZeroExcept(kept)
        other[3] = 2
        assertFailsWith<IllegalStateException> { buffers.assertAllZeroExcept(kept) }
        other.fill(0)
        assertFailsWith<IllegalStateException> { buffers.assertAllZero() }
    }

    @Test
    fun `an equal array that is not the same array is not kept`() {
        val buffers = RecordingBuffers()
        buffers.bytes(2)[1] = 7
        assertFailsWith<IllegalStateException> { buffers.assertAllZeroExcept(byteArrayOf(0, 7)) }
    }
}
