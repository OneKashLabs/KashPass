package org.onekash.kashpass.vault.kdbx

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.testing.RecordingBuffers

/**
 * Every array the decoder allocates is zero-filled after a failure, or once the caller closes the
 * plaintext and clears the stream key and attachments it was given.
 */
class KdbxDecoderZeroingTest {

    private class Derived(val key: ByteArray) {
        var given: ByteArray? = null
        fun derive(): ByteArray = key.copyOf().also { given = it }
    }

    private fun derived(bytes: ByteArray, name: String) =
        Derived(DecoderRig.transformed(bytes, DecoderRig.key(Fixtures.file(Fixtures.named(name))))!!)

    @ParameterizedTest
    @ValueSource(strings = ["keepass2-weak-aeskdf-6000.kdbx", "keepass2-chacha20-argon2d.kdbx", "keepass2-compression-none.kdbx", "keepass2-shared-attachments.kdbx"])
    fun `after an open only the plaintext and the container's arrays hold data, and closing them leaves nothing`(name: String) {
        val bytes = Fixtures.bytes(name)
        val d = derived(bytes, name)
        val buffers = RecordingBuffers()
        val opened = assertIs<KdbxResult.Opened>(DecoderRig.decode(bytes, d::derive, buffers))
        val inner = opened.container.inner
        buffers.assertAllZeroExcept(opened.plaintext.buffer, inner.streamKey, *inner.attachments.map { it.data }.toTypedArray())
        assertTrue(d.given!!.all { it.toInt() == 0 }, "the transformed key is zero-filled")
        opened.plaintext.close()
        inner.streamKey.fill(0)
        inner.attachments.forEach { it.data.fill(0) }
        buffers.assertAllZero()
    }

    @Test
    fun `with gzip the ciphertext is zero-filled and released once inflated, and nothing the result holds is released`() {
        for ((name, gzip) in listOf("keepass2-weak-aeskdf-6000.kdbx" to true, "keepass2-compression-none.kdbx" to false)) {
            val bytes = Fixtures.bytes(name)
            val buffers = RecordingBuffers()
            val opened = assertIs<KdbxResult.Opened>(DecoderRig.decode(bytes, derived(bytes, name)::derive, buffers))
            val inner = opened.container.inner
            val held = listOf(opened.plaintext.buffer, inner.streamKey) + inner.attachments.map { it.data }
            assertTrue(held.none(buffers::released), name)
            // The ciphertext is the largest array before the payload; only gzip replaces it.
            assertEquals(gzip, buffers.releasedSizes.isNotEmpty(), "$name: ${buffers.releasedSizes}")
            opened.plaintext.close()
            inner.streamKey.fill(0)
            inner.attachments.forEach { it.data.fill(0) }
            buffers.assertAllZero()
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["padding-17", "gzip-crc-wrong", "attachment-no-flag-byte", "inner-stream-key-in-neither-header", "inner-stream-id-0", "cipher-aes-ciphertext-not-block-multiple", "block-multi-1-data-flipped"])
    fun `after a failure every array is zero-filled`(name: String) {
        val case = Corpus.all.single { it.name == name }
        val key = DecoderRig.transformed(case.bytes, DecoderRig.key(case.file()))!!
        val d = Derived(key)
        val buffers = RecordingBuffers()
        val result = DecoderRig.decode(case.bytes, d::derive, buffers)
        assertTrue(result !is KdbxResult.Opened, "$name opened")
        assertTrue(buffers.byteSizes.isNotEmpty())
        buffers.assertAllZero()
        assertTrue(d.given!!.all { it.toInt() == 0 })
    }

    @Test
    fun `a wrong key leaves every array zero`() {
        val bytes = Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx")
        val d = Derived(ByteArray(32) { 7 })
        val buffers = RecordingBuffers()
        assertEquals(KdbxResult.WrongKey, DecoderRig.decode(bytes, d::derive, buffers))
        buffers.assertAllZero()
        assertTrue(d.given!!.all { it.toInt() == 0 })
    }

    @Test
    fun `an OutOfMemoryError at any allocation leaves every array zero`() {
        val bytes = Fixtures.bytes("keepass2-shared-attachments.kdbx")
        val d = derived(bytes, "keepass2-shared-attachments.kdbx")
        val total = RecordingBuffers().also { DecoderRig.decode(bytes, d::derive, it).let { r -> (r as KdbxResult.Opened).plaintext.close() } }.byteSizes.size
        for (failAt in 0 until total) {
            val recording = RecordingBuffers()
            var n = 0
            val failing = object : Buffers {
                override fun bytes(size: Int): ByteArray {
                    if (n++ == failAt) throw OutOfMemoryError()
                    return recording.bytes(size)
                }
                override fun ints(size: Int) = recording.ints(size)
            }
            assertEquals(KdbxResult.NotEnoughMemory(MemoryCause.OUT_OF_MEMORY), DecoderRig.decode(bytes, d::derive, failing), "allocation $failAt")
            recording.assertAllZero()
        }
    }
}
