package org.onekash.kashpass.vault.kdbx

import java.util.concurrent.CancellationException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.onekash.kashpass.vault.testing.RecordingBuffers
import org.onekash.kashpass.vault.xml.ByteSink

/**
 * Once the encoder returns, every array it took from [Buffers] and the transformed key are zero,
 * whatever the result; only the file bytes hold data and the composite key is left as given.
 */
internal class KdbxEncoderZeroingTest {

    // Hands the encoder a real transformed key and keeps the array it gave.
    private class Derived {
        var given: ByteArray? = null
        fun derive(p: KdfParameters, composite: ByteArray): ByteArray = EncoderRig.derive(p, composite).also { given = it }
        fun assertZero() = assertTrue(given!!.all { it.toInt() == 0 }, "the transformed key is zero-filled")
    }

    private fun settings(cipher: String = "AES_256", compression: String = "GZIP") =
        EncoderRig.settings(OuterCipher.valueOf(cipher), Compression.valueOf(compression), EncoderRig.aesKdf)

    @ParameterizedTest
    @CsvSource("AES_256,GZIP", "AES_256,NONE", "CHACHA20,GZIP", "CHACHA20,NONE")
    fun `after a save only the file bytes hold data`(cipher: String, compression: String) {
        val buffers = RecordingBuffers()
        val d = Derived()
        val composite = EncoderRig.composite
        val bytes = assertIs<EncodeResult.Encoded>(
            EncoderRig.encode(settings(cipher, compression), derive = d::derive, buffers = buffers, composite = composite),
        ).bytes
        assertTrue(bytes.isNotEmpty())
        // Inner stream key, the inner header's stream fields, payload, the key schedule's two
        // keys, block keys and the keystream states were all taken from the recording.
        assertTrue(buffers.byteSizes.containsAll(listOf(64, 32, 64)), "${buffers.byteSizes}")
        assertTrue(buffers.intSizes.isNotEmpty())
        buffers.assertAllZero()
        d.assertZero()
        assertContentEquals(EncoderRig.composite, composite, "the composite key is the caller's")
    }

    @ParameterizedTest
    @CsvSource("AES_256", "CHACHA20")
    fun `with gzip the payload is zero-filled and released once compressed`(cipher: String) {
        val buffers = RecordingBuffers()
        var handed: ByteArray? = null
        val writer: (PayloadSink) -> Unit = { p ->
            EncoderRig.writer()(p)
            handed = p.handed
        }
        assertIs<EncodeResult.Encoded>(EncoderRig.encode(settings(cipher, "GZIP"), writeXml = writer, buffers = buffers))
        assertTrue(buffers.released(handed!!), "the payload is released")
        buffers.assertAllZero()
    }

    @ParameterizedTest
    @CsvSource("AES_256,GZIP", "AES_256,NONE", "CHACHA20,GZIP", "CHACHA20,NONE")
    fun `every payload buffer the XML outgrows and the inner header's stream fields are released before compression`(cipher: String, compression: String) {
        val buffers = RecordingBuffers()
        val sinkArrays = mutableListOf<ByteArray>()
        var handed: ByteArray? = null
        var checked = false
        val writer: (PayloadSink) -> Unit = { p ->
            val sink = ByteSink({ size -> p.allocate(size).also { sinkArrays += it } }, 64, p::release)
            p.writeInnerHeader { b, o, l -> sink.write(b, o, l) }
            sink.write(EncoderRig.xml(p.keystream))
            sink.write(ByteArray(64 * 1024) { 'x'.code.toByte() })
            p.handOver(sink.buffer, sink.size)
            handed = sink.buffer
        }
        val step = { s: KdbxEncoder.Step ->
            if ((s == KdbxEncoder.Step.COMPRESS || s == KdbxEncoder.Step.ENCRYPT) && !checked) {
                checked = true
                val outgrown = sinkArrays.filter { it !== handed }
                assertTrue(outgrown.size >= 2, "the sink grew: ${sinkArrays.map { it.size }}")
                for (a in outgrown) assertTrue(buffers.released(a), "an outgrown buffer of ${a.size} bytes is released")
                // Stream id field (9 bytes) and stream key field (69 bytes), from the recording.
                assertTrue(78 in buffers.releasedSizes, "the stream fields are released: ${buffers.releasedSizes}")
            }
        }
        assertIs<EncodeResult.Encoded>(EncoderRig.encode(settings(cipher, compression), writeXml = writer, buffers = buffers, step = step))
        assertTrue(checked)
        buffers.assertAllZero()
    }

    @Test
    fun `a refused KDF leaves nothing behind`() {
        val buffers = RecordingBuffers()
        assertEquals(EncodeResult.Refused, EncoderRig.encode(settings(), kdfAllowed = { false }, buffers = buffers))
        buffers.assertAllZero()
    }

    @Test
    fun `a KDF that throws leaves nothing behind`() {
        for (thrown in listOf<Throwable>(IllegalStateException(), OutOfMemoryError())) {
            val buffers = RecordingBuffers()
            val result = EncoderRig.encode(settings(), derive = { _, _ -> throw thrown }, buffers = buffers)
            assertTrue(result is EncodeResult.DeriveFailed || result == EncodeResult.NotEnoughMemory, "$result")
            buffers.assertAllZero()
        }
    }

    @ParameterizedTest
    @CsvSource("AES_256,GZIP", "AES_256,NONE", "CHACHA20,GZIP", "CHACHA20,NONE")
    fun `an XML writer that fails after writing leaves nothing behind`(cipher: String, compression: String) {
        val failures = listOf<Throwable>(IllegalStateException(), KdbxException.AlgorithmUnavailable(), OutOfMemoryError(), CancellationException())
        for (thrown in failures) {
            val buffers = RecordingBuffers()
            val d = Derived()
            val failing: (PayloadSink) -> Unit = { p ->
                EncoderRig.writer()(p)
                p.allocate(128).fill(1)
                throw thrown
            }
            val run = { EncoderRig.encode(settings(cipher, compression), writeXml = failing, derive = d::derive, buffers = buffers) }
            if (thrown is CancellationException) assertThrows<CancellationException> { run() } else assertTrue(run() !is EncodeResult.Encoded)
            buffers.assertAllZero()
            d.assertZero()
        }
    }

    @ParameterizedTest
    @CsvSource("AES_256,GZIP", "AES_256,NONE", "CHACHA20,GZIP", "CHACHA20,NONE")
    fun `an OutOfMemoryError at any allocation leaves nothing behind`(cipher: String, compression: String) {
        val total = RecordingBuffers().also { EncoderRig.encode(settings(cipher, compression), buffers = it) }.byteSizes.size
        assertTrue(total > 5, "allocations: $total")
        for (failAt in 0 until total) {
            val recording = RecordingBuffers()
            val d = Derived()
            var n = 0
            val failing = object : Buffers {
                override fun bytes(size: Int): ByteArray {
                    if (n++ == failAt) throw OutOfMemoryError()
                    return recording.bytes(size)
                }
                override fun ints(size: Int) = recording.ints(size)
            }
            assertEquals(EncodeResult.NotEnoughMemory, EncoderRig.encode(settings(cipher, compression), derive = d::derive, buffers = failing), "allocation $failAt")
            recording.assertAllZero()
            d.assertZero()
        }
    }
}
