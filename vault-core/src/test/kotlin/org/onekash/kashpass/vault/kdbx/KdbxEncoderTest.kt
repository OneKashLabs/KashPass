package org.onekash.kashpass.vault.kdbx

import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.CancellationException
import java.util.stream.Stream
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawKdbx

/**
 * The encoder writes files that KashPass's decoder and the test toolkit open to the same inner
 * header, attachments and XML, runs its steps in order, and reports each failure as one result.
 */
internal class KdbxEncoderTest {

    private class Opened(val result: KdbxResult.Opened, val bytes: ByteArray) {
        val inner get() = result.container.inner
        val xml get() = result.plaintext.buffer.copyOfRange(result.plaintext.xmlOffset, result.plaintext.xmlOffset + result.plaintext.xmlLength)
    }

    private fun decode(bytes: ByteArray): Opened {
        val header = assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(bytes)).header
        val result = KdbxDecoder.decode(bytes, header, EncoderRig.composite, EncoderRig::derive, 64 shl 20)
        return Opened(assertIs<KdbxResult.Opened>(result), bytes)
    }

    private fun encoded(result: EncodeResult): ByteArray = assertIs<EncodeResult.Encoded>(result).bytes

    // Reads the protected password of [xml] with the inner stream of [inner].
    private fun secretOf(xml: ByteArray, inner: InnerHeader): String {
        val text = xml.decodeToString()
        val value = Regex("Protected=\"True\">([^<]*)<").find(text)!!.groupValues[1]
        val bytes = Base64.getDecoder().decode(value)
        InnerStream.open(inner.streamId, inner.streamKey).use { it.xor(bytes, 0, bytes.size) }
        return bytes.decodeToString()
    }

    @ParameterizedTest(name = "{0} {1} {2}")
    @MethodSource("grid")
    fun `KashPass's decoder opens what the encoder wrote to the same inner header, attachments and XML`(cipher: OuterCipher, compression: Compression, kdfName: String) {
        val kdf = kdfs.getValue(kdfName)
        val settings = EncoderRig.settings(cipher, compression, kdf)
        var xml: ByteArray? = null
        val bytes = encoded(EncoderRig.encode(settings, EncoderRig.writer({ xml = it })))
        val opened = decode(bytes)

        assertEquals(cipher, opened.result.container.header.cipher)
        assertEquals(compression, opened.result.container.header.compression)
        assertEquals(KdfUuid.of(kdf), KdfUuid.of(opened.result.container.header.kdf))
        assertKdfEquals(kdf, opened.result.container.header.kdf, withSalt = false)
        assertFalse(opened.result.container.bytesAfterEnd, "bytes after the end block")
        assertEquals(0, KdbxToolkit.split(bytes).afterEnd.size)
        assertEquals(InnerStream.CHACHA20, opened.inner.streamId)
        assertEquals(64, opened.inner.streamKey.size)
        assertEquals(EncoderRig.attachments.map { it.protected }, opened.inner.attachments.map { it.protected })
        assertEquals(EncoderRig.attachments.map { it.data.toList() }, opened.inner.attachments.map { it.data.toList() })
        assertContentEquals(xml, opened.xml)
        assertEquals(EncoderRig.SECRET, secretOf(opened.xml, opened.inner))
    }

    // KdbxToolkit shares no container code with KdbxDecoder, so a fault the encoder and decoder
    // share shows here.
    @ParameterizedTest(name = "{0} {1} {2}")
    @MethodSource("grid")
    fun `the toolkit opens every file the encoder wrote to the XML and attachments encoded`(cipher: OuterCipher, compression: Compression, kdfName: String) {
        var xml: ByteArray? = null
        val bytes = encoded(EncoderRig.encode(EncoderRig.settings(cipher, compression, kdfs.getValue(kdfName)), EncoderRig.writer({ xml = it })))
        val toolkit = KdbxToolkit.open(bytes, KdbxToolkit.Key(EncoderRig.PASSWORD))
        assertContentEquals(xml, toolkit.layers.xml)
        val binaries = toolkit.layers.inner.filter { it.id == KdbxToolkit.INNER_BINARY }
        assertEquals(EncoderRig.attachments.map { it.protected }, binaries.map { it.data[0].toInt() and 1 != 0 })
        assertEquals(EncoderRig.attachments.map { it.data.toList() }, binaries.map { it.data.copyOfRange(1, it.data.size).toList() })
        assertEquals(listOf(EncoderRig.SECRET), toolkit.layers.protectedValues.map { it.decodeToString() })
    }

    @Test
    fun `a payload over one block size is written as several blocks and reads back`() {
        val big = ByteArray(BlockStreamWriter.BLOCK_SIZE * 3 / 2).also { kotlin.random.Random(7).nextBytes(it) }
        val attachments = listOf(Attachment(true, big))
        val bytes = encoded(EncoderRig.encode(EncoderRig.settings(OuterCipher.AES_256, Compression.NONE, EncoderRig.aesKdf), attachments = attachments))
        val split = KdbxToolkit.split(bytes)
        assertEquals(3, split.blocks.size, "two data blocks and the end block")
        assertContentEquals(big, decode(bytes).inner.attachments.single().data)
    }

    @Test
    fun `a fixture's settings save with a real AES-KDF derivation and reopen`() {
        val name = "keepass2-weak-aeskdf-6000.kdbx"
        val opened = openedHeader(RawKdbx.parse(Fixtures.bytes(name)))
        val bytes = encoded(EncoderRig.encode(SaveSettings.from(opened)))
        val reopened = decode(bytes)
        assertKdfEquals(opened.kdf, reopened.result.container.header.kdf, withSalt = false)
        assertEquals(EncoderRig.SECRET, secretOf(reopened.xml, reopened.inner))
    }

    @Test
    fun `the steps run in order, compression only when the settings say so`() {
        val all = KdbxEncoder.Step.entries
        for (compression in Compression.entries) {
            val steps = mutableListOf<KdbxEncoder.Step>()
            encoded(EncoderRig.encode(EncoderRig.settings(OuterCipher.AES_256, compression, EncoderRig.aesKdf), step = { steps += it }))
            val expected = if (compression == Compression.GZIP) all else all - KdbxEncoder.Step.COMPRESS
            assertEquals(expected, steps, "$compression")
        }
    }

    @Test
    fun `the KDF check and the KDF see the parameters the written header holds`() {
        var checked: KdfParameters? = null
        var derived: KdfParameters? = null
        val bytes = encoded(
            EncoderRig.encode(
                EncoderRig.settings(OuterCipher.CHACHA20, Compression.GZIP, EncoderRig.argon2id),
                kdfAllowed = { checked = it; true },
                derive = { p, c -> derived = p; EncoderRig.derive(p, c) },
            ),
        )
        assertSame(checked, derived)
        val header = assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(bytes)).header
        assertKdfEquals(header.kdf, checked!!, withSalt = true)
    }

    @Test
    fun `the inner stream key is the save's fourth random draw, after the master seed, IV and salt`() {
        var draws = 0
        val numbered = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                draws++
                bytes.fill(draws.toByte())
            }
        }
        val bytes = encoded(EncoderRig.encode(EncoderRig.settings(OuterCipher.AES_256, Compression.GZIP, EncoderRig.aesKdf), random = numbered))
        assertEquals(4, draws)
        val opened = decode(bytes)
        assertContentEquals(ByteArray(32) { 1 }, opened.result.container.header.masterSeed)
        assertContentEquals(ByteArray(64) { 4 }, opened.inner.streamKey)
    }

    @Test
    fun `a refused KDF derives nothing and writes no payload`() {
        val steps = mutableListOf<KdbxEncoder.Step>()
        var derived = false
        var wrote = false
        val result = EncoderRig.encode(
            EncoderRig.settings(OuterCipher.AES_256, Compression.GZIP, EncoderRig.aesKdf),
            writeXml = { wrote = true },
            kdfAllowed = { false },
            derive = { _, _ -> derived = true; ByteArray(32) },
            step = { steps += it },
        )
        assertEquals(EncodeResult.Refused, result)
        assertFalse(derived)
        assertFalse(wrote)
        assertEquals(listOf(KdbxEncoder.Step.HEADER, KdbxEncoder.Step.KDF_ALLOWED), steps)
    }

    @Test
    fun `an exception from the KDF is handed back as it was thrown`() {
        val thrown = IllegalStateException()
        val result = EncoderRig.encode(EncoderRig.settings(OuterCipher.AES_256, Compression.GZIP, EncoderRig.aesKdf), derive = { _, _ -> throw thrown })
        assertSame(thrown, assertIs<EncodeResult.DeriveFailed>(result).cause)
    }

    @Test
    fun `an OutOfMemoryError from the KDF is not enough memory`() {
        val result = EncoderRig.encode(EncoderRig.settings(OuterCipher.AES_256, Compression.GZIP, EncoderRig.argon2d), derive = { _, _ -> throw OutOfMemoryError() })
        assertEquals(EncodeResult.NotEnoughMemory, result)
    }

    @Test
    fun `an OutOfMemoryError from an allocation is not enough memory`() {
        val failing = object : Buffers {
            override fun bytes(size: Int): ByteArray = throw OutOfMemoryError()
            override fun ints(size: Int) = IntArray(size)
        }
        val result = EncoderRig.encode(EncoderRig.settings(OuterCipher.AES_256, Compression.GZIP, EncoderRig.aesKdf), buffers = failing)
        assertEquals(EncodeResult.NotEnoughMemory, result)
    }

    @Test
    fun `a CancellationException from the KDF or the XML writer is rethrown`() {
        val settings = EncoderRig.settings(OuterCipher.AES_256, Compression.GZIP, EncoderRig.aesKdf)
        assertThrows<CancellationException> { EncoderRig.encode(settings, derive = { _, _ -> throw CancellationException() }) }
        assertThrows<CancellationException> { EncoderRig.encode(settings, writeXml = { throw CancellationException() }) }
    }

    @Test
    fun `a payload larger than an array can hold is not enough memory`() {
        val chunk = ByteArray(1 shl 24)
        val result = EncoderRig.encode(EncoderRig.settings(OuterCipher.AES_256, Compression.NONE, EncoderRig.aesKdf), attachments = List(128) { Attachment(false, chunk) })
        assertEquals(EncodeResult.NotEnoughMemory, result)
    }

    @Test
    fun `a platform failure is reported as one`() {
        val result = EncoderRig.encode(EncoderRig.settings(OuterCipher.AES_256, Compression.GZIP, EncoderRig.aesKdf), writeXml = { throw KdbxException.AlgorithmUnavailable() })
        assertEquals(EncodeResult.Failed(FailureCause.PLATFORM), result)
    }

    @Test
    fun `a caller that breaks the payload sink's contract gets an internal failure`() {
        val settings = EncoderRig.settings(OuterCipher.CHACHA20, Compression.NONE, EncoderRig.aesKdf)
        val internal = EncodeResult.Failed(FailureCause.INTERNAL)
        assertEquals(internal, EncoderRig.encode(settings, writeXml = {}), "nothing handed over")
        assertEquals(internal, EncoderRig.encode(settings, writeXml = { p -> p.handOver(ByteArray(4096), 200) }), "an array the sink did not allocate")
        assertEquals(
            internal,
            EncoderRig.encode(settings, writeXml = { p -> p.allocate(4096).let { p.handOver(it, 200) } }),
            "no inner header first",
        )
        assertEquals(internal, EncoderRig.encode(settings, writeXml = { p -> p.release(ByteArray(16)) }), "releasing an array the sink did not allocate")
        assertEquals(
            internal,
            EncoderRig.encode(settings, writeXml = { p -> p.allocate(4096).let { p.release(it); p.handOver(it, 4096) } }),
            "handing over a released array",
        )
        var kept: PayloadSink? = null
        encoded(EncoderRig.encode(settings, writeXml = { p -> kept = p; EncoderRig.writer()(p) }))
        assertThrows<KdbxException.Closed> { kept!!.allocate(16) }
        assertThrows<KdbxException.Closed> { kept!!.release(ByteArray(16)) }
        assertThrows<KdbxException.Closed> { kept!!.keystream.xor(ByteArray(1), 0, 1) }
    }

    @Test
    fun `a minor version the header cannot hold is an internal failure`() {
        val result = EncoderRig.encode(EncoderRig.settings(OuterCipher.AES_256, Compression.GZIP, EncoderRig.aesKdf), minor = 0x10000)
        assertEquals(EncodeResult.Failed(FailureCause.INTERNAL), result)
    }

    @Test
    fun `an AES payload that fills its array to the end gains room for the padding`() {
        val settings = EncoderRig.settings(OuterCipher.AES_256, Compression.NONE, EncoderRig.aesKdf)
        var xml: ByteArray? = null
        val bytes = encoded(
            EncoderRig.encode(settings, writeXml = { payload ->
                var inner = ByteArray(0)
                payload.writeInnerHeader { b, o, l -> inner += b.copyOfRange(o, o + l) }
                val content = EncoderRig.xml(payload.keystream).also { xml = it }
                val exact = payload.allocate(inner.size + content.size)
                inner.copyInto(exact)
                content.copyInto(exact, inner.size)
                payload.handOver(exact, exact.size)
            }),
        )
        assertContentEquals(xml, decode(bytes).xml)
    }

    companion object {
        private val kdfs = mapOf("AES-KDF" to EncoderRig.aesKdf, "Argon2d" to EncoderRig.argon2d, "Argon2id" to EncoderRig.argon2id)

        @JvmStatic
        fun grid(): Stream<Arguments> = Stream.of(
            *OuterCipher.entries.flatMap { cipher ->
                Compression.entries.flatMap { compression ->
                    kdfs.keys.map { Arguments.of(cipher, compression, it) }
                }
            }.toTypedArray(),
        )
    }
}
