package org.onekash.kashpass.vault.kdbx

import java.util.concurrent.CancellationException
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.kdbx.KdbxDecoder.Step
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.xml.XmlElement

class KdbxDecoderTest {

    private fun open(name: String): Pair<ByteArray, KdbxToolkit.Opened> {
        val bytes = Fixtures.bytes(name)
        return bytes to KdbxToolkit.open(bytes, DecoderRig.key(Fixtures.file(Fixtures.named(name))))
    }

    @ParameterizedTest
    @ValueSource(strings = ["keepass2-weak-aeskdf-6000.kdbx", "keepass2-chacha20-argon2d.kdbx", "keepass2-compression-none.kdbx", "keepass2-shared-attachments.kdbx"])
    fun `a fixture decodes to the toolkit's inner header and XML`(name: String) {
        val (bytes, toolkit) = open(name)
        val opened = assertIs<KdbxResult.Opened>(DecoderRig.decode(bytes, { toolkit.transformedKey.copyOf() }))
        val p = opened.plaintext
        assertContentEquals(toolkit.layers.xml, p.buffer.copyOfRange(p.xmlOffset, p.xmlOffset + p.xmlLength))
        val inner = toolkit.layers.inner
        val binaries = inner.filter { it.id == KdbxToolkit.INNER_BINARY }
        assertEquals(binaries.size, opened.container.inner.attachments.size)
        binaries.zip(opened.container.inner.attachments).forEach { (raw, a) ->
            assertEquals(raw.data[0].toInt() and 1 != 0, a.protected)
            assertContentEquals(raw.data.copyOfRange(1, raw.data.size), a.data)
        }
        assertContentEquals(inner.last { it.id == KdbxToolkit.INNER_STREAM_KEY }.data, opened.container.inner.streamKey)
        assertFalse(opened.container.bytesAfterEnd)
        p.close()
    }

    // KdbxToolkit reads with JCA and its own stream ciphers and gzip, so it shares no container
    // code with KdbxDecoder; for Argon2 both derive through KdfEngine.
    @Test
    fun `every KDBX 4 fixture that opens decodes to the toolkit's XML, attachments and protected values`() {
        for (fixture in Fixtures.kdbx4Opening) {
            val file = Fixtures.file(fixture)
            val toolkit = KdbxToolkit.open(file.bytes, DecoderRig.key(file))
            var xml: ByteArray? = null
            val read = assertIs<ContainerDecode.Result.Opened>(ContainerRig.open(file, onXml = { b, off, len -> xml = b.copyOfRange(off, off + len) }), fixture.name).read
            assertContentEquals(toolkit.layers.xml, xml, fixture.name)
            val binaries = toolkit.layers.inner.filter { it.id == KdbxToolkit.INNER_BINARY }
            assertEquals(binaries.size, read.pool.size, fixture.name)
            binaries.zip(read.pool.values).forEach { (raw, a) ->
                assertEquals(raw.data[0].toInt() and 1 != 0, a.protected, fixture.name)
                assertContentEquals(raw.data.copyOfRange(1, raw.data.size), a.data, fixture.name)
            }
            val owned = documentOrder(read.xml.root).mapNotNull { read.protectedValues[it]?.utf8() }
            assertEquals(toolkit.layers.protectedValues.map { it.toList() }, owned.map { it.toList() }, fixture.name)
            assertTrue(owned.isNotEmpty() || fixture.name == Fixtures.DESKTOP, "${fixture.name} has protected values")
        }
    }

    private fun documentOrder(e: XmlElement): List<XmlElement> = listOf(e) + e.elements().flatMap { documentOrder(it) }

    @Test
    fun `the steps run in order and stop at the first failure`() {
        val (bytes, toolkit) = open("keepass2-weak-aeskdf-6000.kdbx")
        fun steps(file: ByteArray, key: ByteArray = toolkit.transformedKey): Pair<KdbxResult, List<Step>> {
            val seen = mutableListOf<Step>()
            return DecoderRig.decode(file, { key.copyOf() }, step = { seen += it }) to seen
        }
        val all = listOf(Step.HEADER_HASH, Step.DERIVE, Step.HEADER_MAC, Step.BLOCKS, Step.DECRYPT, Step.INFLATE, Step.INNER_HEADER)
        assertEquals(all, steps(bytes).second)
        val length = RawKdbx.parse(bytes).headerBytes().size
        val badHash = bytes.copyOf().also { it[length] = (it[length] + 1).toByte() }
        assertEquals(KdbxResult.Damaged(KdbxDamage.HEADER_HASH) to listOf(Step.HEADER_HASH), steps(badHash))
        assertEquals(KdbxResult.WrongKey to all.take(3), steps(bytes, ByteArray(32)))
        val badBlock = bytes.copyOf().also { it[length + 64 + 40] = (it[length + 64 + 40] + 1).toByte() }
        assertEquals(KdbxResult.Damaged(KdbxDamage.BLOCK_HMAC) to all.take(4), steps(badBlock))
    }

    @Test
    fun `a wrong key derives once and decrypts nothing`() {
        val (bytes, _) = open("keepass2-weak-aeskdf-6000.kdbx")
        var derived = 0
        val buffers = org.onekash.kashpass.vault.testing.RecordingBuffers()
        val result = DecoderRig.decode(bytes, { derived++; ByteArray(32) }, buffers)
        assertEquals(KdbxResult.WrongKey, result)
        assertEquals(1, derived)
        // Only the header hash and the key schedule were allocated: no ciphertext buffer.
        assertTrue(buffers.byteSizes.all { it <= 64 }, buffers.byteSizes.toString())
    }

    @Test
    fun `failures of the KDF map to their outcome and nothing else escapes`() {
        val (bytes, _) = open("keepass2-weak-aeskdf-6000.kdbx")
        assertEquals(KdbxResult.NotEnoughMemory(MemoryCause.OUT_OF_MEMORY), DecoderRig.decode(bytes, { throw OutOfMemoryError() }))
        assertEquals(KdbxResult.Failed(FailureCause.PLATFORM), DecoderRig.decode(bytes, { throw KdbxException.AlgorithmUnavailable() }))
        assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), DecoderRig.decode(bytes, { throw KdbxException.KdfParametersInvalid() }))
        assertEquals(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT), DecoderRig.decode(bytes, { throw KdbxException.DerivationTooLarge() }))
        assertEquals(KdbxResult.Failed(FailureCause.INTERNAL), DecoderRig.decode(bytes, { throw IllegalStateException() }))
        assertEquals(KdbxResult.Failed(FailureCause.INTERNAL), DecoderRig.decode(bytes, { throw StackOverflowError() }))
        assertEquals(KdbxResult.Failed(FailureCause.INTERNAL), DecoderRig.decode(bytes, { ByteArray(31) }))
        assertThrows<CancellationException> { DecoderRig.decode(bytes, { throw CancellationException() }) }
    }

    @Test
    fun `a decompression over the limit is not enough memory`() {
        val (bytes, toolkit) = open("keepass2-weak-aeskdf-6000.kdbx")
        assertEquals(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT), DecoderRig.decode(bytes, { toolkit.transformedKey.copyOf() }, limit = 100))
    }

    @Test
    fun `the decoder's result for every corpus case it reaches agrees with the case's spec`() {
        val wrong = mutableListOf<String>()
        var decided = 0
        for (c in Corpus.all) {
            if (c.spec == Spec.REFUSED_BY_POLICY) continue
            val r = DecoderRig.decode(c) ?: continue
            decided++
            val ok = when (r) {
                is KdbxResult.Opened -> {
                    r.plaintext.close()
                    // Cases whose outcome the XML sets (damage, Meta/Binaries over the budget) are
                    // checked with the XML hand-off.
                    c.spec in setOf(Spec.OPENS, Spec.OPENS_READ_ONLY, Spec.DAMAGED, Spec.NOT_ENOUGH_MEMORY)
                }
                KdbxResult.WrongKey -> c.spec == Spec.WRONG_KEY
                is KdbxResult.Damaged -> c.spec == Spec.DAMAGED
                is KdbxResult.Unsupported -> c.spec == Spec.UNSUPPORTED
                is KdbxResult.NotEnoughMemory -> c.spec == Spec.NOT_ENOUGH_MEMORY
                is KdbxResult.TooLarge, is KdbxResult.Failed -> false
            }
            if (!ok) wrong += "${c.name}: decoder $r, spec ${c.spec}"
        }
        assertTrue(decided > 2_000, "$decided cases decided")
        assertTrue(wrong.isEmpty(), wrong.joinToString("\n"))
    }

    @Test
    fun `every DAMAGED corpus case the decoder opens is damaged in its XML`() {
        val opened = Corpus.all.filter { it.spec == Spec.DAMAGED }.filter { (DecoderRig.decode(it) as? KdbxResult.Opened)?.also { o -> o.plaintext.close() } != null }
        val xmlLayers = setOf("XML", "PROTECTED_VALUE", "DATE", "XML_HEADER_HASH", "META_BINARY")
        assertEquals(emptyList(), opened.filter { it.damage !in xmlLayers }.map { "${it.name}: ${it.damage}" })
    }
}
