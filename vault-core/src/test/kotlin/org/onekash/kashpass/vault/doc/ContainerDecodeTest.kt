package org.onekash.kashpass.vault.doc

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.CorpusCase
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.kdbx.FailureCause
import org.onekash.kashpass.vault.kdbx.KdbxDamage
import org.onekash.kashpass.vault.kdbx.KdbxException
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.kdbx.KdfParameters
import org.onekash.kashpass.vault.kdbx.MemoryCause
import org.onekash.kashpass.vault.policy.KdfPolicy
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.policy.KdfSetting
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.RecordingBuffers
import org.onekash.kashpass.vault.testing.u32
import org.onekash.kashpass.vault.testing.u64
import org.onekash.kashpass.vault.xml.XmlBytes
import org.onekash.kashpass.vault.xml.XmlElement

class ContainerDecodeTest {

    private fun opened(r: ContainerDecode.Result): ContainerRead = assertIs<ContainerDecode.Result.Opened>(r).read

    private fun case(name: String): CorpusCase = Corpus.all.single { it.name == name }

    private fun documentOrder(root: XmlElement): List<XmlElement> {
        val out = mutableListOf<XmlElement>()
        fun walk(e: XmlElement) {
            out += e
            e.elements().forEach(::walk)
        }
        walk(root)
        return out
    }

    // KdbxDecoderTest compares each fixture's protected values with the toolkit's.
    @ParameterizedTest
    @MethodSource("fixtures")
    fun `every KDBX 4 fixture opens and zero-fills its inner stream key`(name: String) {
        val read = opened(ContainerRig.open(Fixtures.file(Fixtures.named(name))))
        assertTrue(read.protectedValues.isNotEmpty() || name == Fixtures.DESKTOP, name)
        assertTrue(read.container.inner.streamKey.all { it.toInt() == 0 }, "the stream key is zero-filled")
    }

    @Test
    fun `the Argon2 0x12 fixture is refused by the KDF policy before any derivation`() {
        var derived = false
        val file = Fixtures.file(Fixtures.named("keepass2-argon2-version-0x12.kdbx"))
        val r = ContainerDecode.decode(file.bytes, ContainerRig.passwordHash(file), null, ContainerRig.LIMITS, Int.MAX_VALUE, derive = { _, _ -> derived = true; ByteArray(32) })
        assertEquals(KdfRejection.OutOfBounds(KdfSetting.ARGON2_VERSION, 0x12UL), assertIs<ContainerDecode.Result.Refused>(r).rejection)
        assertTrue(!derived)
    }

    @Test
    fun `the KDF policy sees the parameters the KDF derives with, for every fold ordering`() {
        val cases = Corpus.all.filter { it.name.startsWith("kdbx3-") || Regex("""^kdf-.*-then-""").containsMatchIn(it.name) }
        assertTrue(cases.size >= 15)
        for (c in cases) {
            val file = c.file()
            val seen = mutableListOf<KdfSettings>()
            val given = mutableListOf<KdfParameters>()
            ContainerDecode.decode(
                file.bytes, ContainerRig.passwordHash(file), TestFiles.keyFilePart(file), ContainerRig.LIMITS, Int.MAX_VALUE,
                kdfPolicy = { seen += it; KdfPolicy.checkBounds(it) },
                derive = { p, k -> given += p; ContainerRig.derive(p, k) },
            )
            assertTrue(seen.size <= 1 && given.size <= 1, c.name)
            if (given.isNotEmpty()) assertEquals(seen.single(), given.single().toSettings(), c.name)
        }
    }

    @Test
    fun `Meta Binaries items join the pool by ID and leave the tree`() {
        val replaced = opened(ContainerRig.open(case("spec-meta-binary-replaces-0")))
        assertContentEquals("replaced codes".toByteArray(), replaced.pool.getValue(0).data)
        assertEquals(setOf(0), replaced.pool.keys)
        assertNull(replaced.xml.root.child("Meta")!!.child("Binaries"))
        val sparse = opened(ContainerRig.open(case("spec-meta-binary-sparse-id")))
        assertEquals(setOf(0, 5), sparse.pool.keys)
        assertEquals(setOf(0, Int.MAX_VALUE), opened(ContainerRig.open(case("spec-meta-binary-id-max"))).pool.keys)
        val compressed = opened(ContainerRig.open(case("spec-meta-binary-compressed")))
        assertContentEquals("third item".toByteArray(), compressed.pool.getValue(1).data)
        val protectedItem = opened(ContainerRig.open(case("spec-meta-binary-protected-compressed")))
        assertContentEquals("third item".toByteArray(), protectedItem.pool.getValue(1).data)
        assertTrue(protectedItem.pool.getValue(1).protected)
        assertTrue(protectedItem.protectedValues.keys.none { it.name == "Binary" })
    }

    @Test
    fun `the KDF's failures map to their outcome`() {
        val file = Fixtures.file(Fixtures.named("keepass2-weak-aeskdf-6000.kdbx"))
        fun with(e: Throwable) = ContainerDecode.decode(file.bytes, ContainerRig.passwordHash(file), null, ContainerRig.LIMITS, Int.MAX_VALUE, derive = { _, _ -> throw e })
        val rejection = KdfRejection.OutOfBounds(KdfSetting.AES_ROUNDS, 0UL)
        assertEquals(ContainerDecode.Result.Refused(rejection), with(KdfOutOfBoundsException(rejection)))
        assertEquals(ContainerDecode.Result.Failed(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS)), with(KdfSaltException()))
        assertEquals(ContainerDecode.Result.Failed(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT)), with(KdfTooLargeException()))
        assertEquals(ContainerDecode.Result.Failed(KdbxResult.Failed(FailureCause.PLATFORM)), with(KdbxException.AlgorithmUnavailable()))
        assertEquals(ContainerDecode.Result.Failed(KdbxResult.Failed(FailureCause.INTERNAL)), with(IllegalStateException("test")))
    }

    @Test
    fun `a document that is not a KeePass file is damaged, XML over the limit is not enough memory`() {
        val file = Fixtures.file(Fixtures.named("keepass2-compression-none.kdbx"))
        val layers = KdbxToolkit.open(file.bytes, KdbxToolkit.Key(TestFiles.password)).layers
        val other = KdbxToolkit.build(layers.copy(xml = "<Other><Root><Group/></Root></Other>".toByteArray(), protectedValues = emptyList()))
        val open = { bytes: ByteArray, limits: VaultXmlCodec.Limits ->
            ContainerDecode.decode(bytes, ContainerRig.passwordHash(file), null, limits, Int.MAX_VALUE, derive = ContainerRig.derive)
        }
        assertEquals(ContainerDecode.Result.Failed(KdbxResult.Damaged(KdbxDamage.XML)), open(other, ContainerRig.LIMITS))
        assertEquals(ContainerDecode.Result.Failed(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT)), open(file.bytes, VaultXmlCodec.Limits(open = 1_000, save = 1_000)))
    }

    @Test
    fun `the XML cap and the decompression budget are separate limits, each exact`() {
        val file = Fixtures.file(Fixtures.named("keepass2-weak-aeskdf-6000.kdbx"))
        val open = { limits: VaultXmlCodec.Limits, onXml: (ByteArray, Int, Int) -> Unit ->
            ContainerDecode.decode(file.bytes, ContainerRig.passwordHash(file), null, limits, Int.MAX_VALUE, derive = ContainerRig.derive, onXml = onXml)
        }
        var xml = 0
        var payload = 0
        assertIs<ContainerDecode.Result.Opened>(open(ContainerRig.LIMITS) { _, offset, length -> xml = length; payload = offset + length }).read.zeroFill()
        assertTrue(payload > xml)
        val limit = ContainerDecode.Result.Failed(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT))
        assertIs<ContainerDecode.Result.Opened>(open(VaultXmlCodec.Limits(open = xml, save = 0, decompression = payload)) { _, _, _ -> }).read.zeroFill()
        assertEquals(limit, open(VaultXmlCodec.Limits(open = xml - 1, save = 0, decompression = 1 shl 24)) { _, _, _ -> })
        assertEquals(limit, open(VaultXmlCodec.Limits(open = 1 shl 24, save = 0, decompression = payload - 1)) { _, _, _ -> })
    }

    @Test
    fun `the composite key is zero-filled after the derivation`() {
        val file = Fixtures.file(Fixtures.named("keepass2-weak-aeskdf-6000.kdbx"))
        var given: ByteArray? = null
        val r = ContainerDecode.decode(file.bytes, ContainerRig.passwordHash(file), null, ContainerRig.LIMITS, Int.MAX_VALUE, derive = { p, k -> given = k; ContainerRig.derive(p, k.copyOf()) })
        assertIs<ContainerDecode.Result.Opened>(r)
        assertTrue(given!!.all { it.toInt() == 0 })
    }

    @Test
    fun `Argon2 memory above half the heap is not enough memory before any derivation`() {
        val file = Fixtures.file(Fixtures.named("keepass2-argon2id.kdbx"))
        var derived = false
        val r = ContainerDecode.decode(file.bytes, ContainerRig.passwordHash(file), null, ContainerRig.LIMITS, Int.MAX_VALUE, maxHeapBytes = 100L * 1024 * 1024, derive = { _, _ -> derived = true; ByteArray(32) })
        assertEquals(ContainerDecode.Result.Failed(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT)), r)
        assertTrue(!derived)
    }

    @Test
    fun `the heap guard counts the memory Argon2 uses, 8 KiB per lane at least`() {
        val file = Fixtures.file(Fixtures.named("keepass2-argon2id.kdbx"))
        // 8 KiB stated on 25,600 lanes: 200 MiB used, above half of a 256 MiB heap.
        val bytes = RawKdbx.parse(file.bytes).withKdf { it.with("M", RawDictionary.UINT64, u64(8_192UL)).with("P", RawDictionary.UINT32, u32(25_600)) }.toBytes()
        var derived = false
        val r = ContainerDecode.decode(bytes, ContainerRig.passwordHash(file), null, ContainerRig.LIMITS, Int.MAX_VALUE, maxHeapBytes = 256L * 1024 * 1024, derive = { _, _ -> derived = true; ByteArray(32) })
        assertEquals(ContainerDecode.Result.Failed(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT)), r)
        assertTrue(!derived)
    }

    @Test
    fun `a reference keeps the item it named when read, as KeePass 2 resolves it`() {
        val read = opened(ContainerRig.open(case("spec-meta-binary-after-root-replaces-0").file()))
        assertContentEquals("replaced codes".toByteArray(), read.pool.getValue(0).data)
        val named = read.references.values.filterNotNull().distinct().single()
        assertTrue(named !== read.pool.getValue(0))
        assertEquals(20, named.data.size)
        assertTrue(named.data.any { it.toInt() != 0 }, "the item a reference holds is not zero-filled")
        val newId = opened(ContainerRig.open(case("spec-meta-binary-after-root-new-id").file()))
        assertTrue(newId.references.entries.single { it.key.attribute("Ref") == "5" }.value == null)
    }

    @Test
    fun `an attachment a Meta Binaries item replaces is zero-filled`() {
        val buffers = RecordingBuffers()
        val read = opened(ContainerRig.open(case("spec-meta-binary-replaces-0").file(), buffers = buffers))
        buffers.assertAllZeroExcept(read.xml.source.bytes, *read.pool.values.map { it.data }.toTypedArray())
        assertTrue(buffers.byteSizes.isNotEmpty())
    }

    @Test
    fun `a file over the read limit is too large and nothing is read from it`() {
        val file = Fixtures.file(Fixtures.named("keepass2-weak-aeskdf-6000.kdbx"))
        val r = ContainerDecode.decode(file.bytes, ContainerRig.passwordHash(file), null, ContainerRig.LIMITS, file.bytes.size - 1, derive = { _, _ -> error("derived") })
        assertEquals(ContainerDecode.Result.Failed(KdbxResult.TooLarge(file.bytes.size - 1)), r)
    }

    @Test
    fun `after an open only the attachments and the tree's XML hold data, after a failure nothing does`() {
        val buffers = RecordingBuffers()
        val read = opened(ContainerRig.open(Fixtures.file(Fixtures.named("keepass2-shared-attachments.kdbx")), buffers = buffers))
        buffers.assertAllZeroExcept(read.xml.source.bytes, *read.pool.values.map { it.data }.toTypedArray())
        for (name in listOf("spec-date-iso", "spec-inner-protected-not-base64", "spec-meta-binary-id-negative", "xml-header-hash-wrong")) {
            val failing = RecordingBuffers()
            assertIs<ContainerDecode.Result.Failed>(ContainerRig.open(case(name).file(), buffers = failing), name)
            failing.assertAllZero()
        }
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    fun `the payload is zero-filled after decode and the unedited tree writes its own copy of the XML byte for byte`(name: String) {
        val file = Fixtures.file(Fixtures.named(name))
        var payload: ByteArray? = null
        var xml: ByteArray? = null
        val read = opened(
            ContainerRig.open(file) { b, off, len ->
                payload = b
                xml = b.copyOfRange(off, off + len)
            },
        )
        assertTrue(payload!!.all { it.toInt() == 0 }, "the payload buffer is zero-filled")
        assertTrue(read.xml.source.bytes !== payload, "the tree owns its own array")
        assertContentEquals(xml, read.xml.source.bytes)
        assertContentEquals(xml, XmlBytes.write(read.xml))
    }

    companion object {
        @JvmStatic
        fun fixtures(): List<String> = Fixtures.kdbx4Opening.map { it.name }
    }
}
