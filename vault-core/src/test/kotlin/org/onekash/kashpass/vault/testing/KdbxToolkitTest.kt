package org.onekash.kashpass.vault.testing

import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRead
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.kdbx.KdbxDamage
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.xml.XmlElement

class KdbxToolkitTest {

    private val password = TestFiles.password
    private val key = KdbxToolkit.Key(password)

    private fun fixture(name: String) = Fixtures.bytes(name)

    // The toolkit's files read by KashPass's own container, which shares no code with the toolkit.
    private fun decode(bytes: ByteArray): ContainerDecode.Result = ContainerRig.open(VaultFile("toolkit.kdbx", bytes))

    private fun owned(bytes: ByteArray): ContainerRead = assertIs<ContainerDecode.Result.Opened>(decode(bytes)).read

    // The value of every String named [key], history included, protected ones decrypted.
    private fun ContainerRead.values(key: String): Set<String> {
        fun all(e: XmlElement): List<XmlElement> = listOf(e) + e.elements().flatMap { all(it) }
        return all(xml.root).filter { it.name == "String" && it.child("Key")?.text() == key }
            .mapNotNull { it.child("Value") }.map { protectedValues[it]?.reveal() ?: it.text() }.toSet()
    }

    private fun ContainerRead.titles() = values("Title")

    private fun ContainerRead.passwords() = values("Password")

    @ParameterizedTest
    @ValueSource(strings = ["keepass2-weak-aeskdf-6000.kdbx", "keepass2-chacha20-argon2d.kdbx"])
    fun `rebuilding a KeePass 2 vault with no edits gives the same bytes`(name: String) {
        val bytes = fixture(name)
        assertContentEquals(bytes, KdbxToolkit.build(KdbxToolkit.open(bytes, key).layers))
    }

    @Test
    fun `an XML edit survives a decode`() {
        val layers = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key).layers
        val xml = String(layers.xml, Charsets.UTF_8).replace("<Value>Example Mail</Value>", "<Value>Edited Mail</Value>")
        val rebuilt = KdbxToolkit.build(layers.copy(xml = xml.toByteArray(Charsets.UTF_8)))
        val titles = owned(rebuilt).titles()
        assertTrue("Edited Mail" in titles && "Example Mail" !in titles, titles.toString())
    }

    @Test
    fun `a vault re-encrypted under ChaCha20 decodes with every protected value`() {
        val bytes = fixture("keepass2-weak-aeskdf-6000.kdbx")
        val layers = KdbxToolkit.open(bytes, key).layers
        val header = layers.header.withField(RawKdbx.CIPHER_ID, uuidBytes(KdbxToolkit.CHACHA20_CIPHER))
            .withField(RawKdbx.ENCRYPTION_IV, Random(1).nextBytes(12))
        val rebuilt = KdbxToolkit.build(layers.copy(header = header))
        assertEquals(owned(bytes).passwords(), owned(rebuilt).passwords())
    }

    @Test
    fun `37-byte blocks decode`() {
        val layers = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key).layers
        val rebuilt = KdbxToolkit.build(layers.copy(blockSize = 37))
        assertTrue(rebuilt.size > fixture("keepass2-weak-aeskdf-6000.kdbx").size + 30 * 36)
        assertEquals(owned(fixture("keepass2-weak-aeskdf-6000.kdbx")).titles(), owned(rebuilt).titles())
    }

    @Test
    fun `a forced end-block HMAC is written as given`() {
        val layers = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key).layers
        val bad = ByteArray(32) { 0x5A }
        val rebuilt = KdbxToolkit.build(
            layers.copy(editBlocks = { _, blocks -> blocks.dropLast(1) + KdbxToolkit.Block(bad, 0, ByteArray(0)) }),
        )
        assertContentEquals(bad + ByteArray(4), rebuilt.copyOfRange(rebuilt.size - 36, rebuilt.size))
        // The end block's HMAC is checked too.
        assertEquals(KdbxResult.Damaged(KdbxDamage.BLOCK_HMAC), assertIs<ContainerDecode.Result.Failed>(decode(rebuilt)).result)
    }

    @Test
    fun `an AES-KDF seed of 16 bytes derives with its SHA-256`() {
        val layers = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key).layers
        val seed = Random(2).nextBytes(16)
        val header = layers.header.withKdf { it.with("S", RawDictionary.BYTES, seed) }
        val rebuilt = KdbxToolkit.build(layers.copy(header = header))
        val reopened = KdbxToolkit.open(rebuilt, key)
        val aes = KdbxToolkit.effective(reopened.layers.header).kdf as KdbxToolkit.Kdf.Aes
        assertContentEquals(seed, aes.seed)
        assertContentEquals(
            KdbxToolkit.derive(KdbxToolkit.Kdf.Aes(6000UL, KdbxToolkit.sha256(seed)), key),
            reopened.transformedKey,
        )
        // KashPass hashes a seed that is not 32 bytes the same way, so it opens the file.
        assertEquals(owned(fixture("keepass2-weak-aeskdf-6000.kdbx")).titles(), owned(rebuilt).titles())
    }

    @Test
    fun `an element inside a comment, a processing instruction or CDATA is not a protected value`() {
        val layers = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key).layers
        val fake = "<Value Protected=\"True\">not*base64</Value>"
        val xml = String(layers.xml, Charsets.UTF_8).replaceFirst("<Generator>", "<!-- $fake --><?pi $fake ?><Generator>")
        val rebuilt = KdbxToolkit.build(layers.copy(xml = xml.toByteArray(Charsets.UTF_8)))
        val reopened = KdbxToolkit.open(rebuilt, key).layers
        assertEquals(layers.protectedValues.map { it.toList() }, reopened.protectedValues.map { it.toList() })
        assertTrue(fake in String(reopened.xml, Charsets.UTF_8), "the comment and the instruction are written as given")
        assertEquals(owned(fixture("keepass2-weak-aeskdf-6000.kdbx")).passwords(), owned(rebuilt).passwords())
    }

    @Test
    fun `a password with a lone surrogate keys as KeePass 2 encodes it, with U+FFFD`() {
        // SHA-256 of 61 EF BF BD; the same constant StoredKeyCompatibilityTest pins.
        val hash = java.util.HexFormat.of().parseHex("51d277510ba4bf97b25f12d38513c1b620a2a33fc83b3beeeb0dd971bf429e6d")
        assertContentEquals(KdbxToolkit.sha256(hash), KdbxToolkit.Key("a\uD800").composite())
    }

    @Test
    fun `the same edit with the same seed gives the same bytes`() {
        fun edit(): ByteArray {
            val layers = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key).layers
            val header = layers.header.withField(RawKdbx.ENCRYPTION_IV, Random(3).nextBytes(16))
            return KdbxToolkit.build(KdbxToolkit.withInnerStream(layers.copy(header = header), KdbxToolkit.SALSA20, Random(4).nextBytes(32)))
        }
        assertContentEquals(edit(), edit())
    }

    @Test
    fun `protected values re-encrypted with the ArcFour variant decrypt to the same text`() {
        val opened = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key)
        val rebuilt = KdbxToolkit.build(KdbxToolkit.withInnerStream(opened.layers, KdbxToolkit.ARCFOUR_VARIANT, Random(5).nextBytes(40)))
        val reopened = KdbxToolkit.open(rebuilt, key)
        assertEquals(opened.layers.protectedValues.map { it.toList() }, reopened.layers.protectedValues.map { it.toList() })
        assertTrue(!opened.layers.xml.contentEquals(reopened.layers.xml))
    }

    @Test
    fun `the toolkit reads the generated Salsa20 vault, and a Salsa20 stream the toolkit wrote decodes`() {
        val salsa = TestVaults.salsa20Vault()
        val opened = KdbxToolkit.open(salsa, KdbxToolkit.Key(TestVaults.PASSWORD))
        assertEquals(setOf("salsa-pass", "bänk-päss"), opened.layers.protectedValues.map { String(it, Charsets.UTF_8) }.toSet())

        val aes = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key)
        val rebuilt = KdbxToolkit.build(KdbxToolkit.withInnerStream(aes.layers, KdbxToolkit.SALSA20, Random(6).nextBytes(32)))
        assertEquals(owned(fixture("keepass2-weak-aeskdf-6000.kdbx")).passwords(), owned(rebuilt).passwords())
    }

    @Test
    fun `macs give the stored HMAC of every block, end block included`() {
        val opened = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key)
        val macs = KdbxToolkit.macs(opened.layers)
        opened.blocks.forEachIndexed { i, b -> assertContentEquals(b.hmac, macs.block(i.toLong(), b.data), "block $i") }
    }

    @ParameterizedTest
    @ValueSource(strings = ["keepass2-weak-aeskdf-6000.kdbx", "keepass2-chacha20-argon2d.kdbx", "keepass2-compression-none.kdbx"])
    fun `payload reads the decrypted layer before decompression`(name: String) {
        val bytes = fixture(name)
        val opened = KdbxToolkit.open(bytes, key)
        assertContentEquals(opened.compressedBytes ?: opened.contentBytes, KdbxToolkit.payload(bytes, key))
        assertContentEquals(opened.compressedBytes ?: opened.contentBytes, KdbxToolkit.payload(bytes, opened.transformedKey))
    }

    @Test
    fun `payload reads a file whose gzip data is broken`() {
        val opened = KdbxToolkit.open(fixture("keepass2-weak-aeskdf-6000.kdbx"), key)
        val broken = opened.compressedBytes!!.copyOf(opened.compressedBytes!!.size / 2)
        val rebuilt = KdbxToolkit.build(opened.layers.copy(compressed = broken))
        assertContentEquals(broken, KdbxToolkit.payload(rebuilt, key))
    }

    @Test
    fun `split gives the stored header bytes, hashes and blocks without a key`() {
        val bytes = fixture("keepass2-multiblock-attachment.kdbx")
        val split = KdbxToolkit.split(bytes)
        val opened = KdbxToolkit.open(bytes, key)
        assertEquals(opened.blocks.size, split.blocks.size)
        assertTrue(split.blocks.zip(opened.blocks).all { (a, b) -> a.hmac.contentEquals(b.hmac) && a.data.contentEquals(b.data) })
        assertContentEquals(KdbxToolkit.sha256(split.headerBytes), split.storedHash)
        assertEquals(0, split.afterEnd.size)
    }

    @ParameterizedTest
    @ValueSource(strings = ["keepass2-weak-aeskdf-6000.kdbx", "keepass2-chacha20-argon2d.kdbx"])
    fun `protectedCiphertexts match the protected values in count and size`(name: String) {
        val layers = KdbxToolkit.open(fixture(name), key).layers
        val stored = KdbxToolkit.protectedCiphertexts(layers.xml)
        assertTrue(stored.isNotEmpty())
        assertEquals(layers.protectedValues.map { it.size }, stored.map { it.size })
    }
}
