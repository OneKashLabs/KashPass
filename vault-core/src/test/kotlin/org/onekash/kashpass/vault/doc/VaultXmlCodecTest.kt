package org.onekash.kashpass.vault.doc

import java.security.MessageDigest
import java.util.stream.Stream
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.header.HeaderResult
import org.onekash.kashpass.vault.header.KdbxHeaderParser
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.xml.XmlBytes
import org.onekash.kashpass.vault.xml.XmlElement

class VaultXmlCodecTest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("vaults")
    fun `saving without edits keeps the decrypted XML, protected values re-encrypted`(name: String, bytes: ByteArray, password: String) {
        val read = decode(bytes, password)
        val saved = decode(VaultXmlCodec.encodeBytes(read), password)
        assertEquals(canonical(read), canonical(saved), name)
        // Only protected values differ in the raw XML; each decrypts to the same text.
        assertEquals(read.protectedValues.size, saved.protectedValues.size)
        assertEquals(plainOutsideProtected(read), plainOutsideProtected(saved), name)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vaults")
    fun `saving keeps the KDBX version and every attachment's protected flag`(name: String, bytes: ByteArray, password: String) {
        val read = decode(bytes, password)
        val encoded = VaultXmlCodec.encodeBytes(read)
        val before = assertIs<HeaderResult.Valid>(KdbxHeaderParser.parse(bytes)).header
        val after = assertIs<HeaderResult.Valid>(KdbxHeaderParser.parse(encoded)).header
        assertEquals(before.majorVersion to before.minorVersion, after.majorVersion to after.minorVersion, name)
        assertEquals(before.cipher, after.cipher)
        val saved = decode(encoded, password)
        assertEquals(read.attachments.map { it.protected to it.data.toList() }, saved.attachments.map { it.protected to it.data.toList() })
    }

    @Test
    fun `two saves differ from each other and from the opened file in master seed, IV, KDF salt and inner stream key`() {
        val bytes = fixture("keepass2-default-aeskdf.kdbx")
        val read = decode(bytes, fixturePassword)
        val files = listOf(bytes, VaultXmlCodec.encodeBytes(read), VaultXmlCodec.encodeBytes(read))
        val values = files.map { file ->
            val header = assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(file)).header
            val seed = (header.kdf as org.onekash.kashpass.vault.kdbx.KdfParameters.Aes).seed
            listOf(header.masterSeed, header.iv, seed, innerStreamKey(file, header)).map { it.toList() }
        }
        for (i in 0 until 4) {
            assertEquals(3, values.map { it[i] }.toSet().size, "value $i")
        }
    }

    // The inner stream key of [file], read by KashPass's own container before the XML is read.
    private fun innerStreamKey(file: ByteArray, header: org.onekash.kashpass.vault.kdbx.OuterHeader): ByteArray {
        val composite = credentials(fixturePassword).compositeKey()
        val opened = assertIs<org.onekash.kashpass.vault.kdbx.KdbxResult.Opened>(
            org.onekash.kashpass.vault.kdbx.KdbxDecoder.decode(file, header, composite, KdfEngine()::derive, 64 shl 20),
        )
        opened.plaintext.close()
        return opened.container.inner.streamKey
    }

    @Test
    fun `a KDBX 3 header hash in Meta is left out, everything else kept`() {
        // A reader checks a non-empty one against the header and skips an empty one, so only an
        // empty one opens here.
        val xml = TestVaults.keePassXml(meta = "<Generator>x</Generator><HeaderHash></HeaderHash><Other>y</Other>")
        val read = decode(TestVaults.rawXmlVault(xml), TestVaults.PASSWORD)
        val saved = decode(VaultXmlCodec.encodeBytes(read), TestVaults.PASSWORD)
        val written = XmlBytes.text(saved.xml)
        assertFalse(written.contains("HeaderHash"))
        val expected = XmlBytes.text(read.xml).replace(Regex("<HeaderHash\\s*/>|<HeaderHash></HeaderHash>"), "")
            .replace("<Generator>x</Generator>", "<Generator>KashPass</Generator>")
        assertEquals(expected, written)
    }

    @Test
    fun `protected values are decrypted in document order, history and custom fields included`() {
        val read = decode(TestVaults.browserVault(aesRounds = 1_000UL), TestVaults.PASSWORD)
        val values = protectedInOrder(read).map { it.reveal() }
        assertTrue(values.containsAll(listOf("mail-pass", "otpauth://totp/mail?secret=JBSWY3DPEHPK3PXP", "old-mail-pass", "bank-pass", "router-pass")), values.toString())
        val xml = TestVaults.keePassXml(
            entries = "<Entry><String><Key>A</Key><Value Protected=\"True\">{{p:first}}</Value></String>" +
                "<Unknown Protected=\"True\">{{p:second}}</Unknown>" +
                "<String><Key>B</Key><Value Protected=\"True\">{{p:}}</Value></String>" +
                "<String><Key>C</Key><Value Protected=\"True\">{{p:third}}</Value></String></Entry>",
        )
        val doc = decode(TestVaults.rawXmlVault(xml), TestVaults.PASSWORD)
        assertEquals(listOf("first", "second", "", "third"), protectedInOrder(doc).map { it.reveal() })
    }

    @Test
    fun `a save leaves out earlier Keys and Values of an entry part and History inside a history entry, which take no stream`() {
        val history = "<History><Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><String><Key>Title</Key><Value>old</Value></String>" +
            "<History><Entry><String><Key>P</Key><Value Protected=\"True\">{{p:nested}}</Value></String></Entry></History></Entry></History>"
        val xml = TestVaults.keePassXml(
            entries = "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>" +
                "<String><Key>Other</Key><Key>Password</Key><Value Protected=\"True\">{{p:first}}</Value><Value Protected=\"True\">{{p:second}}</Value></String>" +
                "<Binary><Key>a</Key><Key>b</Key><Value Ref=\"0\" /><Value Ref=\"0\" /></Binary>" +
                "$history<String><Key>Later</Key><Value Protected=\"True\">{{p:later}}</Value></String></Entry>",
        )
        val read = decode(TestVaults.rawXmlVault(xml, listOf("A".toByteArray())), TestVaults.PASSWORD)
        val omitted = EntryParts.omitted(read.xml.root)
        assertEquals(listOf("History", "Key", "Key", "Value", "Value"), omitted.map { it.name }.sorted())
        val saved = decode(VaultXmlCodec.encodeBytes(read), TestVaults.PASSWORD)
        assertEquals(revealed(read, omit = { it in omitted || isRootGenerator(it) }), revealed(saved, omit = ::isRootGenerator))
        assertEquals(
            "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><String><Key>Password</Key><Value Protected=\"True\">[second]</Value></String>" +
                "<Binary><Key>b</Key><Value Ref=\"0\" /></Binary><History><Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>" +
                "<String><Key>Title</Key><Value>old</Value></String></Entry></History>" +
                "<String><Key>Later</Key><Value Protected=\"True\">[later]</Value></String></Entry>",
            Regex("<Entry>.*</Entry>").find(revealed(saved))!!.value,
        )
        assertTrue(EntryParts.omitted(saved.xml.root).isEmpty())
    }

    // The XML with each protected value shown as [plaintext] and the elements [omit] names left
    // out.
    private fun revealed(doc: VaultDocument, omit: (XmlElement) -> Boolean = { false }): String = XmlBytes.text(
        doc.xml,
        object : XmlBytes.TextHooks() {
            override fun omit(element: XmlElement) = omit(element)
            override fun text(element: XmlElement) = doc.protectedValues[element]?.let { "[" + it.reveal() + "]" }
        },
    )

    @Test
    fun `protected values never appear in toString`() {
        val value = ProtectedText.of("hunter2")
        assertFalse(value.toString().contains("hunter2"))
        assertEquals(ProtectedText.of("hunter2"), value)
        assertNotEquals(ProtectedText.of("hunter3"), value)
        val chars = "secret".toCharArray()
        assertEquals("secret", ProtectedText.of(chars).reveal())
        assertTrue(chars.all { it == '\u0000' })
    }

    @Test
    fun `a lone surrogate in a protected value becomes U+FFFD, as KeePass 2 writes it`() {
        assertEquals("a\uFFFDb", ProtectedText.of(charArrayOf('a', '\uD800', 'b')).reveal())
    }

    @Test
    fun `a lone surrogate in protected text becomes U+FFFD and a valid pair is kept, as KeePass 2 writes them`() {
        assertEquals("a\uFFFDb", ProtectedText.of("a\uD800b").reveal())
        assertEquals("\uFFFD", ProtectedText.of("\uDC00").reveal())
        assertEquals("x\uD83D\uDE00", ProtectedText.of("x\uD83D\uDE00").reveal())
    }

    @Test
    fun `invalid base64 in a protected value is damage`() {
        val xml = TestVaults.keePassXml(entries = "<Entry><String><Key>P</Key><Value Protected=\"True\">!!not base64!!</Value></String></Entry>")
        assertEquals(Decoded.Damaged(DamageReason.PROTECTED_VALUE), result(TestVaults.rawXmlVault(xml), TestVaults.PASSWORD))
    }

    @Test
    fun `XML that is not a KeePass document is damage`() {
        for (xml in listOf("<Other/>", "<KeePassFile><Root/></KeePassFile>", "<KeePassFile><Root><Group>")) {
            assertEquals(Decoded.Damaged(DamageReason.XML), result(TestVaults.rawXmlVault(xml), TestVaults.PASSWORD), xml)
        }
    }

    @Test
    fun `decrypted XML over the open limit stops reading and reports too large`() {
        // Highly compressible notes: a small file that inflates to megabytes, as a gzip bomb does.
        val notes = "a".repeat(4 * 1024 * 1024)
        val bytes = TestVaults.rawXmlVault(TestVaults.keePassXml(entries = "<Entry><String><Key>Notes</Key><Value>$notes</Value></String></Entry>"))
        assertTrue(bytes.size < 200_000, "fixture is ${bytes.size} bytes")
        assertEquals(Decoded.NotEnoughMemory, VaultXmlCodec.decode(bytes, credentials(TestVaults.PASSWORD), VaultXmlCodec.Limits(open = 1024 * 1024, save = Long.MAX_VALUE)))
        assertIs<Saveability.Saveable>(decode(bytes, TestVaults.PASSWORD).saveability)
    }

    @Test
    fun `the limits follow the heap`() {
        val heap = 512L * 1024 * 1024
        assertEquals(VaultXmlCodec.Limits(open = (heap / 36).toInt(), save = heap / 84, decompression = (heap / 6).toInt(), payloadSave = heap / 9), VaultXmlCodec.Limits.forHeap(heap))
        val largest = VaultXmlCodec.Limits.forHeap(Long.MAX_VALUE)
        assertEquals(Int.MAX_VALUE - 8, largest.open)
        assertEquals(Int.MAX_VALUE - 8, largest.decompression)
        assertEquals(Int.MAX_VALUE - 8L, largest.payloadSave)
    }

    @Test
    fun `the encode hooks XOR exactly the recorded protected values in document order and zero-fill each copy`() {
        val xml = TestVaults.keePassXml(
            meta = "<Generator>x</Generator><HeaderHash></HeaderHash>",
            entries = "<Entry><String><Key>A</Key><Value Protected=\"True\">{{p:first}}</Value></String>" +
                "<Unknown Protected=\"True\" /><String><Key>B</Key><Value Protected=\"True\">{{p:second}}</Value></String></Entry>",
        )
        val doc = decode(TestVaults.rawXmlVault(xml), TestVaults.PASSWORD)
        assertEquals(2, doc.protectedValues.size)
        val copies = mutableListOf<ByteArray>()
        // A stand-in stream: the n-th value is XORed with n.
        val hooks = EncodeHooks(doc) { bytes ->
            copies += bytes
            for (i in bytes.indices) bytes[i] = (bytes[i].toInt() xor copies.size).toByte()
        }
        val written = XmlBytes.text(doc.xml, hooks)
        fun xored(text: String, n: Int) = java.util.Base64.getEncoder().encodeToString(text.toByteArray().map { (it.toInt() xor n).toByte() }.toByteArray())
        assertTrue(written.contains("<Value Protected=\"True\">${xored("first", 1)}</Value>"), written)
        assertTrue(written.contains("<Value Protected=\"True\">${xored("second", 2)}</Value>"), written)
        // Protected="True" with no recorded value is written as it was read.
        assertTrue(written.contains("<Unknown Protected=\"True\" />"), written)
        assertFalse(written.contains("HeaderHash"))
        assertEquals(2, copies.size)
        assertTrue(copies.all { copy -> copy.all { it.toInt() == 0 } }, "each plaintext copy is zero-filled")
    }

    @Test
    fun `a save gives back every protected value of the corpus protected-value shapes`() {
        val cases = Corpus.all.filter { it.name.startsWith("spec-inner-") && "protected" in it.name && it.spec == Spec.OPENS }
        assertTrue(cases.size >= 3, cases.map { it.name }.toString())
        for (c in cases) {
            val file = c.file()
            val read = assertIs<ContainerDecode.Result.Opened>(ContainerRig.open(file), c.name).read
            val credentials = TestFiles.credentials(file)
            val document = VaultXmlCodec.document(read, credentials, ContainerRig.LIMITS)
            val saved = VaultXmlCodec.open(VaultXmlCodec.encodeBytes(document), credentials, ContainerRig.LIMITS)
            val before = protectedInOrder(document).map { it.reveal() }
            assertTrue(before.isNotEmpty(), c.name)
            assertEquals(before, protectedInOrder(saved).map { it.reveal() }, c.name)
            assertEquals(canonical(document), canonical(saved), c.name)
        }
    }

    // A save writes the root Meta's Generator as KashPass (tested on its own above), so the
    // comparisons below leave it out.
    private fun isRootGenerator(element: XmlElement) =
        element.name == "Generator" && element.parent?.name == "Meta" && element.parent?.parent?.parent == null

    // The XML with each protected value's ciphertext replaced by the SHA-256 of its plaintext, and
    // Meta/HeaderHash and Meta/Generator left out: what must survive a save unchanged.
    private fun canonical(doc: VaultDocument): String = XmlBytes.text(
        doc.xml,
        object : XmlBytes.TextHooks() {
            override fun omit(element: XmlElement) = element.name == "HeaderHash" && element.parent?.name == "Meta" || isRootGenerator(element)
            override fun text(element: XmlElement): String? {
                if (element.attribute("Protected") != "True") return null
                val plain = doc.protectedValues.getValue(element).utf8()
                return MessageDigest.getInstance("SHA-256").digest(plain).joinToString("") { "%02x".format(it) }
            }
        },
    )

    // The raw written XML with protected values blanked and Meta/Generator left out: proves
    // untouched text is byte-identical.
    private fun plainOutsideProtected(doc: VaultDocument): String = XmlBytes.text(
        doc.xml,
        object : XmlBytes.TextHooks() {
            override fun omit(element: XmlElement) = isRootGenerator(element)
            override fun text(element: XmlElement) = if (element.attribute("Protected") == "True") "#" else null
        },
    )

    private fun protectedInOrder(doc: VaultDocument): List<ProtectedText> {
        val out = mutableListOf<ProtectedText>()
        fun walk(e: XmlElement) {
            doc.protectedValues[e]?.let(out::add)
            e.elements().forEach(::walk)
        }
        walk(doc.xml.root)
        return out
    }

    private fun generators(document: VaultDocument) =
        document.xml.root.children("Meta").flatMap { it.children("Generator") }.map { it.text() }

    @Test
    fun `a save writes Generator KashPass in place of the stored one, leaving the document as read`() {
        val read = decode(TestVaults.rawXmlVault(TestVaults.keePassXml(meta = "<Generator>KeePass</Generator><DatabaseName>n</DatabaseName>")), TestVaults.PASSWORD)
        val saved = decode(VaultXmlCodec.encodeBytes(read), TestVaults.PASSWORD)
        assertEquals(listOf("KashPass"), generators(saved))
        assertEquals(listOf("KeePass"), generators(read))
        assertEquals("n", saved.xml.root.child("Meta")!!.child("DatabaseName")!!.text())
    }

    @Test
    fun `a save adds Generator KashPass as Meta's first child when the file has none, also in an empty Meta`() {
        for (meta in listOf("<DatabaseName>n</DatabaseName>", "")) {
            val read = decode(TestVaults.rawXmlVault(TestVaults.keePassXml(meta = meta)), TestVaults.PASSWORD)
            val saved = decode(VaultXmlCodec.encodeBytes(read), TestVaults.PASSWORD)
            assertEquals("Generator", saved.xml.root.child("Meta")!!.elements().first().name, meta)
            assertEquals(listOf("KashPass"), generators(saved), meta)
            assertEquals(emptyList(), generators(read), meta)
        }
    }

    @Test
    fun `every Generator in the root Meta is written as KashPass`() {
        val read = decode(TestVaults.rawXmlVault(TestVaults.keePassXml(meta = "<Generator>a</Generator><Generator>b</Generator>")), TestVaults.PASSWORD)
        assertEquals(listOf("KashPass", "KashPass"), generators(decode(VaultXmlCodec.encodeBytes(read), TestVaults.PASSWORD)))
    }

    @Test
    fun `a file without a root Meta gets none`() {
        val xml = TestVaults.keePassXml().replace(Regex("\t<Meta>.*?</Meta>\n"), "")
        val read = decode(TestVaults.rawXmlVault(xml), TestVaults.PASSWORD)
        assertEquals(null, read.xml.root.child("Meta"))
        assertEquals(null, decode(VaultXmlCodec.encodeBytes(read), TestVaults.PASSWORD).xml.root.child("Meta"))
    }

    companion object {
        val fixturePassword: String = System.getProperty("kashpass.fixture.password") ?: "kashpass-test"

        fun fixture(name: String): ByteArray =
            VaultXmlCodecTest::class.java.getResourceAsStream("/fixtures/$name")?.use { it.readBytes() } ?: fail("missing fixture $name")

        internal fun credentials(password: String) = VaultKey.password(password.toCharArray())

        fun decode(bytes: ByteArray, password: String): VaultDocument =
            VaultXmlCodec.open(bytes, credentials(password), VaultXmlCodec.Limits(open = 256 * 1024 * 1024, save = 128L * 1024 * 1024))

        internal fun result(bytes: ByteArray, password: String): Decoded =
            VaultXmlCodec.decode(bytes, credentials(password), VaultXmlCodec.Limits(open = 256 * 1024 * 1024, save = 128L * 1024 * 1024))

        @JvmStatic
        fun vaults(): Stream<Arguments> {
            val fixtures = listOf(
                "keepass2-default-aeskdf.kdbx",
                "keepass2-argon2id.kdbx",
                "keepass2-chacha20-argon2d.kdbx",
                "keepass2-kdbx41-tags.kdbx",
                "keepass2-weak-aeskdf-6000.kdbx",
                "keepass2-desktop-new-database.kdbx",
            ).map { Arguments.of(it, fixture(it), fixturePassword) }
            val generated = listOf(
                "browserVault" to TestVaults.browserVault(aesRounds = 1_000UL),
                "protectedTitleVault" to TestVaults.protectedTitleVault(),
                "repeatedIdsVault" to TestVaults.repeatedIdsVault(),
                "bytes" to TestVaults.bytes(aesRounds = 1_000UL),
            ).map { (name, bytes) -> Arguments.of(name, bytes, TestVaults.PASSWORD) }
            return (fixtures + generated).stream()
        }
    }

    @Test
    fun `canonical comparison catches a changed value`() {
        val read = decode(TestVaults.bytes(aesRounds = 1_000UL), TestVaults.PASSWORD)
        val saved = decode(VaultXmlCodec.encodeBytes(read), TestVaults.PASSWORD)
        assertEquals(canonical(read), canonical(saved))
        val title = saved.xml.root.child("Root")!!.child("Group")!!.child("Group")!!.child("Entry")!!.children("String").first { it.child("Key")!!.text() == "Title" }
        title.child("Value")!!.setText("changed")
        assertNotEquals(canonical(read), canonical(saved))
        assertEquals(read.attachments.map { it.data.toList() }, saved.attachments.map { it.data.toList() })
    }
}
