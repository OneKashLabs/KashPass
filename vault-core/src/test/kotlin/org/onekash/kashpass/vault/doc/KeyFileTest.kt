package org.onekash.kashpass.vault.doc

import java.security.MessageDigest
import java.util.Base64
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail
import java.time.Duration
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.fixtures.Kdbx3Vaults
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.testing.TestVaults

class KeyFileTest {

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    private fun part(bytes: ByteArray): ByteArray = assertIs<KeyFileResult.Key>(KeyFile.parse(bytes)).part

    private fun fixture(name: String): ByteArray =
        javaClass.getResourceAsStream("/fixtures/$name")?.use { it.readBytes() } ?: fail("Missing fixture $name")

    private fun v1(data: String, version: String = "1.00") =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>$version</Version>\n\t</Meta>\n" +
            "\t<Key>\n\t\t<Data>$data</Data>\n\t</Key>\n</KeyFile>"

    private fun v2(key: ByteArray, hash: String? = hex(sha256(key).copyOf(4)), version: String = "2.0", prolog: String = ""): String {
        val attribute = if (hash == null) "" else " Hash=\"$hash\""
        val data = hex(key).chunked(8).chunked(4).joinToString("\n\t\t\t", "\n\t\t\t", "\n\t\t") { it.joinToString(" ") }
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n$prolog<KeyFile>\n\t<Meta>\n\t\t<Version>$version</Version>\n\t</Meta>\n" +
            "\t<Key>\n\t\t<Data$attribute>$data</Data>\n\t</Key>\n</KeyFile>"
    }

    private val key32 = ByteArray(32) { (it * 7 + 3).toByte() }

    @Test
    fun `an XML version 2 key file gives its hex data, whitespace ignored, hash checked`() {
        assertContentEquals(key32, part(v2(key32).toByteArray()))
    }

    @Test
    fun `an XML version 2 key file with CR LF line ends, as KeePass 2 writes it on Windows, gives the same key`() {
        assertContentEquals(key32, part(v2(key32).replace("\n", "\r\n").toByteArray()))
        val fixture = fixture("keepass2-keyfile-v2.keyx")
        assertTrue('\r' !in fixture.decodeToString())
        assertContentEquals(part(fixture.copyOf()), part(fixture.decodeToString().replace("\n", "\r\n").toByteArray()))
    }

    @Test
    fun `an XML version 2 key file with a wrong hash is damaged`() {
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(v2(key32, hash = "00000000").toByteArray()))
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(v2(key32, hash = "XYZ").toByteArray()))
    }

    @Test
    fun `an XML version 2 key file without a hash, or with an empty one, is accepted`() {
        assertContentEquals(key32, part(v2(key32, hash = null).toByteArray()))
        assertContentEquals(key32, part(v2(key32, hash = "").toByteArray()))
    }

    @ParameterizedTest
    @ValueSource(chars = ['\u0009', '\u000A', '\u000D', '\u0020', '\u0085', '\u00A0', '\u1680', '\u2000', '\u2007', '\u200A', '\u2028', '\u2029', '\u202F', '\u205F', '\u3000'])
    fun `key data drops each character the desktop runtime calls white space`(space: Char) {
        val hexData = hex(key32).chunked(8).joinToString("$space$space")
        val file = v2(key32).replace(Regex("(?s)<Data Hash=\"([0-9A-F]+)\">.*</Data>")) { "<Data Hash=\"${it.groupValues[1]}\">$space$hexData$space</Data>" }
        assertContentEquals(key32, part(file.toByteArray()))
        val base64 = Base64.getEncoder().encodeToString(key32).chunked(4).joinToString("$space")
        assertContentEquals(key32, part(v1(base64).toByteArray()))
    }

    @ParameterizedTest
    @ValueSource(chars = ['\u180E', '\u200B', '\u2060', '\uFEFF'])
    fun `key data keeps characters the desktop runtime does not call white space, so the key is damaged`(other: Char) {
        val hexData = hex(key32).chunked(8).joinToString("$other")
        val file = v2(key32, hash = null).replace(Regex("(?s)<Data>.*</Data>"), "<Data>$hexData</Data>")
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(file.toByteArray()))
    }

    @Test
    fun `KeePass 2's white space table is exactly the desktop runtime's list`() {
        val expected = (listOf(0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000) + (0x2000..0x200A)).toSortedSet()
        assertEquals(expected, (0..0xFFFF).filter { KeyFile.isDotNetWhiteSpace(it.toChar()) }.toSortedSet())
    }

    @Test
    fun `an XML version 1 key file gives its base64 data`() {
        assertContentEquals(key32, part(v1(Base64.getEncoder().encodeToString(key32)).toByteArray()))
    }

    @ParameterizedTest
    @ValueSource(strings = ["1.0", "1.00", "1", "1.5", " 1 ", "01", "+1", "1,0", "1.0.0.0"])
    fun `KeePass 2's version 1 spellings read base64`(version: String) {
        assertContentEquals(key32, part(v1(Base64.getEncoder().encodeToString(key32), version).toByteArray()))
    }

    @ParameterizedTest
    @ValueSource(strings = ["2.0", "2", "2.00", "2.1", "02", "2,0"])
    fun `KeePass 2's version 2 spellings read hex`(version: String) {
        assertContentEquals(key32, part(v2(key32, version = version).toByteArray()))
    }

    @ParameterizedTest
    @ValueSource(strings = ["", "3.0", "0.9", "abc", "-1", "65537", "x"])
    fun `an unknown or missing version is damaged`(version: String) {
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(v1(Base64.getEncoder().encodeToString(key32), version).toByteArray()))
    }

    @Test
    fun `KeePass 2's version parse reads the major part only`() {
        assertEquals(1, KeyFile.majorVersion("1.00"))
        assertEquals(2, KeyFile.majorVersion("2.0"))
        assertEquals(0, KeyFile.majorVersion("x.0"))
        assertEquals(65535, KeyFile.majorVersion("65535"))
        assertEquals(0, KeyFile.majorVersion("65536"))
    }

    @Test
    fun `XML key data that isn't base64 or hex, or is empty, is damaged`() {
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(v1("not base64!").toByteArray()))
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(v1("  ").toByteArray()))
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(v1("ZZZZ", version = "2.0").toByteArray()))
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(v1("ABC", version = "2.0").toByteArray()))
        assertEquals(KeyFileResult.Damaged, KeyFile.parse("<KeyFile><Meta><Version>2.0</Version></Meta></KeyFile>".toByteArray()))
    }

    @ParameterizedTest
    @ValueSource(ints = [16, 32, 64, 100])
    fun `XML key data can be any length`(size: Int) {
        val key = ByteArray(size) { (it + 1).toByte() }
        assertContentEquals(key, part(v2(key).toByteArray()))
        assertContentEquals(key, part(v1(Base64.getEncoder().encodeToString(key)).toByteArray()))
    }

    @Test
    fun `a byte order mark before the XML is accepted`() {
        val bom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte())
        assertContentEquals(key32, part(bom + v2(key32).toByteArray()))
    }

    @Test
    fun `an XML key file is read from its UTF-8 bytes in place, one bad byte makes it a raw key`() {
        val bytes = v2(key32, prolog = "<!-- clé 😀 -->\n").toByteArray()
        val before = bytes.copyOf()
        assertContentEquals(key32, part(bytes))
        assertContentEquals(before, bytes, "the parse leaves the caller's bytes as they were")
        // 'é' is C3 A9; C3 followed by 'A' is not UTF-8.
        val broken = bytes.copyOf().also { it[it.indexOf(0xC3.toByte()) + 1] = 0x41 }
        assertContentEquals(sha256(broken), part(broken))
    }

    @ParameterizedTest
    @EnumSource(Utf16Form::class)
    fun `a UTF-16 XML key file is read as the desktop runtime detects it`(form: Utf16Form) {
        assertContentEquals(key32, part(form.encode(v2(key32).replace("utf-8", "utf-16"))))
        assertContentEquals(key32, part(form.encode(v2(key32).replace(" encoding=\"utf-8\"", ""))), "no encoding in the declaration")
        assertContentEquals(key32, part(form.encode(v2(key32).replace("utf-8", "UCS-2"))))
        val noDeclaration = v2(key32).substringAfter("?>\n")
        assertContentEquals(key32, part(form.encode(noDeclaration)), "detected from '<' without a declaration")
        val fixture = fixture("keepass2-keyfile-v2.keyx").decodeToString().replace("utf-8", "utf-16")
        assertContentEquals(part(fixture("keepass2-keyfile-v2.keyx")), part(form.encode(fixture)))
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(form.encode(v2(key32, hash = "00000000").replace("utf-8", "utf-16"))), "a bad key is damaged")
    }

    @ParameterizedTest
    @EnumSource(Utf16Form::class)
    fun `a UTF-16 key file whose declaration names another encoding is hashed, as the desktop runtime switches to it`(form: Utf16Form) {
        for (name in listOf("utf-8", "iso-8859-1", "x-unknown")) {
            val file = form.encode(v2(key32).replace("utf-8", name))
            assertContentEquals(sha256(file), part(file), name)
        }
    }

    @Test
    fun `UCS-4 is not read as XML and is hashed`() {
        val ucs4 = v2(key32).toByteArray(Charsets.UTF_32BE)
        assertContentEquals(sha256(ucs4), part(ucs4))
    }

    /** The four UTF-16 forms .NET's XmlReader detects from a document's first bytes. */
    enum class Utf16Form(private val charset: java.nio.charset.Charset, private val bom: ByteArray) {
        LITTLE_ENDIAN_WITH_BOM(Charsets.UTF_16LE, byteArrayOf(0xFF.toByte(), 0xFE.toByte())),
        LITTLE_ENDIAN(Charsets.UTF_16LE, ByteArray(0)),
        BIG_ENDIAN_WITH_BOM(Charsets.UTF_16BE, byteArrayOf(0xFE.toByte(), 0xFF.toByte())),
        BIG_ENDIAN(Charsets.UTF_16BE, ByteArray(0)),
        ;

        fun encode(text: String): ByteArray = bom + text.toByteArray(charset)
    }

    @Test
    fun `a key file with a document type declaration is refused, not expanded`() {
        val doctype = "<!DOCTYPE KeyFile [<!ENTITY k \"${hex(key32)}\">]>\n"
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(v2(key32, prolog = doctype).toByteArray()))
    }

    @Test
    fun `XML that isn't a KeyFile document is hashed whole`() {
        val other = "<?xml version=\"1.0\"?><html><body>${"x".repeat(80)}</body></html>".toByteArray()
        assertContentEquals(sha256(other), part(other))
        val namespaced = v2(key32).replace("<KeyFile>", "<KeyFile xmlns=\"urn:other\">").toByteArray()
        assertContentEquals(sha256(namespaced), part(namespaced))
    }

    @Test
    fun `a 2 MiB XML key file is read as XML, as KeePass 2 reads one of any size`() {
        val padded = v2(key32).replace("</KeyFile>", "<!--${" ".repeat(2 shl 20)}--></KeyFile>").toByteArray()
        assertTrue(padded.size > 2 shl 20)
        assertContentEquals(key32, part(padded))
    }

    @Test
    fun `XML up to the limit is read, and over it a KeyFile root is not enough memory and any other root is hashed`() {
        val file = v2(key32, prolog = "<!-- a comment -->\n<?pi data?>\n \t\r\n").toByteArray()
        assertContentEquals(key32, assertIs<KeyFileResult.Key>(KeyFile.parse(file, maxXmlBytes = file.size)).part)
        assertEquals(KeyFileResult.NotEnoughMemory, KeyFile.parse(file, maxXmlBytes = file.size - 1))
        val bom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + file
        assertEquals(KeyFileResult.NotEnoughMemory, KeyFile.parse(bom, maxXmlBytes = 10))
        val bare = "<KeyFile/>".toByteArray()
        assertEquals(KeyFileResult.NotEnoughMemory, KeyFile.parse(bare, maxXmlBytes = 9))
        for (other in listOf("<?xml version=\"1.0\"?><html><body>${"x".repeat(80)}</body></html>", "<KeyFileX/>${" ".repeat(60)}", "<!-- unclosed <KeyFile>${" ".repeat(60)}", "x<KeyFile/>${" ".repeat(60)}")) {
            val bytes = other.toByteArray()
            assertContentEquals(sha256(bytes), assertIs<KeyFileResult.Key>(KeyFile.parse(bytes, maxXmlBytes = 10)).part, other)
        }
    }

    @Test
    fun `UTF-16 XML is over the limit when its UTF-8 form is`() {
        val utf8 = v2(key32).toByteArray()
        for (charset in listOf(Charsets.UTF_16LE, Charsets.UTF_16BE)) {
            val file = v2(key32).replace("utf-8", "utf-16").toByteArray(charset)
            val size = utf8.size + 1
            assertContentEquals(key32, assertIs<KeyFileResult.Key>(KeyFile.parse(file, maxXmlBytes = size)).part, "$charset")
            assertEquals(KeyFileResult.NotEnoughMemory, KeyFile.parse(file, maxXmlBytes = size - 1), "$charset")
            assertEquals(KeyFileResult.NotEnoughMemory, KeyFile.parse(file, maxXmlBytes = 10), "$charset")
            val other = "<html>${" ".repeat(60)}</html>".toByteArray(charset)
            assertContentEquals(sha256(other), assertIs<KeyFileResult.Key>(KeyFile.parse(other, maxXmlBytes = 10)).part, "$charset")
        }
    }

    @Test
    fun `exactly 32 bytes are the key as they are`() {
        val raw = ByteArray(32) { (255 - it).toByte() }
        val result = part(raw)
        assertContentEquals(raw, result)
        result.fill(0)
        assertEquals(255.toByte(), raw[0], "the part is a copy")
    }

    @Test
    fun `exactly 64 strict hex characters are decoded`() {
        val text = hex(key32).lowercase().substring(0, 32) + hex(key32).substring(32)
        assertContentEquals(key32, part(text.toByteArray()))
    }

    @Test
    fun `64 bytes that aren't strict hex are hashed`() {
        val spaced = (hex(key32).substring(0, 62) + " \n").toByteArray()
        assertEquals(64, spaced.size)
        assertContentEquals(sha256(spaced), part(spaced))
        val other = ByteArray(64) { 'g'.code.toByte() }
        assertContentEquals(sha256(other), part(other))
    }

    @Test
    fun `any other file, and an empty one, is hashed`() {
        assertContentEquals(sha256(ByteArray(0)), part(ByteArray(0)))
        val odd = ByteArray(33) { it.toByte() }
        assertContentEquals(sha256(odd), part(odd))
        val invalidUtf8 = ByteArray(100) { 0xC3.toByte() }
        assertContentEquals(sha256(invalidUtf8), part(invalidUtf8))
    }

    @Test
    fun `KeePass 2's key files parse to their keys`() {
        // The XML key files hold their key in Data: hex in groups of 8 (2.0) or Base64 (1.00).
        fun data(name: String) = Regex("<Data[^>]*>([^<]*)</Data>").find(String(fixture(name)))!!.groupValues[1]
        assertContentEquals(hexBytes(data("keepass2-keyfile-v2.keyx").filterNot { it.isWhitespace() }), part(fixture("keepass2-keyfile-v2.keyx")))
        assertContentEquals(Base64.getDecoder().decode(data("keepass2-keyfile-v1.key").trim()), part(fixture("keepass2-keyfile-v1.key")))
        assertContentEquals(fixture("keepass2-keyfile-raw32.key"), part(fixture("keepass2-keyfile-raw32.key")))
        assertContentEquals(hexBytes(String(fixture("keepass2-keyfile-hex64.key"))), part(fixture("keepass2-keyfile-hex64.key")))
        assertContentEquals(sha256(fixture("keepass2-keyfile-other.key")), part(fixture("keepass2-keyfile-other.key")))
    }

    @Test
    fun `64 hex characters and a newline (65 bytes) are hashed, as KeePass 2 reads them`() {
        val file = Kdbx3Vaults.KEY_FILE
        assertEquals(65, file.size)
        assertContentEquals(sha256(file), part(file))
    }

    @ParameterizedTest
    @ValueSource(ints = [16, 32, 64])
    fun `the in-memory key file unlocks a vault made with that key part`(size: Int) = runBlocking<Unit> {
        val key = ByteArray(size) { (it * 3 + 1).toByte() }
        val withPassword = TestVaults.bytes(aesRounds = 1_000UL, keyPart = key)
        val credentials = VaultKey.password(TestVaults.PASSWORD.toCharArray(), key)
        assertIs<Decoded.Opened>(VaultXmlCodec.decode(withPassword, credentials, VaultXmlCodec.Limits(1 shl 24, 1L shl 24)))
        val keyOnly = TestVaults.bytes(aesRounds = 1_000UL, password = null, keyPart = key)
        assertIs<Decoded.Opened>(VaultXmlCodec.decode(keyOnly, VaultKey.keyFile(key), VaultXmlCodec.Limits(1 shl 24, 1L shl 24)))
        assertEquals(size, VaultKey.keyFile(key).keyFilePart()!!.size, "the key keeps the part as given")
        val unlocked = TestVaults.unlock(keyOnly, password = "", keyFile = TestVaults.keyFileFor(key))
        assertIs<OpenResult.Unlocked>(unlocked)
    }

    @Test
    fun `a start tag with about 120,000 attributes is read in linear time`() {
        val keyFileRoot = manyAttributes("KeyFile")
        assertTrue(keyFileRoot.size <= 1 shl 20)
        assertTimeoutPreemptively(Duration.ofSeconds(2)) {
            assertEquals(KeyFileResult.Damaged, KeyFile.parse(keyFileRoot), "a KeyFile root without Key and Data is damaged")
        }
        val otherRoot = manyAttributes("X")
        assertTimeoutPreemptively(Duration.ofSeconds(2)) {
            assertContentEquals(sha256(otherRoot), part(otherRoot), "another root is hashed")
        }
    }

    private fun hexBytes(text: String) = text.trim().chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    companion object {
        /** Attributes in the start tag [manyAttributes] builds by default: about 960 KB of them. */
        const val MANY_ATTRIBUTES = 120_000

        /**
         * Returns a self-closing element named [root] with [count] distinct 4-character
         * attributes, each written as `Abcd=""`.
         */
        fun manyAttributes(root: String, count: Int = MANY_ATTRIBUTES): ByteArray {
            val letters = ('a'..'z') + ('A'..'Z')
            val chars = letters + ('0'..'9')
            val text = StringBuilder("<").append(root)
            for (n in 0 until count) {
                val name = charArrayOf(letters[n / (chars.size * chars.size * chars.size) % letters.size], chars[n / (chars.size * chars.size) % chars.size], chars[n / chars.size % chars.size], chars[n % chars.size])
                text.append(' ').append(name).append("=\"\"")
            }
            return text.append("/>").toString().toByteArray()
        }
    }

    @Test
    fun `the XML limit is the heap divided by 60`() {
        assertEquals(256 * 1024 * 1024 / 60, KeyFile.maxXmlBytes(256L * 1024 * 1024))
        assertEquals(Int.MAX_VALUE, KeyFile.maxXmlBytes(Long.MAX_VALUE))
    }

    @Test
    fun `a KeyFile root after a document type declaration makes the file damaged under the limit, too large over it`() {
        val doctype = "<!DOCTYPE KeyFile [<!ENTITY e \"x>y\">]><KeyFile><Meta><Version>2.0</Version></Meta><Key><Data>00</Data></Key></KeyFile>"
        assertEquals(KeyFileResult.Damaged, KeyFile.parse(doctype.toByteArray(), maxXmlBytes = 1 shl 20))
        assertEquals(KeyFileResult.NotEnoughMemory, KeyFile.parse(doctype.toByteArray(), maxXmlBytes = 10))
    }

    @Test
    fun `XML with another root is hashed without a parse, whatever its size`() {
        val other = "<X><a/><a/></X>".toByteArray()
        val hashed = assertIs<KeyFileResult.Key>(KeyFile.parse(other, maxXmlBytes = 4))
        assertContentEquals(java.security.MessageDigest.getInstance("SHA-256").digest(other), hashed.part)
    }

}
