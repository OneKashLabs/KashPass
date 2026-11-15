package org.onekash.kashpass.vault.xml

import java.io.ByteArrayInputStream
import java.util.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class XmlReaderTest {

    private fun parsed(text: String): XmlDocument {
        val result = XmlBytes.parse(text)
        assertIs<XmlReadResult.Parsed>(result, "expected to parse: $text")
        return result.document
    }

    private fun roundTrip(text: String) {
        val bytes = text.encodeToByteArray()
        assertContentEquals(bytes, XmlBytes.write(assertIs<XmlReadResult.Parsed>(XmlBytes.parse(bytes), text).document), text)
    }

    @Test
    fun `text of XML whitespace alone reads as empty, as KeePass 2's reader reads it`() {
        for (xml in listOf("<a>   </a>", "<a>\t&#xD;\n</a>", "<a>&#x20;</a>", "<a>\r\n</a>")) assertEquals("", parsed(xml).root.text(), xml)
        assertEquals(" x ", parsed("<a> x </a>").root.text())
        assertEquals("x", parsed("<a>  <![CDATA[x]]>  </a>").root.text())
        assertEquals(" y", parsed("<a> <!-- c --> y</a>").root.text())
    }

    @Test
    fun `whitespace in CDATA or under xml space preserve is kept, as KeePass 2's reader keeps it`() {
        assertEquals("  ", parsed("<a><![CDATA[  ]]></a>").root.text())
        assertEquals("  ", parsed("<a xml:space=\"preserve\">  </a>").root.text())
        assertEquals("  ", parsed("<a xml:space=\" preserve \">  </a>").root.text())
        assertEquals(" \t", parsed("<r xml:space=\"preserve\"><a> \t</a></r>").root.elements().single().text())
        assertEquals("", parsed("<r xml:space=\"preserve\"><a xml:space=\"default\"> </a></r>").root.elements().single().text())
    }

    @Test
    fun `a KeePass-shaped document is written back unchanged`() {
        roundTrip(KEEPASS_SHAPED)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "<a/>",
            "<a></a>",
            "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\r\n<a>x</a>\r\n",
            "<!-- lead --><?pi data?>\n<a><!-- inner --><?keep this?></a><!-- tail -->\n",
            "<a><![CDATA[ <not> & markup ]]></a>",
            "<a b='single' c=\"double\"   d = 'spaced' />",
            "<a  b=\"1\"\n\tc=\"2\"\r\n></a  >",
            "<a>&lt;&gt;&amp;&apos;&quot;&#65;&#x42;&#xD;</a>",
            "<a>line1\r\nline2\rline3\n</a>",
            "<a b=\"x&#10;y&#9;z\">t</a>",
            "<a>Ä 😀 é</a>",
            "<中文 é😀='ü'><ü/></中文>",
            "<a:b xmlns:a=\"urn:x\"><a:c/></a:b>",
            "<!DOCTYPE a><a/>",
            "<!DOCTYPE a [ <!ENTITY e \"x]>\"> <!-- ] > --> <?p ]>?> ]><a/>",
        ],
    )
    fun `every construct round-trips byte for byte`(text: String) {
        roundTrip(text)
    }

    @Test
    fun `generated documents round-trip byte for byte`() {
        val random = Random(42)
        repeat(300) { roundTrip(generate(random, depth = 0)) }
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>",
            "<?xml version='1.0' encoding='UTF-8' standalone='no'?>",
            "<?xml version = \"1.0\"\t encoding =\"utf-16\" ?>",
            "<?xml version=\"1.0\"?>",
            "<?xml version=\"1.0\" standalone=\"yes\"?>",
        ],
    )
    fun `an XML declaration KeePass 2 accepts is read`(declaration: String) {
        assertEquals("a", parsed("$declaration<a/>").root.name)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "<?xml version=\"1.0\" encoding=\"utf-8\" junk standalone=\"yes\"?>",
            "<?xml version=\"1.0\" <Value>junk</Value> ?>",
            "<?xml encoding=\"utf-8\"?>",
            "<?xml version=\"1.1\"?>",
            "<?xml version=\"1.0\" standalone=\"yes\" encoding=\"utf-8\"?>",
            "<?xml version=\"1.0\" standalone=\"maybe\"?>",
            "<?xml version=1.0?>",
            "<?xml version=\"1.0\" encoding=\"kashpass-unknown\"?>",
            "<?xml version=\"1.0\" encoding=\"1abc\"?>",
            "<?xml version=\"1.0\"",
            "<?xmlversion=\"1.0\"?>",
        ],
    )
    fun `an XML declaration KeePass 2 refuses is malformed`(declaration: String) {
        assertIs<XmlReadResult.Malformed>(XmlBytes.parse("$declaration<a/>"), declaration)
    }

    @Test
    fun `a document type declaration is kept and flagged, never used to define an entity`() {
        assertTrue(parsed("<!DOCTYPE KeePassFile><KeePassFile/>").hasDoctype)
        assertFalse(parsed("<KeePassFile/>").hasDoctype)
        // The declared entity is never defined, so a reference to it is malformed.
        val withEntity = "<!DOCTYPE a [<!ENTITY e \"boom\">]><a>&e;</a>"
        assertIs<XmlReadResult.Malformed>(XmlBytes.parse(withEntity))
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "<!DOCTYPE a [ <!ENTITY x 'a]>b'> ]><a/>",
            "<!DOCTYPE a [ <!ENTITY x \"a]>b\"> ]><a/>",
            "<!DOCTYPE a [ <!-- ]> --> ]><a/>",
            "<!DOCTYPE a [ <?pi ]> ?> ]><a/>",
            "<!DOCTYPE a SYSTEM \"x>y.dtd\"><a/>",
        ],
    )
    fun `the end of an internal subset skips quoted strings, comments and processing instructions`(text: String) {
        val document = parsed(text)
        assertTrue(document.hasDoctype)
        assertEquals("a", document.root.name)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "",
            "text only",
            "<a>",
            "<a></b>",
            "<a><b></a></b>",
            "<a b=\"1\" b=\"2\"/>",
            "<a b=\"<\"/>",
            "<a b=1/>",
            "<a b/>",
            "<a>&unknown;</a>",
            "<a>&#0;</a>",
            "<a>&#xFFFE;</a>",
            "<a>&#xD800;</a>",
            "<a>& </a>",
            "<a>]]></a>",
            "<a/>text after",
            "<a/><b/>",
            "x<a/>",
            "<a>\u0001</a>",
            "<a>￿</a>",
            "<a><!-- a -- b --></a>",
            "<a><?xml version=\"1.0\"?></a>",
            "<a/><!DOCTYPE a>",
            "<!DOCTYPE a><!DOCTYPE a><a/>",
            "<![CDATA[x]]><a/>",
            "<1a/>",
            "<a><!-- unclosed</a>",
            "<a><![CDATA[unclosed</a>",
            "<!DOCTYPE a [ <!ENTITY x 'unclosed ]><a/>",
        ],
    )
    fun `malformed input fails without a partial tree`(text: String) {
        assertIs<XmlReadResult.Malformed>(XmlBytes.parse(text), text)
    }

    @Test
    fun `invalid UTF-8 is malformed`() {
        val bytes = byteArrayOf('<'.code.toByte(), 'a'.code.toByte(), '>'.code.toByte(), 0xC3.toByte(), '<'.code.toByte(), '/'.code.toByte(), 'a'.code.toByte(), '>'.code.toByte())
        assertIs<XmlReadResult.Malformed>(XmlReader.read(ByteArrayInputStream(bytes), 1024))
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "C3", // a lead byte with no continuation
            "80", // a continuation byte with no lead
            "C080", // an overlong NUL
            "C1BF", // an overlong '\u007F'
            "E08080", // an overlong three-byte form
            "F0808080", // an overlong four-byte form
            "EDA080", // the surrogate U+D800
            "EDBFBF", // the surrogate U+DFFF
            "F4908080", // above U+10FFFF
            "F5808080", // a lead byte UTF-8 never uses
            "FF",
            "E282", // a three-byte form cut short
            "EFBFBE", // U+FFFE, well-formed UTF-8 the Char production refuses
            "01", // U+0001, the same
        ],
    )
    fun `a byte sequence that is not UTF-8 of an XML character is malformed at its offset`(hex: String) {
        val bad = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val bytes = "<a>é".encodeToByteArray() + bad + "</a>".encodeToByteArray()
        assertEquals(XmlReadResult.Malformed(5), XmlBytes.parse(bytes), hex)
    }

    @Test
    fun `malformed offsets count bytes`() {
        // 'é' and '😀' are two and four bytes; the bad reference starts at byte 9.
        assertEquals(XmlReadResult.Malformed(9), XmlBytes.parse("<a>é😀&bad;</a>"))
        assertEquals(XmlReadResult.Malformed(0), XmlBytes.parse(""))
    }

    @Test
    fun `a byte order mark is read and not written back`() {
        val document = parsed("\uFEFF<a>bom</a>")
        assertTrue(document.bom)
        assertEquals("bom", document.root.text())
        assertContentEquals("<a>bom</a>".encodeToByteArray(), XmlBytes.write(document))
        assertFalse(parsed("<a>bom</a>").bom)
    }

    @Test
    fun `nesting at the limit parses, one deeper fails without a stack overflow`() {
        fun nested(depth: Int) = "<a>".repeat(depth) + "</a>".repeat(depth)
        assertIs<XmlReadResult.Parsed>(XmlBytes.parse(nested(XmlReader.MAX_DEPTH)))
        assertIs<XmlReadResult.Malformed>(XmlBytes.parse(nested(XmlReader.MAX_DEPTH + 1)))
        assertIs<XmlReadResult.Malformed>(XmlBytes.parse(nested(10_000)))
    }

    @Test
    fun `text is decoded as XML 1_0 defines`() {
        val root = parsed("<a>x&amp;y&#xD;\r\nz\rw&lt;<![CDATA[c\r\nd]]></a>").root
        assertEquals("x&y\r\nz\nw<c\nd", root.text())
        assertEquals("é😀\nü&", parsed("<a>é😀\r\nü&amp;</a>").root.text())
    }

    @Test
    fun `attribute values are normalized as XML 1_0 section 3_3_3 requires`() {
        val root = parsed("<a v=\"one\ttwo\r\nthree\nfour&#10;five&#9;six&amp;\" w='é\r😀'/>").root
        assertEquals("one two three four\nfive\tsix&", root.attribute("v"))
        assertEquals("é 😀", root.attribute("w"))
    }

    @Test
    fun `elements, attributes and text are reachable from the tree`() {
        val root = parsed(KEEPASS_SHAPED).root
        assertEquals("KeePassFile", root.name)
        val entry = root.child("Root")!!.child("Group")!!.child("Entry")!!
        val strings = entry.children("String")
        assertEquals(listOf("Title", "Password"), strings.map { it.child("Key")!!.text() })
        val password = strings[1].child("Value")!!
        assertEquals("True", password.attribute("Protected"))
        assertEquals("c2VjcmV0", password.text())
        assertNull(password.attribute("Missing"))
    }

    @Test
    fun `input over the byte limit is reported as too large after reading limit plus one bytes`() {
        val bytes = "<a>${"x".repeat(100)}</a>".toByteArray()
        var served = 0
        val counting = object : ByteArrayInputStream(bytes) {
            override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, len).also { if (it > 0) served += it }
            override fun read(): Int = super.read().also { if (it >= 0) served++ }
        }
        assertEquals(XmlReadResult.TooLarge, XmlReader.read(counting, 50))
        assertEquals(51, served)
        assertIs<XmlReadResult.Parsed>(XmlReader.read(ByteArrayInputStream(bytes), bytes.size))
    }

    private fun generate(random: Random, depth: Int): String = buildString {
        if (depth == 0 && random.nextBoolean()) append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
        val name = listOf("Entry", "a", "x-y", "n.1", "_u", "é")[random.nextInt(6)]
        append('<').append(name)
        repeat(random.nextInt(3)) { i ->
            append(listOf(" ", "  ", "\n\t")[random.nextInt(3)])
            val quote = if (random.nextBoolean()) '"' else '\''
            append("k$i").append(listOf("=", " = ")[random.nextInt(2)]).append(quote)
            append(listOf("v", "&amp;", "&#10;", "a b", "").random(random)).append(quote)
        }
        if (depth > 3 || random.nextInt(4) == 0) {
            append(listOf("/>", " />")[random.nextInt(2)])
            return@buildString
        }
        append('>')
        repeat(random.nextInt(4)) {
            when (random.nextInt(5)) {
                0 -> append(generate(random, depth + 1))
                1 -> append(listOf("text", "\r\n\t\t", "a&lt;b", "&#x1F600;", "  ").random(random))
                2 -> append("<!-- c -->")
                3 -> append("<![CDATA[ <x> ]]>")
                else -> append("<?p d?>")
            }
        }
        append("</").append(name).append('>')
    }

    private fun <T> List<T>.random(random: Random) = this[random.nextInt(size)]

    companion object {
        val KEEPASS_SHAPED = """
            |<?xml version="1.0" encoding="utf-8" standalone="yes"?>
            |<KeePassFile>
            |	<Meta>
            |		<Generator>KeePass</Generator>
            |		<RecycleBinEnabled>True</RecycleBinEnabled>
            |		<Unknown a="1"><X>y</X></Unknown>
            |	</Meta>
            |	<Root>
            |		<Group>
            |			<UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
            |			<Name>Root</Name>
            |			<Entry>
            |				<String>
            |					<Key>Title</Key>
            |					<Value>  padded  </Value>
            |				</String>
            |				<String>
            |					<Key>Password</Key>
            |					<Value Protected="True">c2VjcmV0</Value>
            |				</String>
            |				<AutoType>
            |					<Association><Window>w</Window><KeystrokeSequence /></Association>
            |				</AutoType>
            |			</Entry>
            |		</Group>
            |		<DeletedObjects />
            |	</Root>
            |</KeePassFile>
        """.trimMargin().replace("\n", "\r\n")
    }
}

class XmlReaderScalingTest {
    @Test
    fun `parsing time grows linearly with the number of text nodes`() {
        // 16,000 entries of KDBX-shaped XML, about 3.8 MB: a quadratic scan takes about 50 s.
        val entry = "\t\t\t<Entry>\n\t\t\t\t<String>\n\t\t\t\t\t<Key>Title</Key>\n\t\t\t\t\t<Value>t</Value>\n\t\t\t\t</String>\n\t\t\t</Entry>\n"
        val xml = "<KeePassFile>\n" + entry.repeat(16_000) + "</KeePassFile>"
        val started = System.nanoTime()
        kotlin.test.assertIs<XmlReadResult.Parsed>(XmlBytes.parse(xml))
        val seconds = (System.nanoTime() - started) / 1e9
        kotlin.test.assertTrue(seconds < 3.0, "parsing took $seconds s")
    }

    @Test
    fun `a start tag with 120,000 attributes parses in linear time`() {
        // About 960 KB; checking each name against every earlier one takes about 40 s.
        val names = (0 until 120_000).map { "a" + it.toString(36).padStart(4, '0') }
        val xml = names.joinToString(" ", "<a ", "/>") { "$it=\"\"" }
        val started = System.nanoTime()
        val document = assertIs<XmlReadResult.Parsed>(XmlBytes.parse(xml)).document
        val seconds = (System.nanoTime() - started) / 1e9
        assertTrue(seconds < 2.0, "parsing took $seconds s")
        assertEquals("", document.root.attribute(names.last()))
    }

    @ParameterizedTest
    @ValueSource(ints = [2, 8, 9, 10, 100])
    fun `a repeated attribute name is malformed at the repeat, however many attributes come first`(count: Int) {
        val names = (0 until count).map { "n$it" }
        for (repeated in listOf(names.first(), names[count / 2], names.last())) {
            val head = names.joinToString(" ", "<a ") { "$it=\"v\"" }
            val xml = "$head $repeated=\"w\"/>"
            assertEquals(XmlReadResult.Malformed(head.length + 1), XmlBytes.parse(xml), xml)
        }
        assertIs<XmlReadResult.Parsed>(XmlBytes.parse(names.joinToString(" ", "<a ", "/>") { "$it=\"v\"" }))
    }

    @Test
    fun `a byte range parses like a stream of the same bytes`() {
        val doc = "<a><b>x</b></a>".encodeToByteArray()
        val bytes = byteArrayOf(9, 9) + doc + byteArrayOf(7)
        val parsed = assertIs<XmlReadResult.Parsed>(XmlReader.read(bytes, 2, doc.size, doc.size))
        assertEquals("b", parsed.document.root.elements().single().name)
        // The tree points into the caller's array: it is read in place and written from there.
        assertTrue(parsed.document.source.bytes === bytes)
        assertContentEquals(doc, XmlBytes.write(parsed.document))
        parsed.document.root.elements().single().setText("y")
        assertContentEquals("<a><b>y</b></a>".encodeToByteArray(), XmlBytes.write(parsed.document))
        assertEquals(XmlReadResult.TooLarge, XmlReader.read(bytes, 2, doc.size, doc.size - 1))
        assertIs<XmlReadResult.Malformed>(XmlReader.read(byteArrayOf(0x3C, 0xC3.toByte(), 0x3E), 0, 3, 10))
    }
}
