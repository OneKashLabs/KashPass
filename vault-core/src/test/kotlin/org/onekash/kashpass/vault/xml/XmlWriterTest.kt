package org.onekash.kashpass.vault.xml

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class XmlWriterTest {

    private fun parsed(text: String) = (XmlBytes.parse(text) as XmlReadResult.Parsed).document

    @Test
    fun `replacing one text changes only that element's content`() {
        val document = parsed(XmlReaderTest.KEEPASS_SHAPED)
        val title = document.root.child("Root")!!.child("Group")!!.child("Entry")!!.children("String")[0].child("Value")!!
        title.setText("new <title> & more")
        val expected = XmlReaderTest.KEEPASS_SHAPED.replace("<Value>  padded  </Value>", "<Value>new &lt;title&gt; &amp; more</Value>")
        assertEquals(expected, XmlBytes.text(document))
    }

    @Test
    fun `replacing one attribute keeps the other attributes as written`() {
        val document = parsed("<r><a x = 'one'  y=\"two\"/><b/></r>")
        document.root.child("a")!!.setAttribute("y", "t\"wo\n")
        assertEquals("<r><a x = 'one' y=\"t&quot;wo&#xA;\"/><b/></r>", XmlBytes.text(document))
    }

    @Test
    fun `a new attribute is appended`() {
        val document = parsed("<r><a x='1'>t</a></r>")
        document.root.child("a")!!.setAttribute("z", "2")
        assertEquals("<r><a x='1' z=\"2\">t</a></r>", XmlBytes.text(document))
    }

    @Test
    fun `text written with a carriage return and markup reads back the same`() {
        val document = parsed("<r><v/></r>")
        val value = "a\r\nb\rc\td <&> ]]> \"'"
        document.root.child("v")!!.setText(value)
        val written = XmlBytes.text(document)
        assertEquals(value, parsed(written).root.child("v")!!.text())
    }

    @Test
    fun `attribute values with whitespace read back the same`() {
        val document = parsed("<r/>")
        val value = "a\tb\nc\r d <&> \"'"
        document.root.setAttribute("v", value)
        assertEquals(value, parsed(XmlBytes.text(document)).root.attribute("v"))
    }

    @Test
    fun `a self-closing element that gains content gets a start and end tag`() {
        val document = parsed("<r><v Protected=\"True\" /></r>")
        document.root.child("v")!!.setText("x")
        assertEquals("<r><v Protected=\"True\">x</v></r>", XmlBytes.text(document))
    }

    @Test
    fun `inserted, removed and moved elements write only the changed parent`() {
        val document = parsed("<r>\n\t<g1><e>1</e></g1>\n\t<g2>\n\t\t<k/>\n\t</g2>\n</r>")
        val g1 = document.root.child("g1")!!
        val g2 = document.root.child("g2")!!
        val e = g1.child("e")!!
        g1.remove(e)
        g2.insert(1, e)
        g2.insert(0, XmlElement("n").apply { setText("new") })
        assertEquals("<r>\n\t<g1></g1>\n\t<g2><n>new</n>\n\t\t<e>1</e><k/>\n\t</g2>\n</r>", XmlBytes.text(document))
    }

    @Test
    fun `a deep copy writes the same bytes and is independent of the original`() {
        val document = parsed("<r><e a='1'><s>x</s><!-- c --></e></r>")
        val entry = document.root.child("e")!!
        val copy = entry.deepCopy()
        copy.child("s")!!.setText("changed")
        document.root.append(copy)
        assertEquals("<r><e a='1'><s>x</s><!-- c --></e><e a='1'><s>changed</s><!-- c --></e></r>", XmlBytes.text(document))
    }

    @Test
    fun `a value with characters XML 1_0 forbids is refused`() {
        val element = parsed("<r/>").root
        assertFailsWith<IllegalArgumentException> { element.setText("a\u0001b") }
        assertFailsWith<IllegalArgumentException> { element.setText("a\uD800b") }
        assertFailsWith<IllegalArgumentException> { element.setAttribute("v", "￾") }
    }

    @Test
    fun `an element already in a tree cannot be inserted twice`() {
        val document = parsed("<r><a/></r>")
        assertFailsWith<IllegalArgumentException> { document.root.append(document.root.child("a")!!) }
    }

    @Test
    fun `the written document parses again`() {
        val document = parsed(XmlReaderTest.KEEPASS_SHAPED)
        document.root.child("Meta")!!.child("Generator")!!.setText("KashPass")
        assertIs<XmlReadResult.Parsed>(XmlBytes.parse(XmlBytes.write(document)))
    }

    @Test
    fun `an unedited document is written byte for byte, line ends and non-ASCII text kept`() {
        val text = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<r a='é'>\r\n\t<v>😀 ü\r\n</v>\r\n</r>\r\n"
        assertContentEquals(text.encodeToByteArray(), XmlBytes.write(parsed(text)))
        // With hooks every element is walked, and unchanged nodes are copied as bytes.
        assertContentEquals(text.encodeToByteArray(), XmlBytes.write(parsed(text), object : XmlWriter.Hooks {}))
    }

    @Test
    fun `an edited node is encoded as UTF-8 on its own`() {
        val document = parsed("<r>\r\n<v>a</v><w>é</w></r>")
        document.root.child("v")!!.setText("😀 ü <")
        assertContentEquals("<r>\r\n<v>😀 ü &lt;</v><w>é</w></r>".encodeToByteArray(), XmlBytes.write(document))
    }

    @Test
    fun `a content hook writes bytes in place of the children`() {
        val document = parsed("<r><p Protected=\"True\">old</p><q>keep</q><e Protected=\"True\" /><f Protected=\"True\">x</f></r>")
        val hooks = object : XmlWriter.Hooks {
            override fun content(element: XmlElement, sink: ByteSink): Boolean = when (element.name) {
                "p" -> {
                    sink.write(byteArrayOf(0x41, 0x42))
                    true
                }
                // An empty replacement keeps an element that is empty as written as it was.
                "e", "f" -> true
                else -> false
            }
        }
        assertEquals("<r><p Protected=\"True\">AB</p><q>keep</q><e Protected=\"True\" /><f Protected=\"True\"></f></r>", XmlBytes.text(document, hooks))
    }

    @Test
    fun `a prepend hook writes before the first child, and opens a self-closing or empty element`() {
        val document = parsed("<r><m>\n\t<a>1</a></m><e /><f></f><g>x</g></r>")
        val hooks = object : XmlWriter.Hooks {
            override fun prepend(element: XmlElement, sink: ByteSink) {
                if (element.name in setOf("m", "e", "f")) sink.writeUtf8("<n>new</n>")
            }
        }
        assertEquals("<r><m><n>new</n>\n\t<a>1</a></m><e><n>new</n></e><f><n>new</n></f><g>x</g></r>", XmlBytes.text(document, hooks))
        assertEquals("<r><m>\n\t<a>1</a></m><e /><f></f><g>x</g></r>", XmlBytes.text(document))
    }

    @Test
    fun `an attribute hook changes the written value without touching the tree`() {
        val text = "<r><b Ref=\"1\"/><b Ref='2' x = 'y'>t</b><c Ref=\"2\"></c></r>"
        val document = parsed(text)
        val hooks = object : XmlWriter.Hooks {
            override fun attribute(element: XmlElement, name: String) =
                if (element.name == "b" && name == "Ref") (element.attribute(name)!!.toInt() + 4).toString() else null
        }
        assertEquals("<r><b Ref=\"5\"/><b Ref=\"6\" x = 'y'>t</b><c Ref=\"2\"></c></r>", XmlBytes.text(document, hooks))
        assertEquals(listOf("1", "2"), document.root.children("b").map { it.attribute("Ref") })
        assertFalse(document.root.subtreeChanged)
        assertEquals(text, XmlBytes.text(document))
        val refused = object : XmlWriter.Hooks {
            override fun attribute(element: XmlElement, name: String) = "a\u0001"
        }
        assertFailsWith<IllegalArgumentException> { XmlBytes.write(document, refused) }
    }

    @Test
    fun `an attribute hook applies to an element whose content a hook replaces`() {
        val document = parsed("<r><v Ref=\"1\" Protected=\"True\">x</v></r>")
        val hooks = object : XmlWriter.Hooks {
            override fun attribute(element: XmlElement, name: String) = if (name == "Ref") "0" else null
            override fun content(element: XmlElement, sink: ByteSink): Boolean {
                if (element.name != "v") return false
                sink.writeUtf8("y")
                return true
            }
        }
        assertEquals("<r><v Ref=\"0\" Protected=\"True\">y</v></r>", XmlBytes.text(document, hooks))
    }

    @Test
    fun `the sink grows through its allocator, zero-fills what it drops and hands over its array`() {
        val allocated = mutableListOf<ByteArray>()
        val sink = ByteSink({ size -> ByteArray(size).also { allocated += it } }, initialCapacity = 16)
        val data = ByteArray(100) { (it + 1).toByte() }
        sink.write(data)
        assertTrue(allocated.size > 1)
        assertTrue(sink.buffer === allocated.last())
        assertEquals(100, sink.size)
        assertContentEquals(data, sink.buffer.copyOf(sink.size))
        for (old in allocated.dropLast(1)) assertTrue(old.all { it.toInt() == 0 }, "a replaced array is zero-filled")
        sink.truncate(10)
        assertTrue(sink.buffer.drop(10).all { it.toInt() == 0 })
        sink.clear()
        assertEquals(0, sink.size)
        assertTrue(sink.buffer.all { it.toInt() == 0 })
    }

    @Test
    fun `the sink gives back each array it outgrows, zero-filled, and grows a large one by its need plus a step`() {
        val allocated = mutableListOf<ByteArray>()
        val released = mutableListOf<ByteArray>()
        val sink = ByteSink({ size -> ByteArray(size).also { allocated += it } }, initialCapacity = 16) { old ->
            assertTrue(old.all { it.toInt() == 0 }, "a released array is zero-filled")
            released += old
        }
        sink.write(ByteArray(100) { 1 })
        assertEquals(200, sink.buffer.size, "a small sink holds twice its need")
        val large = 3 * ByteSink.GROWTH_STEP.toInt()
        sink.write(ByteArray(large - 100) { 2 })
        assertEquals(large + ByteSink.GROWTH_STEP.toInt(), sink.buffer.size, "a large sink holds its need plus the step")
        assertEquals(allocated.dropLast(1).map { System.identityHashCode(it) }, released.map { System.identityHashCode(it) })
        assertTrue(sink.buffer === allocated.last())
    }

    @Test
    fun `the sink writes UTF-8, a lone surrogate as U+FFFD`() {
        val sink = ByteSink(::ByteArray)
        sink.writeUtf8("aé€😀\uD800b\uDC00")
        val expected = "aé€😀\uFFFDb\uFFFD".encodeToByteArray()
        assertContentEquals(expected, sink.buffer.copyOf(sink.size))
    }
}
