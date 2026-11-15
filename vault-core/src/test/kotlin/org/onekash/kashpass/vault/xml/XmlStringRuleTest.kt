package org.onekash.kashpass.vault.xml

import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.testing.KotlinSourceText

/**
 * The XML reader and the container build no String of the whole document: in vault.xml every
 * String made from bytes comes from [XmlSource.string], one node at a time, and no main source in
 * vault.xml or vault.kdbx builds a String from bytes without "// allowed: <reason>" on the line
 * before. The codec that writes a save's XML ([org.onekash.kashpass.vault.doc.VaultXmlCodec])
 * builds none at all.
 */
class XmlStringRuleTest {

    private val root = File("src/main/kotlin/org/onekash/kashpass/vault")

    // String(...), decodeToString, toString with an argument (a charset), a charset decoder.
    private val fromBytes = Regex(
        """(?<![\w.`])String\s*\(|\bdecodeToString\b|\btoString\s*\(\s*[^)\s]|\bnewDecoder\b|\bCharsets\s*\.\s*\w+\s*\.\s*decode\b""",
    )

    /**
     * Returns the 1-based lines of [source] that build a String from bytes: those the line before
     * allows, then the others.
     */
    private fun matches(source: String): Pair<List<Int>, List<Int>> {
        val lines = source.lines()
        val found = KotlinSourceText.references(source, fromBytes).map { it.first }.distinct()
        return found.partition { line -> line >= 2 && lines[line - 2].trim().startsWith("// allowed:") }
    }

    private fun sources(dir: String): List<File> =
        File(root, dir).walkTopDown().filter { it.isFile && it.extension == "kt" }.sortedBy { it.path }.toList()

    @Test
    fun `no main source in vault xml or vault kdbx builds a String from bytes without allowed`() {
        val xml = sources("xml")
        val kdbx = sources("kdbx")
        assertTrue(xml.any { it.name == "XmlReader.kt" } && kdbx.any { it.name == "KdbxDecoder.kt" }, "no sources under ${root.absolutePath}")
        val unmarked = (xml + kdbx).flatMap { file -> matches(file.readText()).second.map { "${file.relativeTo(root)}:$it" } }
        assertEquals(emptyList(), unmarked)
    }

    @Test
    fun `vault xml decodes bytes in one helper only`() {
        val allowed = sources("xml").flatMap { file -> matches(file.readText()).first.map { file.name to it } }
        assertEquals(listOf("XmlSource.kt"), allowed.map { it.first })
        val source = File(root, "xml/XmlSource.kt").readText()
        val code = KotlinSourceText.codeLines(source)
        val helper = code.indexOfFirst { it.contains("fun string(") } + 1
        assertTrue(helper > 0 && allowed.single().second in helper..helper + 2, "the allowed line is in XmlSource.string")
        // toString on the sink or the source would build a String of their content.
        for (name in listOf("ByteSink.kt", "XmlSource.kt")) {
            val text = File(root, "xml/$name").readText()
            assertEquals(emptyList(), KotlinSourceText.references(text, Regex("""\bfun\s+toString\b""")), name)
        }
    }

    @Test
    fun `the codec's encode path builds no String from bytes`() {
        val codec = File(root, "doc/VaultXmlCodec.kt")
        assertTrue(codec.isFile, "no codec under ${root.absolutePath}")
        assertEquals(emptyList<Int>() to emptyList(), matches(codec.readText()))
    }

    @Test
    fun `the rule catches a planted String built from bytes`() {
        val planted = listOf(
            "fun f(b: ByteArray, sink: ByteSink, sb: StringBuilder) {",
            "    val a = String(b, Charsets.UTF_8)",
            "    val c = b.decodeToString()",
            "    val d = b.toString(Charsets.UTF_8)",
            "    val e = sink.buffer.toString(Charsets.UTF_8)",
            "    val g = Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(b))",
            "    val h = Charsets.UTF_8.decode(java.nio.ByteBuffer.wrap(b))",
            "    // allowed: a planted exception",
            "    val i = String(b, 0, 1, Charsets.UTF_8)",
            "    val ok = sb.toString() + buildString { } + java.util.UUID.fromString(\"String(b)\") // String(b)",
            "}",
        ).joinToString("\n")
        val (allowed, unmarked) = matches(planted)
        assertEquals(listOf(2, 3, 4, 5, 6, 7), unmarked)
        assertEquals(listOf(9), allowed)
    }
}
