package org.onekash.kashpass.vault.property

import io.kotest.property.checkAll
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.index.documentOf
import org.onekash.kashpass.vault.keepass2.DocumentReport
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.VaultModel
import org.w3c.dom.Element

/**
 * Any generated vault, opened by KashPass and saved with no edit, opens again with the same
 * content, and the test toolkit, which shares no container code with KashPass, reads every
 * generated field (history included) with its protected flag, each entry's attachments by name
 * and bytes, and the group tree from the save.
 */
class RoundTripProperties {

    @Test
    fun `any generated vault saves with no edit and reads back the same in KashPass and the toolkit`() = runBlocking<Unit> {
        val key = ByteArray(32) { it.toByte() }
        checkAll(PropertyRuns.config(40), Generators.doc) { doc ->
            val opened = documentOf(VaultModel.write(doc, aesRounds = 1UL))
            val save = VaultXmlCodec.encodeBytes(opened)
            assertEquals(DocumentReport.of(opened, key), DocumentReport.of(documentOf(save), key), "KashPass reads its save as the vault it opened")
            val layers = KdbxToolkit.open(save, KdbxToolkit.Key(TestVaults.PASSWORD)).layers
            val pool = layers.inner.filter { it.id == KdbxToolkit.INNER_BINARY }.map { it.data.copyOfRange(1, it.data.size) }
            val xml = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(layers.xml.inputStream()).documentElement
            // The toolkit gives protected values in document order, as the XML lists them.
            val values = xml.getElementsByTagName("Value")
            val protectedText = HashMap<Element, String>()
            var next = 0
            for (i in 0 until values.length) {
                val v = values.item(i) as Element
                if (v.getAttribute("Protected") == "True") protectedText[v] = layers.protectedValues[next++].toString(Charsets.UTF_8)
            }
            val root = children(children(xml, "Root").single(), "Group").single()
            group(doc.root, root, doc, pool, protectedText)
        }
    }

    private fun group(model: VaultModel.Group, element: Element, doc: VaultModel.Doc, pool: List<ByteArray>, protectedText: Map<Element, String>) {
        assertEquals(model.name, text(children(element, "Name").single()), "group name")
        val groups = children(element, "Group")
        assertEquals(model.groups.map { it.name }, groups.map { text(children(it, "Name").single()) }, "subgroups of ${model.name}")
        model.groups.zip(groups).forEach { (m, e) -> group(m, e, doc, pool, protectedText) }
        val entries = children(element, "Entry")
        assertEquals(model.entries.size, entries.size, "entries of ${model.name}")
        model.entries.zip(entries).forEach { (m, e) -> entry(m, e, doc, pool, protectedText) }
    }

    private fun entry(model: VaultModel.Entry, element: Element, doc: VaultModel.Doc, pool: List<ByteArray>, protectedText: Map<Element, String>) {
        val fields = children(element, "String").associate { s ->
            val v = children(s, "Value").single()
            text(children(s, "Key").single()) to (if (v.getAttribute("Protected") == "True") VaultModel.Value.Protected(protectedText.getValue(v)) else VaultModel.Value.Plain(text(v)))
        }
        assertEquals(model.fields.toMap(), fields, "fields of an entry")
        val binaries = children(element, "Binary").associate { b -> text(children(b, "Key").single()) to pool[children(b, "Value").single().getAttribute("Ref").toInt()] }
        assertEquals(model.binaries.map { it.first }.toSet(), binaries.keys, "attachment names")
        for ((name, ref) in model.binaries) assertContentEquals(doc.attachments[ref], binaries.getValue(name), "attachment $name")
        val history = children(element, "History").flatMap { children(it, "Entry") }
        assertEquals(model.history.size, history.size, "history items")
        model.history.zip(history).forEach { (m, e) -> entry(m, e, doc, pool, protectedText) }
    }

    private fun children(e: Element, name: String): List<Element> =
        (0 until e.childNodes.length).map { e.childNodes.item(it) }.filterIsInstance<Element>().filter { it.tagName == name }

    private fun text(e: Element): String = e.textContent
}
