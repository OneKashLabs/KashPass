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
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.KdbxSignature
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * Every vault KashPass's decoder opens editable saves through [VaultXmlCodec.encode] and reopens
 * in KashPass's decoder with the same content; the gated KeePass2SaveTest has KeePass 2 read the
 * same saves.
 */
class DocumentRoundTripTest {

    private fun read(file: VaultFile): ContainerRead = assertIs<ContainerDecode.Result.Opened>(ContainerRig.open(file), file.name).read

    private fun document(file: VaultFile) = VaultXmlCodec.document(read(file), TestFiles.credentials(file), ContainerRig.LIMITS)

    // Every element by path with its text, protected values as plaintext and attachment references
    // as the bytes they name: what both readers must agree on.
    private fun content(root: XmlElement, values: Map<XmlElement, ProtectedText>, attachment: (XmlElement, Int) -> ByteArray?): List<String> {
        val out = mutableListOf<String>()
        val omitted = EntryParts.omitted(root)
        fun walk(e: XmlElement, path: String) {
            val here = "$path/${e.name}"
            // A save leaves out Meta/HeaderHash and the entry parts in [EntryParts.omitted]
            // ([EncodeHooks]).
            if (here == "/KeePassFile/Meta/HeaderHash" || e in omitted) return
            val ref = e.attribute("Ref")?.trim()?.toIntOrNull()
            out += when {
                values.containsKey(e) -> "$here protected ${values.getValue(e).reveal()}"
                ref != null && e.name == "Value" && e.parent?.name == "Binary" -> "$here attachment ${attachment(e, ref)?.toList()}"
                e.hasElementChildren -> here
                else -> "$here ${e.text().trim()}"
            }
            e.elements().forEach { walk(it, here) }
        }
        walk(root, "")
        return out
    }

    // A save writes Meta/Generator as KashPass, adding it first in Meta when missing
    // ([EncodeHooks]).
    private fun withSavedGenerator(content: List<String>): List<String> {
        val generator = "/KeePassFile/Meta/Generator"
        if (content.none { it.startsWith("$generator ") }) {
            val at = content.indexOf("/KeePassFile/Meta")
            return if (at < 0) content else content.toMutableList().apply { add(at + 1, "$generator KashPass") }
        }
        return content.map { if (it.startsWith("$generator ") && !it.startsWith("$generator protected ")) "$generator KashPass" else it }
    }

    private fun roundTrip(file: VaultFile) {
        val before = read(file)
        // Before the document renumbers the references in the tree.
        val expected = withSavedGenerator(content(before.xml.root, before.protectedValues) { e, ref -> if (before.references.containsKey(e)) before.references[e]?.data else before.pool[ref]?.data })
        val document = VaultXmlCodec.document(before, TestFiles.credentials(file), ContainerRig.LIMITS)
        assertEquals(Saveability.Saveable, document.saveability, file.name)
        val saved = VaultXmlCodec.encodeBytes(document)
        val again = read(VaultFile(file.name, saved, file.mode, file.keyFileName, file.keyFile))
        assertEquals(expected, content(again.xml.root, again.protectedValues) { e, ref -> if (again.references.containsKey(e)) again.references[e]?.data else again.pool[ref]?.data }, file.name)
        assertEquals(before.container.header.kdf.toSettings(), again.container.header.kdf.toSettings(), file.name)
        assertEquals(KdbxSignature.NORMAL, again.container.header.signature)
        assertTrue(again.container.header.minorVersion <= 1)
        assertNull(again.xml.root.child("Meta")?.child("Binaries"))
        val ids = RawKdbx.parse(saved).fields.map { it.id }.toSet()
        assertTrue(ids.all { it in setOf(0, 2, 3, 4, 7, 11, 12) }, "${file.name}: $ids")
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    fun `every fixture saves and reopens the same in both decoders`(name: String) = roundTrip(Fixtures.file(Fixtures.named(name)))

    @Test
    fun `every editable corpus case saves and reopens the same`() {
        val editable = Corpus.all.filter { it.spec == Spec.OPENS && !it.name.startsWith("truncated") }
        assertTrue(editable.size > 50, "${editable.size} cases")
        val bad = editable.mapNotNull { c -> runCatching { roundTrip(c.file()) }.exceptionOrNull()?.let { "${c.name}: ${it.message}" } }
        assertTrue(bad.isEmpty(), bad.joinToString("\n"))
    }

    @Test
    fun `the pre-release signature and a 4 2 file save as KeePass 2 writes them`() {
        for (name in listOf("spec-signature-pre-release", "header-version-4-2")) {
            val c = Corpus.all.single { it.name == name }
            val saved = VaultXmlCodec.encodeBytes(document(c.file()))
            val header = assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(saved)).header
            assertEquals(KdbxSignature.NORMAL, header.signature, name)
            assertEquals(if (name == "header-version-4-2") 1 else c.let { assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(it.bytes)).header.minorVersion }, header.minorVersion, name)
        }
    }

    @Test
    fun `Meta Binaries items are saved into the inner header`() {
        val c = Corpus.all.single { it.name == "spec-meta-binary-new" }
        val saved = VaultXmlCodec.encodeBytes(document(c.file()))
        val again = read(c.file().let { VaultFile(it.name, saved, it.mode, it.keyFileName, it.keyFile) })
        assertEquals(listOf("third item"), again.references.values.filterNotNull().map { String(it.data) }.filter { it == "third item" })
        assertEquals(2, again.container.inner.attachments.size)
        assertNull(again.xml.root.child("Meta")!!.child("Binaries"))
    }

    @Test
    fun `duplicate, sparse, replaced and unreferenced pools open editable, and a Ref that names no item opens read-only`() {
        fun case(name: String): CorpusCase = Corpus.all.single { it.name == name }
        val editable = listOf(
            "attachment-identical-pool-items", "spec-meta-binary-sparse-id", "spec-meta-binary-id-max", "attachment-unreferenced-pool-item",
            "spec-meta-binary-after-root-replaces-0", "spec-meta-binary-protected-unreferenced",
        )
        for (name in editable) assertEquals(Saveability.Saveable, document(case(name).file()).saveability, name)
        for (name in listOf("attachment-reference-out-of-range", "attachment-reference-negative", "spec-meta-binary-after-root-new-id")) {
            assertEquals(Saveability.ReadOnly(ReadOnlyReason.ATTACHMENT_REF_OUT_OF_RANGE), document(case(name).file()).saveability, name)
        }
    }

    companion object {
        @JvmStatic
        fun fixtures(): List<String> = Fixtures.kdbx4Opening.map { it.name }
    }
}
