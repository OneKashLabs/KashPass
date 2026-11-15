package org.onekash.kashpass.vault.save

import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.doc.BinaryPool
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.EncodeHooks
import org.onekash.kashpass.vault.doc.EntryParts
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.decode
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.doc.parseInt32Invariant
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.VaultIndex
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.xml.XmlBytes

/**
 * Every KeePass 2 fixture and every corpus case that opens editable is opened, edited, saved
 * through [SafeSaver] with KashPass's own encoder, and reopened by KashPass's decoder with the
 * edit, each attachment reference naming the same content, and no bytes after the end block.
 */
class OwnedSaveRoundTripTest {

    private val loc = "content://fake/vault.kdbx"
    private val now = Instant.now().truncatedTo(ChronoUnit.SECONDS)
    private val writers = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @AfterEach
    fun tearDown() = writers.cancel()

    // Each entry attachment as name=content, in document order, by its last Key, the one that
    // takes effect.
    private fun named(document: VaultDocument): List<String> = BinaryPool.values(document.xml.root).map {
        val content = document.attachments.getOrNull(parseInt32Invariant(it.attribute("Ref")) ?: -1)?.data?.toList()
        EntryParts.key(it.parent!!)?.text() + "=" + content
    }

    // The XML of [document] as a save writes it ([EncodeHooks]), each protected value as the
    // Base64 of its plaintext, with no stream applied.
    private fun written(document: VaultDocument): String {
        val rebuilt = BinaryPool.rebuild(document)
        return XmlBytes.text(document.xml, EncodeHooks(document, rebuilt::ref) {})
    }

    private fun roundTrip(file: VaultFile) = runBlocking {
        val credentials = TestFiles.credentials(file)
        val document = VaultXmlCodec.decode(file.bytes, credentials, ContainerRig.LIMITS).let { assertIs<Decoded.Opened>(it, file.name).document }
        assertEquals(Saveability.Saveable, document.saveability, file.name)
        var edited = EntryEdits.add(document, null, EntryDraft("Saved by KashPass", "user", ProtectedText.of("pass"), "", ""), now).document
        val row = VaultIndex.from(edited).rows(Chip.All, "").firstOrNull { it.title != "Saved by KashPass" }
        if (row != null) {
            val draft = EntryEdits.draftOf(edited, row.id)!!
            val result = EntryEdits.edit(edited, row.id, EntryDraft(draft.title + " edited", draft.userName, draft.password, draft.url, draft.notes), now)
            edited = assertIs<EditResult.Changed>(result, file.name).document
        }
        val storage = FakeVaultStorage().apply { put(loc, file.bytes) }
        val saver = SafeSaver(storage, FakeBackupStore { now }, FakeSaveMarkerStore(), FakeVaultStateStore(), Dispatchers.IO, writers, maxHeapBytes = { 1L shl 30 })
        val vault = OpenedVault(edited, OpenedVault.Baseline.Known(Sha256.hex(file.bytes)), file.bytes.size.toLong(), now, UnlockOrigin.PASSWORD)
        assertIs<SaveResult.Saved>(saver.save(loc, vault), file.name)
        val saved = storage.bytes(loc)!!
        val reopened = assertIs<Decoded.Opened>(VaultXmlCodec.decode(saved, credentials, ContainerRig.LIMITS), file.name)
        assertFalse(reopened.bytesAfterEnd, file.name)
        val titles = VaultIndex.from(reopened.document).rows(Chip.All, "").map { it.title }
        assertTrue("Saved by KashPass" in titles, file.name)
        if (row != null) assertTrue(row.title + " edited" in titles, file.name)
        assertEquals(named(edited), named(reopened.document), file.name)
        assertEquals(Saveability.Saveable, reopened.document.saveability, file.name)
    }

    @ParameterizedTest
    @MethodSource("fixtures")
    fun `every fixture saves with an edit and reopens with it`(name: String) = roundTrip(Fixtures.file(Fixtures.named(name)))

    @Test
    fun `an unedited save writes the same XML as a save of the reopened file, minus the parts KeePass 2 reads past`() {
        val sources = Fixtures.kdbx4Opening.map { Fixtures.file(it) } + Corpus.all.filter { it.spec == Spec.OPENS }.map { it.file() }
        val withOmitted = mutableListOf<String>()
        val bad = sources.mapNotNull { file ->
            val credentials = TestFiles.credentials(file)
            val document = assertIs<Decoded.Opened>(VaultXmlCodec.decode(file.bytes, credentials, ContainerRig.LIMITS), file.name).document
            if (EntryParts.omitted(document.xml.root).isNotEmpty()) withOmitted += file.name.removeSuffix(".kdbx")
            val saved = assertIs<Decoded.Opened>(VaultXmlCodec.decode(VaultXmlCodec.encodeBytes(document), credentials, ContainerRig.LIMITS), file.name).document
            file.name.takeIf { written(document) != written(saved) }
        }
        assertTrue(bad.isEmpty(), bad.joinToString())
        assertEquals(DUPLICATE_SHAPES, withOmitted.toSet(), "only the cases with duplicate entry parts leave anything out")
    }

    @Test
    fun `every corpus case that opens editable saves with an edit and reopens with it`() {
        val editable = Corpus.all.filter { it.spec == Spec.OPENS }
        assertTrue(editable.size > 50, "${editable.size} cases")
        val bad = editable.mapNotNull { c -> runCatching { roundTrip(c.file()) }.exceptionOrNull()?.let { "${c.name}: ${it.message}" } }
        assertTrue(bad.isEmpty(), bad.joinToString("\n"))
    }

    companion object {
        // The corpus cases whose entries hold parts a read skips (EntryParts.omitted).
        private val DUPLICATE_SHAPES = setOf("xml-string-value-twice", "xml-string-key-twice", "xml-binary-value-twice", "xml-binary-key-twice", "xml-history-in-history-entry")

        @JvmStatic
        fun fixtures(): List<String> = Fixtures.kdbx4Opening.map { it.name }
    }
}
