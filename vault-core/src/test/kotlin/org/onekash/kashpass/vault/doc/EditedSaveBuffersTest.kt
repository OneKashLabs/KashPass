package org.onekash.kashpass.vault.doc

import java.time.Instant
import java.util.Collections
import java.util.IdentityHashMap
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.kdbx.Buffers
import org.onekash.kashpass.vault.testing.RecordingBuffers

/**
 * A save whose XML outgrows the payload buffer sized from the opened vault gives every outgrown
 * buffer back as it grows, so the encode never holds more than two arrays the size of the
 * attachments at once: the payload buffer and its replacement while it grows, or the payload
 * and its compressed copy. The inner header is copied into the payload buffer and never held in
 * an array of its own.
 */
class EditedSaveBuffersTest {

    // Records which large arrays are handed out and not yet released at every allocation.
    private class LiveBuffers(private val recording: RecordingBuffers, private val large: Int) : Buffers {
        private val live: MutableSet<ByteArray> = Collections.newSetFromMap(IdentityHashMap())
        var mostLive = 0
            private set

        override fun bytes(size: Int): ByteArray = recording.bytes(size).also {
            if (size >= large) live += it
            mostLive = maxOf(mostLive, live.size)
        }

        override fun ints(size: Int) = recording.ints(size)

        override fun release(array: ByteArray) {
            recording.release(array)
            live -= array
        }
    }

    @Test
    fun `a save whose edits outgrow the payload buffer releases each outgrown buffer, with no inner header copy`() {
        val opened = VaultXmlCodecTest.decode(VaultXmlCodecTest.fixture("keepass2-multiblock-attachment.kdbx"), VaultXmlCodecTest.fixturePassword)
        val attachmentBytes = opened.attachments.maxOf { it.data.size }
        assertTrue(attachmentBytes > 1024 * 1024)
        var document = opened
        for ((k, id) in DocumentIds.entries(opened).keys.withIndex()) {
            val draft = assertIsNotNull(EntryEdits.draftOf(document, id))
            val notes = draft.notes + "edit $k ".repeat(32 * 1024)
            val edit = EntryEdits.edit(document, id, EntryDraft(draft.title, draft.userName, draft.password, draft.url, notes), Instant.EPOCH)
            document = assertIs<EditResult.Changed>(edit).document
        }
        val recording = RecordingBuffers()
        val buffers = LiveBuffers(recording, large = attachmentBytes)
        val encoded = assertIs<Encoded.Bytes>(VaultXmlCodec.encode(document, derive = KdfEngine(), buffers = buffers))
        assertTrue(encoded.xmlBytes > opened.xmlBytes + 256 * 1024, "the XML grew by ${encoded.xmlBytes - opened.xmlBytes} bytes")

        val large = recording.byteSizes.filter { it >= attachmentBytes }
        assertTrue(large.first() < encoded.payloadBytes, "the payload buffer sized from the opened vault was outgrown: $large")
        // The last large array is the compressed payload, encrypted in place into the file.
        assertEquals(large.dropLast(1).sorted(), recording.releasedSizes.filter { it >= attachmentBytes }.sorted(), "large arrays released")
        assertEquals(2, buffers.mostLive, "large arrays live at once")
        recording.assertAllZero()
        val reopened = VaultXmlCodecTest.decode(encoded.bytes, VaultXmlCodecTest.fixturePassword)
        assertEquals(opened.attachments.map { it.data.toList() }, reopened.attachments.map { it.data.toList() })
        assertEquals(notes(document), notes(reopened))
    }

    private fun notes(document: VaultDocument): List<String> =
        DocumentIds.entries(document).keys.map { id -> EntryEdits.draftOf(document, id)!!.notes }

    private fun <T : Any> assertIsNotNull(value: T?): T = value ?: throw AssertionError("expected a value")
}
