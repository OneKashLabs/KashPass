package org.onekash.kashpass.vault.doc

import java.io.File
import java.time.Duration
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDelete
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.open.VaultSession
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage

/**
 * Edits, adds and deletes an entry in a KeePass 2 fixture, saving after each change as the app
 * does, reopens the result and checks every change. With -Pkashpass.interop.out=<dir> it also
 * writes the saved vault there.
 */
object InteropRoundTrip {

    private const val loc = "content://fake/interop.kdbx"
    private val now = Instant.parse("2026-10-20T12:00:00Z")

    /** Password fixtures the round trip runs on. */
    val passwordFixtures = listOf(
        "keepass2-default-aeskdf.kdbx", "keepass2-argon2id.kdbx", "keepass2-chacha20-argon2d.kdbx",
        "keepass2-kdbx41-tags.kdbx", "keepass2-weak-aeskdf-6000.kdbx", "keepass2-desktop-new-database.kdbx",
    )

    /** Key-file fixtures: vault, whether it also needs the password, key file. */
    val keyFileFixtures = listOf(
        Triple("keepass2-password-keyfile-v2.kdbx", true, "keepass2-keyfile-v2.keyx"),
        Triple("keepass2-keyfile-only-v1.kdbx", false, "keepass2-keyfile-v1.key"),
        Triple("keepass2-keyfile-only-hex64.kdbx", false, "keepass2-keyfile-hex64.key"),
    )

    /** Runs the round trip on fixture [name] and returns the bytes of the last save. */
    fun run(name: String, password: String, keyFileName: String?): ByteArray = runBlocking {
        // Each open gets its own copy: vault-core zero-fills the key-file bytes it is given.
        fun keyFile() = keyFileName?.let { VaultXmlCodecTest.fixture(it) }
        val storage = FakeVaultStorage().apply { put(loc, VaultXmlCodecTest.fixture(name)) }
        val state = FakeVaultStateStore()
        val opener = VaultOpener.create(storage, state, Dispatchers.IO)
        val saver = SafeSaver(storage, FakeBackupStore(), FakeSaveMarkerStore(), state, Dispatchers.IO, CoroutineScope(SupervisorJob() + Dispatchers.IO), Duration.ofSeconds(30))
        var session = (opener.open(loc, password.toCharArray(), keyFile = keyFile()) as OpenResult.Unlocked).session
        val rows = session.index.rows(Chip.All, "")
        val edited = rows.first()
        val deleted = rows.last()
        val historyBefore = history(session, edited.id)

        suspend fun save(document: VaultDocument) {
            val saved = assertIs<SaveResult.Saved>(saver.save(loc, session.opened.withDocument(document)), name)
            session = VaultSession.from(saved.opened)
        }

        val draft = EntryEdits.draftOf(session.opened.document, edited.id)!!
        save(assertIs<EditResult.Changed>(EntryEdits.edit(session.opened.document, edited.id, EntryDraft("Edited by KashPass", draft.userName, ProtectedText.of("new-password"), draft.url, draft.notes), now)).document)
        val group = EntryEdits.groups(session.opened.document).first { !it.isTopLevel }
        save(EntryEdits.add(session.opened.document, group.id, EntryDraft("Added by KashPass", "phone", ProtectedText.of("generated"), "https://example.test", ""), now).document)
        val removal = EntryDelete.delete(session.opened.document, deleted.id, now)!!
        save(removal.document)

        val reopened = (opener.open(loc, password.toCharArray(), keyFile = keyFile()) as OpenResult.Unlocked).session
        val titles = reopened.index.rows(Chip.All, "").map { it.title }
        assertTrue("Edited by KashPass" in titles, "$name: $titles")
        assertTrue("Added by KashPass" in titles)
        assertTrue(deleted.title !in titles)
        assertEquals(historyBefore + 1, history(reopened, edited.id))
        assertEquals("new-password", EntryEdits.draftOf(reopened.opened.document, edited.id)!!.password.reveal())
        assertEquals(org.onekash.kashpass.vault.edit.DeleteKind.TO_RECYCLE_BIN, removal.kind, "every fixture has the bin on")
        assertTrue(reopened.index.rows(Chip.RecycleBin, "").any { it.title == deleted.title })
        assertEquals(Saveability.Saveable, reopened.saveability)

        // Then delete it again from the bin: permanent, with a DeletedObject record.
        val inBin = session.index.rows(Chip.RecycleBin, "").first { it.title == deleted.title }
        val permanent = EntryDelete.delete(session.opened.document, inBin.id, now)!!
        assertEquals(org.onekash.kashpass.vault.edit.DeleteKind.PERMANENT, permanent.kind)
        save(permanent.document)
        val finalDoc = (opener.open(loc, password.toCharArray(), keyFile = keyFile()) as OpenResult.Unlocked).session
        assertTrue(finalDoc.index.rows(Chip.RecycleBin, "").none { it.title == deleted.title })
        assertEquals(1, finalDoc.opened.document.xml.root.child("Root")!!.child("DeletedObjects")!!.children("DeletedObject").size)

        val savedBytes = storage.bytes(loc)!!
        System.getProperty("kashpass.interop.out")?.let { dir ->
            File(dir).mkdirs()
            File(dir, name).writeBytes(savedBytes)
            File(dir, "$name.expected").writeText(
                "edited ${edited.title} -> Edited by KashPass\nadded Added by KashPass in ${group.label}\n" +
                    "deleted ${deleted.title} (${removal.kind}), then permanently from the bin\n",
            )
            assertTrue(File(dir, name).length() > 0)
        }
        savedBytes
    }

    private fun history(session: VaultSession, id: String): Int =
        DocumentIds.entries(session.opened.document)[id]!!.child("History")?.children("Entry")?.size ?: 0
}
