package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import kotlin.test.fail
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDelete
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage

/**
 * Runs [CompanionOp]s as the app does: opens the vault through [VaultOpener], applies the
 * ops with [EntryEdits] and [EntryDelete] at one time, and saves once with [SafeSaver] over the
 * shared storage fake. Fails the test naming the file and op when a step does not succeed.
 */
internal object CompanionRig {

    private const val LOCATION = "content://fake/companion.kdbx"

    /**
     * Opens [file] as the app does and returns the result; an unlocked session is released before
     * returning, so only the result's kind and details are usable.
     */
    fun openResult(file: VaultFile): OpenResult = runBlocking {
        val storage = FakeVaultStorage().apply { put(LOCATION, file.bytes) }
        VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO).open(LOCATION, password(file), keyFile = file.keyFile?.copyOf())
            .also { (it as? OpenResult.Unlocked)?.session?.release() }
    }

    /** Opens [file] as the app does and returns the unlocked vault. */
    fun open(file: VaultFile): OpenedVault = runBlocking {
        val storage = FakeVaultStorage().apply { put(LOCATION, file.bytes) }
        when (val opened = VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO).open(LOCATION, password(file), keyFile = file.keyFile?.copyOf())) {
            is OpenResult.Unlocked -> opened.session.opened.also { opened.session.release() }
            else -> fail("${file.name}: the opener gives $opened")
        }
    }

    /**
     * Opens [file], applies [ops] in order at [now] and saves once; returns the saved bytes as a
     * file named [name] with [file]'s credentials. When no op changes the document and none is
     * [CompanionOp.NoEdit], nothing is saved and the input's bytes come back, as the editor writes
     * nothing for an edit that changes no field.
     */
    fun run(file: VaultFile, ops: List<CompanionOp>, now: Instant, name: String): VaultFile = runBlocking {
        val storage = FakeVaultStorage().apply { put(LOCATION, file.bytes) }
        val state = FakeVaultStateStore()
        val writers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val opened = VaultOpener.create(storage, state, Dispatchers.IO).open(LOCATION, password(file), keyFile = file.keyFile?.copyOf())
            if (opened !is OpenResult.Unlocked) fail("${file.name}: the opener gives $opened")
            val vault = opened.session.opened
            opened.session.release()
            var document = vault.document
            for (op in ops) document = apply(document, op, now, file.name)
            if (document === vault.document && CompanionOp.NoEdit !in ops) return@runBlocking VaultFile(name, file.bytes, file.mode, file.keyFileName, file.keyFile)
            val saver = SafeSaver.create(storage, FakeBackupStore { now }, FakeSaveMarkerStore(), state, Dispatchers.IO, writers)
            val saved = saver.save(LOCATION, vault.withDocument(document))
            if (saved !is SaveResult.Saved) fail("${file.name} $ops: the save gives $saved")
            VaultFile(name, storage.bytes(LOCATION)!!, file.mode, file.keyFileName, file.keyFile)
        } finally {
            writers.cancel()
        }
    }

    /** Applies [op] to [document] as the editor or the delete action does. */
    fun apply(document: VaultDocument, op: CompanionOp, now: Instant, what: String = ""): VaultDocument = when (op) {
        CompanionOp.NoEdit -> document
        is CompanionOp.Edit -> {
            val id = id(op.entry)
            val d = EntryEdits.draftOf(document, id) ?: fail("$what: no entry ${op.entry}")
            val draft = when (op.field) {
                "Title" -> EntryDraft(op.value, d.userName, d.password, d.url, d.notes)
                "UserName" -> EntryDraft(d.title, op.value, d.password, d.url, d.notes)
                "Password" -> EntryDraft(d.title, d.userName, ProtectedText.of(op.value), d.url, d.notes)
                "URL" -> EntryDraft(d.title, d.userName, d.password, op.value, d.notes)
                else -> EntryDraft(d.title, d.userName, d.password, d.url, op.value)
            }
            when (val r = EntryEdits.edit(document, id, draft, now)) {
                is EditResult.Changed -> r.document
                EditResult.Unchanged -> document
                else -> fail("$what $op: $r")
            }
        }
        is CompanionOp.Add -> {
            // The editor starts a new entry from the vault's defaults (newDraft); the user types
            // the rest.
            val start = EntryEdits.newDraft(document, ProtectedText.of(op.password))
            val draft = EntryDraft(op.title, start.userName, start.password, op.url, op.notes)
            EntryEdits.add(document, op.group?.let(::id), draft, now, Uuids.parse(op.uuid)!!).document
        }
        is CompanionOp.Delete -> EntryDelete.delete(document, id(op.entry), now)?.document ?: fail("$what: no entry ${op.entry}")
        is CompanionOp.DeleteCustomData -> throw IllegalArgumentException("KashPass offers no custom data editing: $op")
    }

    // The index id of the entry or group KeePass 2's XML names by [base64] UUID.
    private fun id(base64: String): String = (Uuids.parse(base64) ?: fail("not a UUID: $base64")).toString()

    private fun password(file: VaultFile): CharArray = (TestFiles.password(file.mode) ?: "").toCharArray()
}
