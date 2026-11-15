package org.onekash.kashpass.vault.open

import kotlin.test.assertEquals
import org.onekash.kashpass.vault.doc.encodeBytes
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.storage.StorageFailure

class ReloadTest {

    private val rig = OpenRig().apply { storage.put(loc, OpenRig.vault) }

    @Test
    fun `an unchanged file is not read again into a new session`() = runBlocking<Unit> {
        val session = rig.unlock().session
        val decodes = rig.decodes
        assertSame(RefreshResult.Unchanged, rig.opener.refresh(rig.loc, session))
        assertEquals(decodes, rig.decodes)
    }

    @Test
    fun `a changed file is reloaded with the session's key through every check`() = runBlocking<Unit> {
        val session = rig.unlock().session
        rig.storage.put(rig.loc, rig.retitled(session.opened.document, "Changed on desktop"))
        val reloaded = assertIs<RefreshResult.Reloaded>(rig.opener.refresh(rig.loc, session)).opened.session
        assertTrue("Changed on desktop" in rig.titles(reloaded))
        assertNotEquals(session.opened.baseline, reloaded.opened.baseline)
    }

    @Test
    fun `an entry deleted elsewhere is absent from the reloaded session`() = runBlocking<Unit> {
        val session = rig.unlock().session
        val id = session.index.rows(Chip.All, "").first().id
        val deleted = org.onekash.kashpass.vault.edit.EntryDelete.delete(session.opened.document, id, java.time.Instant.now())!!
        rig.storage.put(rig.loc, org.onekash.kashpass.vault.doc.VaultXmlCodec.encodeBytes(deleted.document))
        val reloaded = assertIs<RefreshResult.Reloaded>(rig.opener.refresh(rig.loc, session)).opened.session
        assertNull(reloaded.index.details(id))
    }

    @Test
    fun `a reload refuses weaker settings and an unreadable file, like an unlock`() = runBlocking<Unit> {
        val session = rig.unlock().session
        rig.storage.put(rig.loc, OpenRig.weaker)
        assertIs<KdfRejection.Weakened>(assertIs<OpenResult.Refused>(assertIs<RefreshResult.Failed>(rig.opener.refresh(rig.loc, session)).result).rejection)
        rig.storage.fail(rig.loc, StorageFailure.IO_FAILURE)
        assertEquals(StorageFailure.IO_FAILURE, assertIs<OpenResult.Unreadable>(assertIs<RefreshResult.Failed>(rig.opener.refresh(rig.loc, session)).result).cause)
    }

    @Test
    fun `a file that doesn't answer in time is reported as timed out by refresh and reopen`() = runBlocking<Unit> {
        val session = rig.unlock().session
        rig.storage.fail(rig.loc, StorageFailure.TIMED_OUT)
        assertEquals(StorageFailure.TIMED_OUT, assertIs<OpenResult.Unreadable>(assertIs<RefreshResult.Failed>(rig.opener.refresh(rig.loc, session)).result).cause)
        val reopened = assertIs<OpenResult.Unreadable>(rig.opener.reopen(rig.loc, session))
        assertEquals(StorageFailure.TIMED_OUT, reopened.cause)
        assertEquals(rig.backups.list(rig.loc).first(), reopened.lastCopy)
    }

    @Test
    fun `an unknown baseline always reloads`() = runBlocking<Unit> {
        val session = rig.unlock().session
        val unknown = VaultSession.from(session.opened.withBaseline(OpenedVault.Baseline.Unknown))
        assertIs<RefreshResult.Reloaded>(rig.opener.refresh(rig.loc, unknown))
    }

    @Test
    fun `reopen unlocks the file with the session's key`() = runBlocking<Unit> {
        val session = rig.unlock().session
        val again = assertIs<OpenResult.Unlocked>(rig.opener.reopen(rig.loc, session))
        assertEquals(rig.titles(session), rig.titles(again.session))
        assertNull(again.backup)
    }

    @Test
    fun `a successful open keeps the bytes as a backup once`() = runBlocking<Unit> {
        rig.unlock()
        rig.unlock()
        val kept = rig.backups.list(rig.loc)
        assertEquals(listOf(BackupKind.OPENED), kept.map { it.kind })
        assertEquals(OpenRig.vault.size.toLong(), kept.single().size)
    }

    @Test
    fun `a backup that can't be kept doesn't block the unlock`() = runBlocking<Unit> {
        rig.backups.failing = true
        assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, org.onekash.kashpass.vault.testing.TestVaults.PASSWORD.toCharArray()))
        assertEquals(KdfSettings.AesKdf(1_000UL), rig.state.kdfBaseline(rig.loc))
    }
}
