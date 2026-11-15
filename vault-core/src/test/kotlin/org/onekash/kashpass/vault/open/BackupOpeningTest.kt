package org.onekash.kashpass.vault.open

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.u64

class BackupOpeningTest {

    private val rig = OpenRig().apply { storage.put(loc, OpenRig.vault) }

    private suspend fun keep(bytes: ByteArray): BackupInfo = (rig.backups.add(rig.loc, bytes, BackupKind.BEFORE_SAVE) as BackupResult.Added).info

    private fun pw() = TestVaults.PASSWORD.toCharArray()

    @Test
    fun `a backup weaker than the file's settings opens read-only and changes nothing stored`() = runBlocking<Unit> {
        rig.unlock()
        val backup = keep(OpenRig.weaker)
        val count = rig.backups.list(rig.loc).size
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, backup, pw()))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.BACKUP), opened.session.saveability)
        assertEquals(backup, opened.backup)
        assertEquals(false, opened.showWeakWarning)
        assertEquals(KdfSettings.AesKdf(1_000UL), rig.state.kdfBaseline(rig.loc), "the downgrade baseline is unchanged")
        assertEquals(count, rig.backups.list(rig.loc).size, "opening a backup keeps no new backup")
    }

    @Test
    fun `the last copy opens read-only as the last copy`() = runBlocking<Unit> {
        val backup = keep(OpenRig.vault)
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, backup, pw(), lastCopy = LastCopyReason.UNAVAILABLE))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.LAST_COPY), opened.session.saveability)
    }

    @Test
    fun `a backup needs the right password and settings within bounds`() = runBlocking<Unit> {
        val backup = keep(OpenRig.vault)
        val wrong = "nope".toCharArray()
        assertEquals(OpenResult.WrongPassword, rig.opener.openBackup(rig.loc, backup, wrong))
        assertTrue(wrong.all { it == '\u0000' })
        val broken = keep(RawKdbx.parse(OpenRig.vault).withKdf { it.with("R", RawDictionary.UINT64, u64(0UL)) }.toBytes())
        assertIs<OpenResult.Refused>(rig.opener.openBackup(rig.loc, broken, pw()))
        val gone = broken.copy(id = "missing")
        assertEquals(OpenResult.Unreadable(StorageFailure.NOT_FOUND), rig.opener.openBackup(rig.loc, gone, pw()))
    }

    @Test
    fun `a backup whose bytes don't match the hash in its name is damaged and never decrypted`() = runBlocking<Unit> {
        val backup = keep(OpenRig.vault)
        rig.backups.corrupt(rig.loc, backup.id)
        val decodes = rig.decodes
        assertEquals(OpenResult.BackupDamaged, rig.opener.openBackup(rig.loc, backup, pw()))
        assertEquals(OpenResult.BackupDamaged, rig.opener.openBackup(rig.loc, backup, pw(), lastCopy = LastCopyReason.UNAVAILABLE))
        assertEquals(decodes, rig.decodes)
    }

    @Test
    fun `after a save the last copy is the saved file`() = runBlocking<Unit> {
        rig.unlock()
        val saved = rig.retitled(rig.unlock().session.opened.document, "Phone edit")
        rig.backups.add(rig.loc, saved, BackupKind.SAVED)
        rig.storage.fail(rig.loc, StorageFailure.TIMED_OUT)
        val lastCopy = assertIs<OpenResult.Unreadable>(rig.opener.check(rig.loc)).lastCopy!!
        assertEquals(org.onekash.kashpass.vault.backup.Sha256.hex(saved), lastCopy.sha256)
    }

    @Test
    fun `an unreadable file reports the newest backup as the last copy`() = runBlocking<Unit> {
        rig.storage.fail(rig.loc, StorageFailure.IO_FAILURE)
        assertNull(assertIs<OpenResult.Unreadable>(rig.opener.check(rig.loc)).lastCopy, "no backup yet")
        keep(OpenRig.weaker)
        val newest = keep(OpenRig.vault)
        for (cause in listOf(StorageFailure.NOT_FOUND, StorageFailure.PERMISSION_REVOKED, StorageFailure.IO_FAILURE, StorageFailure.TIMED_OUT)) {
            rig.storage.fail(rig.loc, cause)
            assertEquals(OpenResult.Unreadable(cause, newest), rig.opener.check(rig.loc))
            assertEquals(OpenResult.Unreadable(cause, newest), rig.opener.open(rig.loc, pw()))
        }
        rig.storage.fail(rig.loc, StorageFailure.TOO_LARGE)
        assertEquals(OpenResult.Unreadable(StorageFailure.TOO_LARGE), rig.opener.check(rig.loc))
    }

    @Test
    fun `backups are listed newest first`() = runBlocking<Unit> {
        val first = keep(OpenRig.weaker)
        Thread.sleep(5)
        val second = keep(OpenRig.vault)
        assertEquals(listOf(second, first), rig.opener.backups(rig.loc))
    }

    @Test
    fun `a backup opens with the unlocked session's key`() = runBlocking<Unit> {
        val session = rig.unlock().session
        val backup = keep(OpenRig.weaker)
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, backup, session))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.BACKUP), opened.session.saveability)
        assertEquals(backup, opened.backup)
    }

    @Test
    fun `backups of key-file vaults open with the key file, as the last copy too`() = runBlocking<Unit> {
        val rig = OpenRig().apply { storage.put(loc, OpenRig.keyFileVault) }
        val backup = (rig.backups.add(rig.loc, OpenRig.keyFileVault, BackupKind.BEFORE_SAVE) as BackupResult.Added).info
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, backup, pw(), keyFile = TestVaults.KEY_FILE))
        assertEquals(UnlockOrigin.PASSWORD_AND_KEY_FILE, opened.session.opened.origin)
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.BACKUP), opened.session.saveability)
        val last = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, backup, pw(), LastCopyReason.CORRUPTED, keyFile = TestVaults.KEY_FILE))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.LAST_COPY_CORRUPTED), last.session.saveability)
        assertEquals(OpenResult.WrongPassword, rig.opener.openBackup(rig.loc, backup, pw()))
        val damaged = "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data>ZZ</Data></Key></KeyFile>".toByteArray()
        assertEquals(OpenResult.KeyFileDamaged, rig.opener.openBackup(rig.loc, backup, pw(), keyFile = damaged))
        assertTrue(damaged.all { it == 0.toByte() })

        val only = OpenRig().apply { storage.put(loc, OpenRig.emptyPasswordKeyFileVault) }
        val kept = (only.backups.add(only.loc, OpenRig.emptyPasswordKeyFileVault, BackupKind.BEFORE_SAVE) as BackupResult.Added).info
        val keyOnly = assertIs<OpenResult.Unlocked>(only.opener.openBackup(only.loc, kept, CharArray(0), keyFile = TestVaults.KEY_FILE))
        assertEquals(UnlockOrigin.KEY_FILE_ONLY, keyOnly.session.opened.origin)
    }
}
