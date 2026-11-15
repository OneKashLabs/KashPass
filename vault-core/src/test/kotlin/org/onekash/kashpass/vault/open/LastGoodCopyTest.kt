package org.onekash.kashpass.vault.open

import org.onekash.kashpass.vault.doc.open
import java.time.Duration
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.save.CopyResult
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.testing.TestVaults

class LastGoodCopyTest {

    private val rig = OpenRig().apply { storage.put(loc, OpenRig.vault) }

    private var clock = java.time.Instant.parse("2026-10-21T10:00:00Z")

    init {
        rig.backups.now = { clock }
    }

    private suspend fun keep(bytes: ByteArray, kind: BackupKind = BackupKind.OPENED): BackupInfo {
        clock = clock.plusSeconds(60)
        return (rig.backups.add(rig.loc, bytes, kind) as BackupResult.Added).info
    }

    private fun saver() = SafeSaver(rig.storage, rig.backups, rig.markers, rig.state, Dispatchers.IO, CoroutineScope(SupervisorJob() + Dispatchers.IO), Duration.ofSeconds(5))

    private fun pw() = TestVaults.PASSWORD.toCharArray()

    // Cut short inside the header: the parser reports it before any key derivation.
    private val headerCorrupted: ByteArray by lazy { OpenRig.vault.copyOf(40) }

    // A valid header over XML that isn't a KDBX document: found only after the key derivation.
    private val bodyCorrupted: ByteArray by lazy { TestVaults.rawXmlVault("<NotKeePass/>") }

    @Test
    fun `a corrupted file's last copy is the newest copy that differs from it`() = runBlocking<Unit> {
        keep(OpenRig.weaker)
        val newest = keep(OpenRig.vault)
        rig.storage.put(rig.loc, headerCorrupted)
        val damaged = assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc))
        assertEquals(DamageReason.TRUNCATED, damaged.reason)
        assertEquals(newest, damaged.lastCopy)
        assertEquals(newest, assertIs<OpenResult.Damaged>(rig.opener.open(rig.loc, pw())).lastCopy)
    }

    @Test
    fun `a copy whose header doesn't parse is skipped`() = runBlocking<Unit> {
        val good = keep(OpenRig.weaker)
        keep(headerCorrupted)
        rig.storage.put(rig.loc, headerCorrupted)
        assertEquals(good, assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc)).lastCopy)
    }

    @Test
    fun `a copy whose bytes don't match its recorded hash is skipped`() = runBlocking<Unit> {
        val older = keep(OpenRig.weaker)
        val newest = keep(OpenRig.vault)
        rig.backups.corrupt(rig.loc, newest.id)
        rig.storage.put(rig.loc, headerCorrupted)
        assertEquals(older, assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc)).lastCopy)
    }

    @Test
    fun `no good copy leaves lastCopy empty`() = runBlocking<Unit> {
        rig.storage.put(rig.loc, headerCorrupted)
        assertNull(assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc)).lastCopy)
    }

    @Test
    fun `a pending marker's old copy comes first, unless it is the file`() = runBlocking<Unit> {
        // A restore by an earlier version of KashPass can leave a marker whose old bytes are the
        // corrupted file itself; the older good copy is the last copy.
        val good = keep(OpenRig.weaker)
        keep(bodyCorrupted, BackupKind.BEFORE_SAVE)
        rig.storage.put(rig.loc, bodyCorrupted)
        rig.markers.set(rig.loc, Sha256.hex(bodyCorrupted), Sha256.hex(OpenRig.weaker))
        assertEquals(good, assertIs<OpenResult.Damaged>(rig.opener.open(rig.loc, pw())).lastCopy)
    }

    @Test
    fun `a partial write puts the marker's old copy before newer ones, skipping a corrupted one`() = runBlocking<Unit> {
        val old = keep(OpenRig.vault)
        keep(OpenRig.weaker)
        rig.markers.set(rig.loc, old.sha256, "f".repeat(64))
        rig.storage.put(rig.loc, headerCorrupted)
        assertEquals(old, assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc)).lastCopy)
        rig.backups.corrupt(rig.loc, old.id)
        val next = rig.backups.list(rig.loc).first()
        assertEquals(next, assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc)).lastCopy)
    }

    @Test
    fun `a before-save copy with no decrypted twin comes after copies known to decrypt`() = runBlocking<Unit> {
        // A restore by an earlier version of KashPass kept the corrupted file as a before-save
        // copy, which no unlock decrypted.
        val good = keep(OpenRig.vault)
        val corrupted = keep(bodyCorrupted, BackupKind.BEFORE_SAVE)
        rig.markers.set(rig.loc, corrupted.sha256, Sha256.hex(OpenRig.weaker))
        rig.storage.put(rig.loc, headerCorrupted)
        assertEquals(good, assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc)).lastCopy)
        rig.markers.clear(rig.loc)
        rig.storage.fail(rig.loc, StorageFailure.IO_FAILURE)
        assertEquals(good, assertIs<OpenResult.Unreadable>(rig.opener.check(rig.loc)).lastCopy)
    }

    @Test
    fun `a copy kept only before a save is the last copy when nothing else is kept`() = runBlocking<Unit> {
        val before = keep(OpenRig.weaker, BackupKind.BEFORE_SAVE)
        rig.storage.put(rig.loc, headerCorrupted)
        assertEquals(before, assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc)).lastCopy)
    }

    @Test
    fun `a copy with key settings out of bounds is skipped`() = runBlocking<Unit> {
        val good = keep(OpenRig.weaker)
        keep(org.onekash.kashpass.vault.testing.RawKdbx.parse(OpenRig.vault).withKdf { it.with("R", org.onekash.kashpass.vault.testing.RawDictionary.UINT64, org.onekash.kashpass.vault.testing.u64(0UL)) }.toBytes())
        rig.storage.put(rig.loc, headerCorrupted)
        assertEquals(good, assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc)).lastCopy)
    }

    @Test
    fun `an unlock with the stored key clears the marker`() = runBlocking<Unit> {
        rig.markers.set(rig.loc, "0".repeat(64), "f".repeat(64))
        val key = java.security.MessageDigest.getInstance("SHA-256").digest(TestVaults.PASSWORD.toByteArray())
        assertIs<OpenResult.Unlocked>(rig.opener.openWithKey(rig.loc, key))
        assertNull(rig.markers.get(rig.loc))
    }

    @Test
    fun `a backup opened from a last copy stays a last copy`() = runBlocking<Unit> {
        val first = keep(OpenRig.vault)
        val second = keep(OpenRig.weaker)
        val copy = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, first, pw(), LastCopyReason.CORRUPTED))
        val next = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, second, copy.session))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.LAST_COPY_CORRUPTED), next.session.saveability)
    }

    @Test
    fun `the copy of a file damaged after its header stays that copy when another backup opens from it`() = runBlocking<Unit> {
        val first = keep(OpenRig.vault)
        val second = keep(OpenRig.weaker)
        val copy = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, first, pw(), LastCopyReason.CORRUPTED_AFTER_HEADER))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.LAST_COPY_CORRUPTED_AFTER_HEADER), copy.session.saveability)
        val next = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, second, copy.session))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.LAST_COPY_CORRUPTED_AFTER_HEADER), next.session.saveability)
    }

    @Test
    fun `corruption found after the key derivation carries the last copy`() = runBlocking<Unit> {
        val good = keep(OpenRig.vault)
        rig.storage.put(rig.loc, bodyCorrupted)
        val damaged = assertIs<OpenResult.Damaged>(rig.opener.open(rig.loc, pw()))
        assertTrue(damaged.reason.afterHeaderHmac, damaged.reason.toString())
        assertEquals(good, damaged.lastCopy)
        val key = java.security.MessageDigest.getInstance("SHA-256").digest(TestVaults.PASSWORD.toByteArray())
        assertEquals(good, assertIs<OpenResult.Damaged>(rig.opener.openWithKey(rig.loc, key)).lastCopy)
    }

    @Test
    fun `reopen of a corrupted file carries the last copy`() = runBlocking<Unit> {
        val session = rig.unlock().session
        val good = rig.backups.list(rig.loc).first()
        rig.storage.put(rig.loc, headerCorrupted)
        assertEquals(good, assertIs<OpenResult.Damaged>(rig.opener.reopen(rig.loc, session)).lastCopy)
    }

    @Test
    fun `a corrupted backup reports no last copy of its own`() = runBlocking<Unit> {
        keep(OpenRig.vault)
        val broken = keep(bodyCorrupted)
        val damaged = assertIs<OpenResult.Damaged>(rig.opener.openBackup(rig.loc, broken, pw()))
        assertNull(damaged.lastCopy)
    }

    @Test
    fun `check clears a marker whose new bytes are in the file and says nothing`() = runBlocking<Unit> {
        rig.markers.set(rig.loc, "0".repeat(64), Sha256.hex(OpenRig.vault))
        assertEquals(false, assertIs<OpenResult.Ready>(rig.opener.check(rig.loc)).lostCutOffSave)
        assertNull(rig.markers.get(rig.loc))
    }

    @Test
    fun `check clears a marker whose old bytes are in the file and reports the lost save`() = runBlocking<Unit> {
        rig.markers.set(rig.loc, Sha256.hex(OpenRig.vault), "f".repeat(64))
        assertEquals(true, assertIs<OpenResult.Ready>(rig.opener.check(rig.loc)).lostCutOffSave)
        assertNull(rig.markers.get(rig.loc))
    }

    @Test
    fun `a file holding neither version reports the lost save and keeps the marker until it opens`() = runBlocking<Unit> {
        rig.markers.set(rig.loc, "0".repeat(64), "f".repeat(64))
        assertEquals(true, assertIs<OpenResult.Ready>(rig.opener.check(rig.loc)).lostCutOffSave)
        assertNotNull(rig.markers.get(rig.loc))
        rig.unlock()
        assertNull(rig.markers.get(rig.loc))
    }

    @Test
    fun `refresh, reopen and a corrupted or unreadable file leave the marker`() = runBlocking<Unit> {
        val session = rig.unlock().session
        rig.markers.set(rig.loc, "0".repeat(64), "f".repeat(64))
        rig.opener.refresh(rig.loc, session)
        assertIs<OpenResult.Unlocked>(rig.opener.reopen(rig.loc, session))
        assertNotNull(rig.markers.get(rig.loc))
        rig.storage.put(rig.loc, bodyCorrupted)
        assertIs<OpenResult.Damaged>(rig.opener.open(rig.loc, pw()))
        rig.storage.put(rig.loc, headerCorrupted)
        assertIs<OpenResult.Damaged>(rig.opener.check(rig.loc))
        rig.storage.fail(rig.loc, StorageFailure.IO_FAILURE)
        assertIs<OpenResult.Unreadable>(rig.opener.check(rig.loc))
        assertNotNull(rig.markers.get(rig.loc))
    }

    @Test
    fun `a corrupted file's last copy saves as a new file that opens editable`() = runBlocking<Unit> {
        val session = rig.unlock().session
        val corrupted = OpenRig.vault.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        rig.storage.put(rig.loc, corrupted)
        val offered = assertNotNull(assertIs<OpenResult.Damaged>(rig.opener.open(rig.loc, pw())).lastCopy)
        val copy = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, offered, pw(), LastCopyReason.CORRUPTED))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.LAST_COPY_CORRUPTED), copy.session.saveability)
        val newFile = rig.storage.createDocument("Vault (backup).kdbx")
        val saved = saver().saveBackupCopy(rig.backups.read(rig.loc, offered.id)!!, copy.session.opened, newFile)
        assertIs<CopyResult.Saved>(saved)
        assertContentEquals(corrupted, rig.storage.bytes(rig.loc), "the corrupted file is never written")
        assertNull(rig.state.kdfBaseline(newFile))
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.open(newFile, pw()))
        assertEquals(Saveability.Saveable, opened.session.saveability)
        assertEquals(rig.titles(session), rig.titles(opened.session))
        assertEquals(opened.kdf, rig.state.kdfBaseline(newFile))
    }

    @Test
    fun `an unavailable file's last copy opens as the last copy`() = runBlocking<Unit> {
        val backup = keep(OpenRig.vault)
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, backup, pw(), LastCopyReason.UNAVAILABLE))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.LAST_COPY), opened.session.saveability)
    }

    @Test
    fun `a save cut off mid-write leaves the copy it replaced as the last copy`() = runBlocking<Unit> {
        val session = rig.unlock().session
        val saver = saver()
        rig.storage.failWrites(rig.loc, StorageFailure.IO_FAILURE, afterOpen = true)
        val edited = session.opened.withDocument(VaultXmlCodec.open(rig.retitled(session.opened.document, "Lost"), OpenRig.credentials, VaultXmlCodec.Limits(64 shl 20, 64L shl 20)))
        assertIs<SaveResult.MaybeDamaged>(saver.save(rig.loc, edited))
        // Half the new bytes landed: the header reads, so check reports the lost save.
        assertEquals(true, assertIs<OpenResult.Ready>(rig.opener.check(rig.loc)).lostCutOffSave)
        val offered = assertNotNull(assertIs<OpenResult.Damaged>(rig.opener.open(rig.loc, pw())).lastCopy)
        assertContentEquals(OpenRig.vault, rig.backups.read(rig.loc, offered.id))
    }
}
