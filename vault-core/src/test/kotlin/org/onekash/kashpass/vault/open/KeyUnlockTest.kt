package org.onekash.kashpass.vault.open

import java.time.Instant
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.security.MessageDigest
import kotlin.test.assertNull
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.time.Duration
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
import org.onekash.kashpass.vault.doc.KeyFileTest
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.HeaderDictionaries
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.VaultIndex
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.u64

class KeyUnlockTest {

    private val rig = OpenRig().apply { storage.put(loc, OpenRig.vault) }

    @Test
    fun `the key of a password session opens the same vault and is wiped`() = runBlocking<Unit> {
        val key = rig.unlock().session.unlockKey()!!
        assertEquals(32, key.size)
        val copy = key.copyOf()
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.openWithKey(rig.loc, key))
        assertTrue(key.all { it == 0.toByte() }, "the caller's array is zeroed")
        assertContentEquals(copy, opened.session.unlockKey()!!, "a key session hands out the same key")
        assertEquals(rig.titles(rig.unlock().session), rig.titles(opened.session))
    }

    @Test
    fun `a session opened by key saves a file the password opens, and refreshes`() = runBlocking<Unit> {
        val original = rig.unlock().session.unlockKey()!!
        val session = assertIs<OpenResult.Unlocked>(rig.opener.openWithKey(rig.loc, original.copyOf())).session
        val document = session.opened.document
        val id = VaultIndex.from(document).rows(Chip.All, "").first().id
        val d = EntryEdits.draftOf(document, id)!!
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(document, id, EntryDraft("Saved by key", d.userName, d.password, d.url, d.notes), Instant.now())).document
        val saver = SafeSaver.create(rig.storage, FakeBackupStore(), FakeSaveMarkerStore(), rig.state, Dispatchers.IO, CoroutineScope(SupervisorJob() + Dispatchers.IO))
        val saved = assertIs<SaveResult.Saved>(saver.save(rig.loc, session.opened.withDocument(edited)))
        assertTrue("Saved by key" in rig.titles(rig.unlock().session), "a fresh password open reads the save")
        assertIs<RefreshResult.Unchanged>(rig.opener.refresh(rig.loc, VaultSession.from(saved.opened)))
        assertContentEquals(original, session.unlockKey()!!, "the session's key is intact after use")
    }

    @Test
    fun `a wrong key is a wrong password and is wiped`() = runBlocking<Unit> {
        val key = ByteArray(32) { 7 }
        assertEquals(OpenResult.WrongPassword, rig.opener.openWithKey(rig.loc, key))
        assertTrue(key.all { it == 0.toByte() })
    }

    @Test
    fun `refusals derive nothing and wipe the key`() = runBlocking<Unit> {
        val key = rig.unlock().session.unlockKey()!!
        rig.storage.put(rig.loc, RawKdbx.parse(OpenRig.vault).withKdf { it.with("R", RawDictionary.UINT64, u64(100_000_000UL)) }.toBytes())
        val decodes = rig.decodes
        assertIs<OpenResult.TooSlow>(rig.opener.openWithKey(rig.loc, key))
        assertEquals(decodes, rig.decodes)
        assertTrue(key.all { it == 0.toByte() })
        rig.storage.put(rig.loc, TestVaults.bytes(aesRounds = 500UL))
        assertIs<OpenResult.Refused>(rig.opener.openWithKey(rig.loc, ByteArray(32)))
        assertEquals(KdfSettings.AesKdf(1_000UL), rig.state.kdfBaseline(rig.loc))
    }

    private val passHash = sha256(TestVaults.PASSWORD.toByteArray())

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun keyRig(vault: ByteArray) = OpenRig().apply { storage.put(loc, vault) }

    private fun zeroed(b: ByteArray) = b.all { it == 0.toByte() }

    @Test
    fun `a password and key file vault opens with both and not with either alone`() = runBlocking<Unit> {
        val rig = keyRig(OpenRig.keyFileVault)
        val keyFile = TestVaults.KEY_FILE
        val password = pw()
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, password, keyFile = keyFile))
        assertEquals(UnlockOrigin.PASSWORD_AND_KEY_FILE, opened.session.opened.origin)
        assertTrue(zeroed(keyFile) && password.all { it == '\u0000' }, "the key file and password arrays are zeroed")
        assertEquals(OpenResult.WrongPassword, rig.opener.open(rig.loc, pw()))
        assertEquals(OpenResult.WrongPassword, rig.opener.open(rig.loc, CharArray(0), keyFile = TestVaults.KEY_FILE))
        val otherKey = TestVaults.keyFileFor(ByteArray(32) { 1 })
        assertEquals(OpenResult.WrongPassword, rig.opener.open(rig.loc, pw(), keyFile = otherKey))
    }

    @Test
    fun `a key-file-only vault opens with an empty password field, the key file alone first`() = runBlocking<Unit> {
        val rig = keyRig(OpenRig.keyFileOnlyVault)
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, CharArray(0), keyFile = TestVaults.KEY_FILE))
        assertEquals(1, rig.decodes, "no retry when the key file alone opens it")
        assertEquals(UnlockOrigin.KEY_FILE_ONLY, opened.session.opened.origin)
        assertNull(opened.session.unlockKey(), "a key-file-only session has nothing to seal")
    }

    @Test
    fun `a vault of an empty password and a key file opens on the one retry`() = runBlocking<Unit> {
        val rig = keyRig(OpenRig.emptyPasswordKeyFileVault)
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, CharArray(0), keyFile = TestVaults.KEY_FILE))
        assertEquals(2, rig.decodes)
        assertEquals(UnlockOrigin.KEY_FILE_ONLY, opened.session.opened.origin)
        assertNull(opened.session.unlockKey())
        val wrong = TestVaults.keyFileFor(ByteArray(32) { 2 })
        assertEquals(OpenResult.WrongPassword, rig.opener.open(rig.loc, CharArray(0), keyFile = wrong))
        assertEquals(4, rig.decodes, "a wrong key file is tried twice, no more")
    }

    @Test
    fun `a damaged key file reads and derives nothing and is wiped`() = runBlocking<Unit> {
        val rig = keyRig(OpenRig.keyFileVault)
        fun damaged() = String(TestVaults.KEY_FILE).replace(Regex("Hash=\"[0-9A-F]+\""), "Hash=\"00000000\"").toByteArray()
        val keyFile = damaged()
        val password = pw()
        assertEquals(OpenResult.KeyFileDamaged, rig.opener.open(rig.loc, password, keyFile = keyFile))
        assertTrue(zeroed(keyFile) && password.all { it == '\u0000' })
        val key = passHash.copyOf()
        val again = damaged()
        assertEquals(OpenResult.KeyFileDamaged, rig.opener.openWithKey(rig.loc, key, keyFile = again))
        assertTrue(zeroed(key) && zeroed(again))
        assertEquals(0, rig.decodes)
        assertEquals(0, rig.storage.reads, "the vault file is not read")
    }

    @Test
    fun `a key file with about 120,000 attributes on its root is refused or hashed in bounded time`() {
        val rig = keyRig(OpenRig.keyFileVault)
        assertTimeoutPreemptively(Duration.ofSeconds(2)) {
            runBlocking {
                assertEquals(OpenResult.KeyFileDamaged, rig.opener.open(rig.loc, pw(), keyFile = KeyFileTest.manyAttributes("KeyFile")))
            }
        }
        assertTimeoutPreemptively(Duration.ofSeconds(2)) {
            runBlocking {
                assertEquals(OpenResult.WrongPassword, rig.opener.open(rig.loc, pw(), keyFile = KeyFileTest.manyAttributes("X")))
            }
        }
    }

    @ParameterizedTest
    @EnumSource(KeyFileTest.Utf16Form::class)
    fun `KeePass 2's XML key file in UTF-16 unlocks its key-file-only vault`(form: KeyFileTest.Utf16Form) = runBlocking<Unit> {
        val keyFile = form.encode(Fixtures.bytes("keepass2-keyfile-v2.keyx").decodeToString().replace("utf-8", "utf-16"))
        val opened = TestVaults.unlock(Fixtures.bytes("keepass2-keyfile-only-v2.kdbx"), password = "", keyFile = keyFile)
        assertEquals(UnlockOrigin.KEY_FILE_ONLY, opened.session.opened.origin)
        assertTrue(zeroed(keyFile))
    }

    @Test
    fun `a 2 MiB XML key file unlocks its vault`() = runBlocking<Unit> {
        val rig = keyRig(OpenRig.keyFileVault)
        val keyFile = String(TestVaults.KEY_FILE).replace("</KeyFile>", "<!--${" ".repeat(2 shl 20)}--></KeyFile>").toByteArray()
        assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, pw(), keyFile = keyFile))
    }

    @Test
    fun `XML over this heap's limit is a key file too large with a KeyFile root and hashed with another`() = runBlocking<Unit> {
        // A 64 MiB heap allows about 1.8 MB of XML; each file here is 2 MiB.
        val heap = 64L shl 20
        assertTrue(VaultXmlCodec.Limits.forHeap(heap).open < 2 shl 20)
        val other = "<?xml version=\"1.0\"?>\n<html>${" ".repeat(2 shl 20)}</html>".toByteArray()
        val hashedVault = TestVaults.bytes(aesRounds = 1_000UL, keyPart = sha256(other))
        val storage = FakeVaultStorage().apply { put(rig.loc, hashedVault) }
        val opener = HeaderDictionaries.opener(storage, FakeVaultStateStore(), Dispatchers.IO, heap, FakeBackupStore())
        assertIs<OpenResult.Unlocked>(opener.open(rig.loc, pw(), keyFile = other.copyOf()))
        val keyFile = String(TestVaults.KEY_FILE).replace("</KeyFile>", "<!--${" ".repeat(2 shl 20)}--></KeyFile>").toByteArray()
        assertEquals(OpenResult.KeyFileTooLarge, opener.open(rig.loc, pw(), keyFile = keyFile))
        assertTrue(zeroed(keyFile))
        val key = passHash.copyOf()
        val again = String(TestVaults.KEY_FILE).replace("</KeyFile>", "<!--${" ".repeat(2 shl 20)}--></KeyFile>").toByteArray()
        assertEquals(OpenResult.KeyFileTooLarge, opener.openWithKey(rig.loc, key, keyFile = again))
        assertTrue(zeroed(key) && zeroed(again))
    }

    @Test
    fun `biometric with a key file gives the same composite key as the password and key file`() = runBlocking<Unit> {
        val rig = keyRig(OpenRig.keyFileVault)
        val byPassword = assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, pw(), keyFile = TestVaults.KEY_FILE)).session
        val sealed = byPassword.unlockKey()!!
        assertContentEquals(passHash, sealed, "only the passphrase hash is sealed, never the key-file part")
        val key = sealed.copyOf()
        val keyFile = TestVaults.KEY_FILE
        val byKey = assertIs<OpenResult.Unlocked>(rig.opener.openWithKey(rig.loc, key, keyFile = keyFile)).session
        assertTrue(zeroed(key) && zeroed(keyFile))
        assertEquals(UnlockOrigin.STORED_KEY_AND_KEY_FILE, byKey.opened.origin)
        assertContentEquals(passHash, byKey.unlockKey()!!)
        val pwCredentials = byPassword.opened.document.credentials
        val keyCredentials = byKey.opened.document.credentials
        assertContentEquals(pwCredentials.compositeKey(), keyCredentials.compositeKey(), "the composite key is the same")
        assertEquals(OpenResult.WrongPassword, rig.opener.openWithKey(rig.loc, passHash.copyOf()), "the hash alone doesn't open it")
    }

    /** How each origin unlocks, and the key [VaultSession.unlockKey] must hand out for it. */
    enum class Case(val origin: UnlockOrigin, val sealed: Boolean) {
        PASSWORD(UnlockOrigin.PASSWORD, true),
        PASSWORD_AND_KEY_FILE(UnlockOrigin.PASSWORD_AND_KEY_FILE, true),
        KEY_FILE_ONLY(UnlockOrigin.KEY_FILE_ONLY, false),
        KEY_FILE_AND_EMPTY_PASSWORD(UnlockOrigin.KEY_FILE_ONLY, false),
        STORED_KEY(UnlockOrigin.STORED_KEY, true),
        STORED_KEY_AND_KEY_FILE(UnlockOrigin.STORED_KEY_AND_KEY_FILE, true),
    }

    private suspend fun unlock(rig: OpenRig, case: Case): VaultSession {
        val result = when (case) {
            Case.PASSWORD -> rig.opener.open(rig.loc, pw())
            Case.PASSWORD_AND_KEY_FILE -> rig.opener.open(rig.loc, pw(), keyFile = TestVaults.KEY_FILE)
            Case.KEY_FILE_ONLY, Case.KEY_FILE_AND_EMPTY_PASSWORD -> rig.opener.open(rig.loc, CharArray(0), keyFile = TestVaults.KEY_FILE)
            Case.STORED_KEY -> rig.opener.openWithKey(rig.loc, passHash.copyOf())
            Case.STORED_KEY_AND_KEY_FILE -> rig.opener.openWithKey(rig.loc, passHash.copyOf(), keyFile = TestVaults.KEY_FILE)
        }
        return assertIs<OpenResult.Unlocked>(result).session
    }

    private fun vaultOf(case: Case) = when (case) {
        Case.PASSWORD, Case.STORED_KEY -> OpenRig.vault
        Case.PASSWORD_AND_KEY_FILE, Case.STORED_KEY_AND_KEY_FILE -> OpenRig.keyFileVault
        Case.KEY_FILE_ONLY -> OpenRig.keyFileOnlyVault
        Case.KEY_FILE_AND_EMPTY_PASSWORD -> OpenRig.emptyPasswordKeyFileVault
    }

    private fun assertKey(case: Case, session: VaultSession, step: String) {
        assertEquals(case.origin, session.opened.origin, "origin $step")
        val key = session.unlockKey()
        if (case.sealed) assertContentEquals(passHash, key, "unlock key $step") else assertNull(key, "unlock key $step")
    }

    @ParameterizedTest
    @EnumSource(Case::class)
    fun `the unlock key follows the origin through unlock, save, refresh, reopen and backup`(case: Case) = runBlocking<Unit> {
        val rig = keyRig(vaultOf(case))
        val session = unlock(rig, case)
        assertKey(case, session, "after unlock")

        val saver = SafeSaver.create(rig.storage, FakeBackupStore(), FakeSaveMarkerStore(), rig.state, Dispatchers.IO, CoroutineScope(SupervisorJob() + Dispatchers.IO))
        val document = session.opened.document
        val id = VaultIndex.from(document).rows(Chip.All, "").first().id
        val d = EntryEdits.draftOf(document, id)!!
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(document, id, EntryDraft("Saved", d.userName, d.password, d.url, d.notes), Instant.now())).document
        val saved = VaultSession.from(assertIs<SaveResult.Saved>(saver.save(rig.loc, session.opened.withDocument(edited))).opened)
        assertKey(case, saved, "after a save")

        rig.storage.put(rig.loc, rig.retitled(saved.opened.document, "Changed elsewhere"))
        val refreshed = assertIs<RefreshResult.Reloaded>(rig.opener.refresh(rig.loc, saved)).opened.session
        assertKey(case, refreshed, "after refresh")

        val reopened = assertIs<OpenResult.Unlocked>(rig.opener.reopen(rig.loc, refreshed)).session
        assertKey(case, reopened, "after reopen")

        val backup = rig.backups.list(rig.loc).first()
        val fromBackup = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, backup, reopened)).session
        assertKey(case, fromBackup, "after opening a backup")
    }

    private fun pw() = TestVaults.PASSWORD.toCharArray()
}
