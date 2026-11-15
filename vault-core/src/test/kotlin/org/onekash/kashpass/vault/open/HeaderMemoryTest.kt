package org.onekash.kashpass.vault.open

import java.security.MessageDigest
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.HeaderRead
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.kdbx.KdbxDamage
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.memory.MemoryRun
import org.onekash.kashpass.vault.keepass2.KeePass2Run
import org.onekash.kashpass.vault.storage.maxVaultBytes
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.HeaderDictionaries
import org.onekash.kashpass.vault.testing.TestVaults

/**
 * A file whose outer header field 11 or 12 holds a dictionary of millions of tiny entries, up to
 * the read limit, fills the heap before the header HMAC can be checked. The opener reports it as
 * NotEnoughMemory with the last good copy, on every path that reads the file's header, and never
 * lets an OutOfMemoryError out. The default tests compute the limits for a [HEAP] heap; the gated
 * one runs the file sized for a 512 MiB heap in a child JVM with that heap.
 */
class HeaderMemoryTest {

    private val loc = "content://fake/vault.kdbx"
    private val storage = FakeVaultStorage()
    private val state = FakeVaultStateStore()
    private val backups = FakeBackupStore()
    private val opener = HeaderDictionaries.opener(storage, state, Dispatchers.IO, HEAP, backups)

    private fun crafted(field: Int) = HeaderDictionaries.manyEntries(field, maxVaultBytes(HEAP) - 1)

    private fun pw() = TestVaults.PASSWORD.toCharArray()

    private fun key() = MessageDigest.getInstance("SHA-256").digest(TestVaults.PASSWORD.toByteArray())

    // Unlocks the good vault, which keeps it as a backup, then replaces the file with [bytes].
    private suspend fun goodCopyThen(bytes: ByteArray): Pair<VaultSession, BackupInfo> {
        storage.put(loc, OpenRig.vault)
        val session = assertIs<OpenResult.Unlocked>(opener.open(loc, pw())).session
        storage.put(loc, bytes)
        return session to backups.list(loc).single()
    }

    @ParameterizedTest
    @ValueSource(ints = [HeaderDictionaries.KDF, HeaderDictionaries.PUBLIC_CUSTOM_DATA])
    fun `check, open, openWithKey and reopen give NotEnoughMemory with the last good copy`(field: Int) = runBlocking<Unit> {
        val (session, good) = goodCopyThen(crafted(field))
        assertEquals(OpenResult.NotEnoughMemory(good), opener.check(loc))
        assertEquals(OpenResult.NotEnoughMemory(good), opener.open(loc, pw()))
        assertEquals(OpenResult.NotEnoughMemory(good), opener.openWithKey(loc, key()))
        assertEquals(OpenResult.NotEnoughMemory(good), opener.reopen(loc, session))
    }

    @ParameterizedTest
    @ValueSource(ints = [HeaderDictionaries.KDF, HeaderDictionaries.PUBLIC_CUSTOM_DATA])
    fun `refresh gives NotEnoughMemory without a copy`(field: Int) = runBlocking<Unit> {
        val (session, _) = goodCopyThen(crafted(field))
        assertEquals(RefreshResult.Failed(OpenResult.NotEnoughMemory()), opener.refresh(loc, session))
    }

    @Test
    fun `the last good copy opens read-only as the copy of a file that can't be read`() = runBlocking<Unit> {
        val (_, good) = goodCopyThen(crafted(HeaderDictionaries.KDF))
        val copy = assertIs<OpenResult.NotEnoughMemory>(opener.check(loc)).lastCopy!!
        assertEquals(good, copy)
        val opened = assertIs<OpenResult.Unlocked>(opener.openBackup(loc, copy, pw(), LastCopyReason.UNAVAILABLE))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.LAST_COPY), opened.session.saveability)
    }

    @Test
    fun `with no copy kept the result carries none`() = runBlocking<Unit> {
        storage.put(loc, crafted(HeaderDictionaries.PUBLIC_CUSTOM_DATA))
        assertEquals(OpenResult.NotEnoughMemory(), opener.check(loc))
    }

    @Test
    fun `a kept copy with such a header is never the last copy and opens as NotEnoughMemory`() = runBlocking<Unit> {
        val (_, good) = goodCopyThen(crafted(HeaderDictionaries.KDF))
        val bad = (backups.add(loc, crafted(HeaderDictionaries.PUBLIC_CUSTOM_DATA), BackupKind.OPENED) as BackupResult.Added).info
        assertEquals(OpenResult.NotEnoughMemory(good), opener.check(loc))
        assertEquals(OpenResult.NotEnoughMemory(), opener.openBackup(loc, bad, pw()))
    }

    @Test
    fun `an OutOfMemoryError while reading the header is NotEnoughMemory with the last good copy`() = runBlocking<Unit> {
        storage.put(loc, OpenRig.vault)
        val throwing = VaultOpener(
            storage, state, Dispatchers.IO, maxHeapBytes = { HEAP }, backups = backups,
            readHeader = { b, heap -> if (b.contentEquals(OpenRig.vault)) VaultXmlCodec.header(b, heap) else throw OutOfMemoryError() },
        ) { b, h, c, budget -> VaultXmlCodec.decode(b, h, c, budget) }
        assertIs<OpenResult.Unlocked>(throwing.open(loc, pw()))
        val good = backups.list(loc).single()
        storage.put(loc, OpenRig.weaker)
        assertEquals(OpenResult.NotEnoughMemory(good), throwing.check(loc))
        assertEquals(OpenResult.NotEnoughMemory(good), throwing.open(loc, pw()))
    }

    @Test
    fun `running out of memory while decrypting carries no copy`() = runBlocking<Unit> {
        storage.put(loc, OpenRig.vault)
        assertIs<OpenResult.Unlocked>(opener.open(loc, pw()))
        storage.put(loc, TestVaults.bytes(aesRounds = 1_000UL))
        val starved = VaultOpener(storage, state, Dispatchers.IO, maxHeapBytes = { HEAP }, backups = backups) { _, _, _, _ -> throw OutOfMemoryError() }
        assertEquals(OpenResult.NotEnoughMemory(), starved.open(loc, pw()))
        val decodedOut = VaultOpener(storage, state, Dispatchers.IO, maxHeapBytes = { HEAP }, backups = backups) { _, _, _, _ -> Decoded.NotEnoughMemory }
        assertEquals(OpenResult.NotEnoughMemory(), decodedOut.open(loc, pw()))
    }

    @Test
    fun `the header reader stops at the budget for the heap it is given`() {
        val bytes = crafted(HeaderDictionaries.KDF)
        assertEquals(Decoded.NotEnoughMemory, assertIs<HeaderRead.Invalid>(VaultXmlCodec.header(bytes, HEAP)).result)
        // Without a budget the whole dictionary is read, and it has no $UUID.
        val unbounded = assertIs<KdbxHeaderReader.Read.Invalid>(KdbxHeaderReader.read(bytes, KdbxHeaderReader.NO_HEAP_LIMIT))
        assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), unbounded.result)
    }

    @Test
    fun `a vault with ordinary dictionaries opens under the same heap`() = runBlocking<Unit> {
        storage.put(loc, OpenRig.vault)
        assertIs<OpenResult.Ready>(opener.check(loc))
        assertIs<OpenResult.Unlocked>(opener.open(loc, pw()))
    }

    @ParameterizedTest
    @ValueSource(ints = [HeaderDictionaries.KDF, HeaderDictionaries.PUBLIC_CUSTOM_DATA])
    @EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
    fun `the file sized for a 512 MiB heap is NotEnoughMemory in a 512 MiB child JVM`(field: Int) {
        val m = MemoryRun.header(field, "512m")
        assertEquals("NotEnoughMemory", m.step("check")?.outcome, m.log.lines().takeLast(20).joinToString("\n"))
    }

    private companion object {
        const val HEAP = 32L * 1024 * 1024
    }
}
