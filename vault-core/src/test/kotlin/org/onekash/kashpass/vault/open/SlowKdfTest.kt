package org.onekash.kashpass.vault.open

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.u64

class SlowKdfTest {

    private val rig = OpenRig().apply { storage.put(loc, OpenRig.vault) }

    // The test vault with its AES-KDF rounds rewritten; the header HMAC does not match, so a
    // derivation that runs ends as a wrong password, which shows that it ran.
    private fun withRounds(rounds: ULong) = RawKdbx.parse(OpenRig.vault).withKdf { it.with("R", RawDictionary.UINT64, u64(rounds)) }.toBytes()

    private val slow = KdfSettings.AesKdf(100_000_000UL)

    private fun pw() = TestVaults.PASSWORD.toCharArray()

    @Test
    fun `check reports a work jump without deriving`() = runBlocking<Unit> {
        rig.unlock()
        rig.storage.put(rig.loc, withRounds(slow.rounds))
        val decodes = rig.decodes
        val ready = assertIs<OpenResult.Ready>(rig.opener.check(rig.loc))
        assertEquals(slow, ready.slow?.kdf)
        assertEquals(decodes, rig.decodes)
    }

    @Test
    fun `open refuses a slow file until those exact settings are accepted`() = runBlocking<Unit> {
        rig.unlock()
        rig.storage.put(rig.loc, withRounds(slow.rounds))
        val decodes = rig.decodes
        assertEquals(slow, assertIs<OpenResult.TooSlow>(rig.opener.open(rig.loc, pw())).slow.kdf)
        assertEquals(slow, assertIs<OpenResult.TooSlow>(rig.opener.open(rig.loc, pw(), acceptedSlow = KdfSettings.AesKdf(90_000_000UL))).slow.kdf)
        assertEquals(decodes, rig.decodes, "nothing derived")
        rig.opener.open(rig.loc, pw(), acceptedSlow = slow)
        assertEquals(decodes + 1, rig.decodes, "accepted settings derive")
    }

    @Test
    fun `accepted settings become the baseline and stop warning`() = runBlocking<Unit> {
        // An intact vault one round over 10x the default work, so the accepted open
        // succeeds.
        val heavy = TestVaults.bytes(aesRounds = 6_000_001UL)
        rig.state.saveKdfBaseline(rig.loc, KdfSettings.AesKdf(600_000UL))
        rig.storage.put(rig.loc, heavy)
        val warned = assertNotNull(assertIs<OpenResult.Ready>(rig.opener.check(rig.loc)).slow)
        assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, pw(), acceptedSlow = warned.kdf))
        assertEquals(warned.kdf, rig.state.kdfBaseline(rig.loc))
        assertNull(assertIs<OpenResult.Ready>(rig.opener.check(rig.loc)).slow)
    }

    @Test
    fun `refresh and reopen refuse a slow file without deriving`() = runBlocking<Unit> {
        val session = rig.unlock().session
        rig.storage.put(rig.loc, withRounds(slow.rounds))
        val decodes = rig.decodes
        assertIs<OpenResult.TooSlow>(assertIs<RefreshResult.Failed>(rig.opener.refresh(rig.loc, session)).result)
        assertIs<OpenResult.TooSlow>(rig.opener.reopen(rig.loc, session))
        assertEquals(decodes, rig.decodes)
    }

    @Test
    fun `a slow backup warns, by password and by session key`() = runBlocking<Unit> {
        val session = rig.unlock().session
        val backup = (rig.backups.add(rig.loc, withRounds(slow.rounds), BackupKind.BEFORE_SAVE) as BackupResult.Added).info
        val decodes = rig.decodes
        assertIs<OpenResult.TooSlow>(rig.opener.openBackup(rig.loc, backup, pw()))
        assertIs<OpenResult.TooSlow>(rig.opener.openBackup(rig.loc, backup, session))
        assertEquals(decodes, rig.decodes)
        rig.opener.openBackup(rig.loc, backup, pw(), acceptedSlow = slow)
        assertEquals(decodes + 1, rig.decodes)
        assertNotNull(rig.state.kdfBaseline(rig.loc))
    }
}
