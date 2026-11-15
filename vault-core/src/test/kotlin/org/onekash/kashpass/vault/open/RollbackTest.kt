package org.onekash.kashpass.vault.open

import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.doc.KdbxTime
import org.onekash.kashpass.vault.testing.TestVaults

class RollbackTest {

    private val rig = OpenRig()

    private fun vault(modified: String) = TestVaults.rawXmlVault(
        TestVaults.keePassXml(
            "\t\t\t<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><Times><LastModificationTime>${KdbxTime.format(Instant.parse(modified))}</LastModificationTime></Times>" +
                "<String><Key>Title</Key><Value>T</Value></String></Entry>\n",
        ),
    )

    private val newer = vault("2026-06-01T00:00:00Z")
    private val older = vault("2026-01-01T00:00:00Z")

    private fun pw() = TestVaults.PASSWORD.toCharArray()

    @Test
    fun `an open remembers the newest change and an older file later is reported`() = runBlocking<Unit> {
        rig.storage.put(rig.loc, newer)
        assertNull(assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, pw())).olderThan)
        assertEquals(Instant.parse("2026-06-01T00:00:00Z"), rig.state.newestSeen(rig.loc))
        rig.storage.put(rig.loc, older)
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, pw()))
        assertEquals(Instant.parse("2026-06-01T00:00:00Z"), opened.olderThan)
        assertEquals(Instant.parse("2026-01-01T00:00:00Z"), opened.fileNewest)
        assertEquals(Instant.parse("2026-06-01T00:00:00Z"), rig.state.newestSeen(rig.loc), "never lowered by an older file")
    }

    @Test
    fun `refresh and reopen report an older file`() = runBlocking<Unit> {
        rig.storage.put(rig.loc, newer)
        val session = assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, pw())).session
        rig.storage.put(rig.loc, older)
        val reloaded = assertIs<RefreshResult.Reloaded>(rig.opener.refresh(rig.loc, session))
        assertEquals(Instant.parse("2026-06-01T00:00:00Z"), reloaded.opened.olderThan)
        assertEquals(Instant.parse("2026-06-01T00:00:00Z"), assertIs<OpenResult.Unlocked>(rig.opener.reopen(rig.loc, session)).olderThan)
    }

    @Test
    fun `accepting the older version stops the warning`() = runBlocking<Unit> {
        rig.storage.put(rig.loc, newer)
        rig.opener.open(rig.loc, pw())
        rig.storage.put(rig.loc, older)
        val opened = assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, pw()))
        rig.opener.acceptNewest(rig.loc, opened.fileNewest!!)
        assertNull(assertIs<OpenResult.Unlocked>(rig.opener.open(rig.loc, pw())).olderThan)
    }

    @Test
    fun `backups never report or change the newest change seen`() = runBlocking<Unit> {
        rig.storage.put(rig.loc, newer)
        rig.opener.open(rig.loc, pw())
        val backup = (rig.backups.add(rig.loc, older, BackupKind.BEFORE_SAVE) as BackupResult.Added).info
        assertNull(assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, backup, pw())).olderThan)
        assertEquals(Instant.parse("2026-06-01T00:00:00Z"), rig.state.newestSeen(rig.loc))
    }
}
