package org.onekash.kashpass.ui.format

import java.time.LocalDateTime
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.storage.Writability
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SaveProblemTest {

    private val vault: OpenedVault = runBlocking { TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL)) }.session.opened
    private val prepared = FakeVaultSaver().prepared(vault)

    // One of each subclass; the when in SaveProblem.message is exhaustive, so an added one fails to
    // compile there.
    private val all = listOf(
        SaveResult.Saved(vault),
        SaveResult.Conflict(vault, prepared),
        SaveResult.NotReachable(vault, prepared),
        SaveResult.NotWritable(vault, Writability.NOT_WRITABLE),
        SaveResult.ReadOnly(vault, Saveability.ReadOnly(ReadOnlyReason.DOCTYPE)),
        SaveResult.KdfRefused(vault, null),
        SaveResult.BackupFailed(vault, prepared),
        SaveResult.WriteFailed(vault, prepared),
        SaveResult.NotSavedUnchanged(vault, prepared),
        SaveResult.MaybeDamaged(vault, prepared),
        SaveResult.VerifyFailed(vault, prepared),
        SaveResult.WriterStillRunning(vault, prepared),
        SaveResult.NotEnoughMemory(vault),
        SaveResult.UnexpectedError(vault, prepared),
    )

    @Test
    fun `every result has a message`() {
        assertEquals(14, all.map { it::class }.toSet().size)
        for (result in all) assertTrue(result.toString(), SaveProblem.message(result) != 0)
    }

    @Test
    fun `retry is a choice only when the file is known unchanged`() {
        val retry = all.filter { SaveChoice.RETRY in SaveProblem.choices(it) }.map { it::class.simpleName }
        assertEquals(listOf("NotReachable", "BackupFailed", "WriteFailed", "NotSavedUnchanged", "WriterStillRunning", "UnexpectedError"), retry)
        for (result in listOf(SaveResult.VerifyFailed(vault, prepared), SaveResult.MaybeDamaged(vault, prepared), SaveResult.Conflict(vault, prepared))) {
            assertFalse(SaveChoice.RETRY in SaveProblem.choices(result))
        }
    }

    @Test
    fun `a conflict allows a copy, a reload or going back, and nothing overwrites`() {
        assertEquals(listOf(SaveChoice.SAVE_AS_COPY, SaveChoice.RELOAD, SaveChoice.KEEP_EDITING), SaveProblem.choices(SaveResult.Conflict(vault, prepared)))
        assertEquals(listOf(SaveChoice.RETRY, SaveChoice.SAVE_AS_COPY, SaveChoice.KEEP_EDITING), SaveProblem.choices(SaveResult.WriteFailed(vault, prepared)))
        assertEquals(listOf(SaveChoice.KEEP_EDITING), SaveProblem.choices(SaveResult.NotEnoughMemory(vault)))
        assertTrue(SaveChoice.entries.none { it.name.contains("OVERWRITE") })
    }

    @Test
    fun `a file that didn't respond allows Retry, a copy or going back`() {
        val result = SaveResult.NotReachable(vault, prepared)
        assertEquals(listOf(SaveChoice.RETRY, SaveChoice.SAVE_AS_COPY, SaveChoice.KEEP_EDITING), SaveProblem.choices(result))
        val res = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>().resources
        assertEquals("The file didn't respond in 30 seconds. Nothing was written.", res.getString(SaveProblem.message(result)))
        assertFalse(SaveProblem.inline(result))
    }

    @Test
    fun `an unexpected error offers Retry only while the file is known unchanged, and a copy only with bytes`() {
        val unknown = vault.withBaseline(OpenedVault.Baseline.Unknown)
        assertEquals(listOf(SaveChoice.RETRY, SaveChoice.SAVE_AS_COPY, SaveChoice.KEEP_EDITING), SaveProblem.choices(SaveResult.UnexpectedError(vault, prepared)))
        assertEquals(listOf(SaveChoice.SAVE_AS_COPY, SaveChoice.RELOAD, SaveChoice.KEEP_EDITING), SaveProblem.choices(SaveResult.UnexpectedError(unknown, prepared)))
        assertEquals(listOf(SaveChoice.KEEP_EDITING), SaveProblem.choices(SaveResult.UnexpectedError(vault, null)))
        assertEquals(listOf(SaveChoice.RELOAD, SaveChoice.KEEP_EDITING), SaveProblem.choices(SaveResult.UnexpectedError(unknown, null)))
        val res = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>().resources
        assertEquals("Not saved: something went wrong. Your edits are kept.", res.getString(SaveProblem.message(SaveResult.UnexpectedError(vault, null))))
        assertFalse(SaveProblem.inline(SaveResult.UnexpectedError(vault, null)))
    }

    @Test
    fun `refusals the editor explains need no sheet`() {
        assertEquals(listOf("NotWritable", "ReadOnly"), all.filter(SaveProblem::inline).map { it::class.simpleName })
    }

    @Test
    fun `a copy is named after the vault with the device and time`() {
        val at = LocalDateTime.of(2026, 10, 20, 9, 5)
        val res = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>().resources
        val pattern = res.getString(org.onekash.kashpass.R.string.copy_name)
        val fallback = res.getString(org.onekash.kashpass.R.string.copy_name_fallback)
        assertEquals("Passwords (device 2026-10-20 0905).kdbx", SaveProblem.copyName(pattern, fallback, "Passwords.kdbx", at))
        assertEquals("Vault (device 2026-10-20 0905).kdbx", SaveProblem.copyName(pattern, fallback, null, at))
    }

    @Test
    fun `a backup saved as a new file is named after the vault and the backup's time`() {
        val res = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>().resources
        val pattern = res.getString(org.onekash.kashpass.R.string.backup_file_name)
        val fallback = res.getString(org.onekash.kashpass.R.string.copy_name_fallback)
        val at = LocalDateTime.of(2026, 10, 19, 10, 0)
        assertEquals("Passwords (backup 2026-10-19 1000).kdbx", SaveProblem.copyName(pattern, fallback, "Passwords.kdbx", at))
    }
}
