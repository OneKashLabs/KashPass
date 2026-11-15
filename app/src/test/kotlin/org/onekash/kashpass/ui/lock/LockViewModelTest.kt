package org.onekash.kashpass.ui.lock

import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import kotlinx.coroutines.cancel
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.platform.ChooseResult
import org.onekash.kashpass.platform.RememberedVault
import org.onekash.kashpass.testing.FakeVaultFiles
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.vault.doc.DecodeFailure
import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.header.UnsupportedReason
import org.onekash.kashpass.vault.open.LastCopyReason
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.policy.KdfSetting
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import kotlinx.coroutines.CompletableDeferred

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class LockViewModelTest {

    private val dispatcher = StandardTestDispatcher()
    private val opener = FakeVaultOpener(dispatcher)
    private val sessions = SessionHolder()
    private val files = FakeVaultFiles().apply { names += mapOf(OTHER to "Shared.kdbx", KEY to "shared.keyx") }

    @Before
    fun setUp() = Dispatchers.setMain(dispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun vm() = LockViewModel(files, opener, sessions)

    @Test
    fun `with no vault the screen is first run, with no password field and no check`() = runTest(dispatcher) {
        val vm = vm()
        advanceUntilIdle()
        assertEquals(LockUiState(), vm.uiState.value)
        assertEquals(0, opener.checks)
    }

    @Test
    fun `Kash's first-run wave is marked once and stays marked through a refresh`() = runTest(dispatcher) {
        val vm = vm()
        advanceUntilIdle()
        assertFalse(vm.wavePlayed)
        vm.markWavePlayed()
        vm.refresh()
        advanceUntilIdle()
        assertTrue(vm.wavePlayed)
    }

    @Test
    fun `a remembered vault is checked on appear and shows the password field when ready`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        assertTrue(vm.uiState.value.checking)
        advanceUntilIdle()
        assertEquals(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true), vm.uiState.value)
        assertEquals(1, opener.checks)
    }

    @Test
    fun `problems found by the check hide the password field before anything is typed`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val cases = listOf(
            OpenResult.Refused(KdfRejection.OutOfBounds(KdfSetting.ARGON2_ITERATIONS, 0UL)) to
                LockMessage.Refused(KdfRejection.OutOfBounds(KdfSetting.ARGON2_ITERATIONS, 0UL)),
            OpenResult.Unsupported(UnsupportedReason.FormatVersion(3, 1)) to LockMessage.Unsupported(UnsupportedReason.FormatVersion(3, 1)),
            OpenResult.Damaged(DamageReason.TRUNCATED) to LockMessage.Damaged,
            OpenResult.Unreadable(StorageFailure.IO_FAILURE) to LockMessage.Unreadable(StorageFailure.IO_FAILURE),
            OpenResult.Failed(DecodeFailure.PLATFORM) to LockMessage.Failed(DecodeFailure.PLATFORM),
        )
        for ((result, message) in cases) {
            opener.checkResult = result
            val vm = vm()
            advanceUntilIdle()
            assertFalse(vm.uiState.value.showPasswordField)
            assertEquals(message, vm.uiState.value.message)
        }
    }

    @Test
    fun `retry is a choice for unreadable files except too large ones`() {
        assertTrue(LockUiState(message = LockMessage.Unreadable(StorageFailure.IO_FAILURE)).canRetry)
        assertFalse(LockUiState(message = LockMessage.Unreadable(StorageFailure.TOO_LARGE)).canRetry)
        assertFalse(LockUiState(message = LockMessage.Damaged).canRetry)
    }

    @Test
    fun `cancelling the picker changes nothing`() = runTest(dispatcher) {
        val vm = vm()
        advanceUntilIdle()
        vm.onPicked(null)
        assertEquals(LockUiState(), vm.uiState.value)
        assertEquals(0, files.chosen.size)
    }

    @Test
    fun `picking a file remembers it and checks it`() = runTest(dispatcher) {
        val vm = vm()
        advanceUntilIdle()
        vm.onPicked(Uri.parse(LOC))
        advanceUntilIdle()
        assertEquals("picked.kdbx", vm.uiState.value.vaultName)
        assertTrue(vm.uiState.value.showPasswordField)
    }

    @Test
    fun `a refused grant shows ChooseFailed`() = runTest(dispatcher) {
        files.failChoose = true
        val vm = vm()
        advanceUntilIdle()
        vm.onPicked(Uri.parse(LOC))
        advanceUntilIdle()
        assertEquals(LockMessage.ChooseFailed, vm.uiState.value.message)
    }

    @Test
    fun `the right password unlocks and publishes the session`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        assertTrue(vm.uiState.value.unlocking)
        advanceUntilIdle()
        assertFalse(vm.uiState.value.unlocking)
        assertNotNull(sessions.current.value)
        assertEquals(LOC, sessions.current.value!!.location)
    }

    @Test
    fun `a wrong password keeps the field, shows the message and publishes nothing`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.unlock("wrong".toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.WrongPassword, vm.uiState.value.message)
        assertTrue(vm.uiState.value.showPasswordField)
        assertNull(sessions.current.value)
    }

    @Test
    fun `a second tap while unlocking starts no second attempt and its password is zeroed`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.openResult = { OpenResult.WrongPassword }
        val vm = vm()
        advanceUntilIdle()
        // The first attempt is deriving its key when the second tap comes.
        opener.holdUnlock()
        vm.unlock("one".toCharArray())
        val second = "two".toCharArray()
        vm.unlock(second)
        opener.releaseUnlock()
        advanceUntilIdle()
        assertEquals(1, opener.opens)
        assertTrue(second.all { it == '\u0000' })
    }

    @Test
    fun `an unlock finishing after a lock is discarded`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        sessions.lock()
        advanceUntilIdle()
        assertNull(sessions.current.value)
        assertFalse(vm.uiState.value.unlocking)
    }

    @Test
    fun `the file is checked again after every lock, so a replaced file is reported before typing`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertNotNull(sessions.current.value)
        assertEquals(1, opener.checks)
        opener.checkResult = OpenResult.Damaged(DamageReason.TRUNCATED)
        sessions.lock()
        advanceUntilIdle()
        assertEquals(2, opener.checks)
        assertEquals(LockMessage.Damaged, vm.uiState.value.message)
    }

    @Test
    fun `picking a file while an unlock runs is ignored`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        vm.onPicked(Uri.parse("content://drive/document/other"))
        advanceUntilIdle()
        assertEquals(emptyList<Uri>(), files.chosen)
        assertEquals(LOC, sessions.current.value?.location)
    }

    @Test
    fun `an unlock for a file other than the chosen one is discarded`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        files.vault = RememberedVault("content://drive/document/other", "Other.kdbx")
        advanceUntilIdle()
        assertNull(sessions.current.value)
        assertFalse(vm.uiState.value.unlocking)
    }

    @Test
    fun `not enough memory hides the field with its message`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.openResult = { OpenResult.NotEnoughMemory() }
        val vm = vm()
        advanceUntilIdle()
        vm.unlock("x".toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.NotEnoughMemory, vm.uiState.value.message)
        assertFalse(vm.uiState.value.showPasswordField)
    }

    private val backup = org.onekash.kashpass.vault.backup.BackupInfo(
        "1-opened-${"0".repeat(64)}.kdbx", java.time.Instant.parse("2026-10-19T10:00:00Z"), 100, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0".repeat(64),
    )

    @Test
    fun `an unreadable file with a backup shows the last copy, which opens read-only with the password`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.checkResult = OpenResult.Unreadable(StorageFailure.IO_FAILURE, backup)
        val vm = vm()
        advanceUntilIdle()
        assertEquals(LastCopy(backup, LastCopyReason.UNAVAILABLE), vm.uiState.value.lastCopy)
        assertFalse(vm.uiState.value.showPasswordField)
        vm.openLastCopy()
        assertEquals(backup, vm.uiState.value.backupTarget)
        assertEquals(LastCopyReason.UNAVAILABLE, vm.uiState.value.targetLastCopy)
        assertTrue(vm.uiState.value.showPasswordField)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(listOf("openBackup"), opener.calls)
        val unlocked = sessions.current.value!!
        assertNotNull(unlocked.backup)
        assertEquals(
            org.onekash.kashpass.vault.doc.Saveability.ReadOnly(org.onekash.kashpass.vault.doc.ReadOnlyReason.LAST_COPY),
            unlocked.session.saveability,
        )
    }

    @Test
    fun `a header that needs more memory than the heap shows the message and the last copy, which opens as a last copy`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.checkResult = OpenResult.NotEnoughMemory(backup)
        val vm = vm()
        advanceUntilIdle()
        assertEquals(LockMessage.NotEnoughMemory, vm.uiState.value.message)
        assertFalse(vm.uiState.value.showPasswordField)
        assertEquals(LastCopy(backup, LastCopyReason.UNAVAILABLE), vm.uiState.value.lastCopy)
        vm.openLastCopy()
        assertEquals(LastCopyReason.UNAVAILABLE, vm.uiState.value.targetLastCopy)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(
            org.onekash.kashpass.vault.doc.Saveability.ReadOnly(org.onekash.kashpass.vault.doc.ReadOnlyReason.LAST_COPY),
            sessions.current.value!!.session.saveability,
        )
    }

    @Test
    fun `a launch check whose header dictionary fills the heap shows the message and the last copy`() = runTest(dispatcher) {
        val heap = 32L * 1024 * 1024
        val storage = org.onekash.kashpass.vault.testing.FakeVaultStorage()
        val backupStore = org.onekash.kashpass.vault.testing.FakeBackupStore()
        val good = backupStore.add(LOC, TestVaults.bytes(aesRounds = 1_000UL), org.onekash.kashpass.vault.backup.BackupKind.OPENED)
        val crafted = org.onekash.kashpass.vault.testing.HeaderDictionaries.manyEntries(
            org.onekash.kashpass.vault.testing.HeaderDictionaries.KDF, org.onekash.kashpass.vault.storage.maxVaultBytes(heap) - 1,
        )
        storage.put(LOC, crafted)
        val realOpener = org.onekash.kashpass.vault.testing.HeaderDictionaries.opener(storage, org.onekash.kashpass.vault.testing.FakeVaultStateStore(), dispatcher, heap, backupStore)
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = LockViewModel(files, realOpener, sessions)
        advanceUntilIdle()
        assertEquals(LockMessage.NotEnoughMemory, vm.uiState.value.message)
        assertFalse(vm.uiState.value.showPasswordField)
        val info = (good as org.onekash.kashpass.vault.backup.BackupResult.Added).info
        assertEquals(LastCopy(info, LastCopyReason.UNAVAILABLE), vm.uiState.value.lastCopy)
    }

    @Test
    fun `cancelling a password unlock stops the attempt, zeroes the password and leaves the field for another try`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        opener.holdUnlock()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        runCurrent()
        assertTrue(vm.uiState.value.unlocking)
        vm.cancelUnlock()
        advanceUntilIdle()
        assertFalse(vm.uiState.value.unlocking)
        assertEquals(1, opener.cancelledUnlocks)
        assertTrue(opener.passwordArrays.single().all { it == '\u0000' })
        assertTrue(vm.uiState.value.showPasswordField)
        assertNull(vm.uiState.value.message)
        assertNull(sessions.current.value)
        opener.releaseUnlock()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertNotNull("a new attempt runs as usual", sessions.current.value)
    }

    @Test
    fun `cancelling a backup unlock stops the attempt and keeps the backup as the target`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.openBackup(backup)
        opener.holdUnlock()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        runCurrent()
        assertTrue(vm.uiState.value.unlocking)
        vm.cancelUnlock()
        advanceUntilIdle()
        assertFalse(vm.uiState.value.unlocking)
        assertEquals(1, opener.cancelledUnlocks)
        assertEquals(backup, vm.uiState.value.backupTarget)
        assertNull(sessions.current.value)
    }

    @Test
    fun `cancelling with no attempt running changes nothing`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        val before = vm.uiState.value
        vm.cancelUnlock()
        advanceUntilIdle()
        assertEquals(before, vm.uiState.value)
    }

    @Test
    fun `a damaged backup says so and stays on the backup`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.backupResult = OpenResult.BackupDamaged
        val vm = vm()
        advanceUntilIdle()
        vm.openBackup(backup)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.BackupDamaged, vm.uiState.value.message)
        assertEquals(backup, vm.uiState.value.backupTarget)
        assertEquals(null, sessions.current.value)
    }

    @Test
    fun `a corrupted file shows its last copy, which opens as the corrupted file's copy`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.checkResult = OpenResult.Damaged(DamageReason.TRUNCATED, backup)
        val vm = vm()
        advanceUntilIdle()
        assertEquals(LockMessage.Damaged, vm.uiState.value.message)
        assertEquals(LastCopy(backup, LastCopyReason.CORRUPTED), vm.uiState.value.lastCopy)
        assertFalse(vm.uiState.value.showPasswordField)
        vm.openLastCopy()
        assertEquals(LastCopyReason.CORRUPTED, vm.uiState.value.targetLastCopy)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(
            org.onekash.kashpass.vault.doc.Saveability.ReadOnly(org.onekash.kashpass.vault.doc.ReadOnlyReason.LAST_COPY_CORRUPTED),
            sessions.current.value!!.session.saveability,
        )
    }

    @Test
    fun `damage after the header shows the repair hint and a copy that opens as such`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.checkResult = OpenResult.Damaged(DamageReason.BLOCK_HMAC, backup)
        val vm = vm()
        advanceUntilIdle()
        assertEquals(LockMessage.DamagedAfterHeader, vm.uiState.value.message)
        assertEquals(LastCopy(backup, LastCopyReason.CORRUPTED_AFTER_HEADER), vm.uiState.value.lastCopy)
        vm.openLastCopy()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(
            org.onekash.kashpass.vault.doc.Saveability.ReadOnly(org.onekash.kashpass.vault.doc.ReadOnlyReason.LAST_COPY_CORRUPTED_AFTER_HEADER),
            sessions.current.value!!.session.saveability,
        )
    }

    @Test
    fun `a damaged backup keeps the backup message, never the repair hint`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.checkResult = OpenResult.Damaged(DamageReason.BLOCK_HMAC, backup)
        opener.backupResult = OpenResult.Damaged(DamageReason.BLOCK_HMAC)
        val vm = vm()
        advanceUntilIdle()
        vm.openLastCopy()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.BackupDamaged, vm.uiState.value.message)
    }

    @Test
    fun `a corrupted file without a good copy shows none`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.checkResult = OpenResult.Damaged(DamageReason.TRUNCATED)
        val vm = vm()
        advanceUntilIdle()
        assertNull(vm.uiState.value.lastCopy)
    }

    @Test
    fun `a corrupted last copy says the backup is corrupted and cancel goes back to the file`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.checkResult = OpenResult.Damaged(DamageReason.TRUNCATED, backup)
        opener.backupResult = OpenResult.Damaged(DamageReason.TRUNCATED)
        val vm = vm()
        advanceUntilIdle()
        vm.openLastCopy()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.BackupDamaged, vm.uiState.value.message)
        assertEquals(backup, vm.uiState.value.backupTarget)
        assertTrue(vm.uiState.value.showPasswordField)
        vm.cancelBackup()
        advanceUntilIdle()
        assertNull(vm.uiState.value.backupTarget)
    }

    @Test
    fun `a last copy that can't be read says the backup is corrupted`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.checkResult = OpenResult.Unreadable(StorageFailure.IO_FAILURE, backup)
        opener.backupResult = OpenResult.Unreadable(StorageFailure.NOT_FOUND)
        val vm = vm()
        advanceUntilIdle()
        vm.openLastCopy()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.BackupDamaged, vm.uiState.value.message)
        assertTrue(vm.uiState.value.showPasswordField)
    }

    @Test
    fun `a save cut off before the lock is reported by check`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        opener.checkResult = OpenResult.Ready(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(600_000UL), weak = false, lostCutOffSave = true)
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.lostCutOffSave)
        assertTrue(vm.uiState.value.showPasswordField)
    }

    private companion object {
        const val LOC = "content://drive/document/doc1"
        const val OTHER = "content://other.app/files/shared.kdbx"
        const val KEY = "content://other.app/files/shared.keyx"
        const val KEY_2 = "content://other.app/files/second.keyx"
        const val PICKED = "content://drive/document/doc7"
    }

    @Test
    fun `an Open with of the remembered vault shows the lock screen and nothing else`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(LOC), writableGrant = true)
        advanceUntilIdle()
        assertEquals(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true), vm.uiState.value)
        assertTrue(files.taken.isEmpty())
    }

    @Test
    fun `a file with a writable grant and no vault remembered waits for Open this file`() = runTest(dispatcher) {
        files.offeredWritable = true
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        advanceUntilIdle()
        assertTrue("nothing becomes the vault without the tap", files.chosen.isEmpty())
        assertEquals("Shared.kdbx", vm.uiState.value.vaultName)
        assertTrue(vm.uiState.value.offered)
        assertNull(vm.uiState.value.offeredInPlaceOf)
        assertFalse(vm.uiState.value.showPasswordField)
        assertFalse(vm.uiState.value.openedFromApp)
        vm.openOffered()
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse(OTHER)), files.chosen)
        assertEquals("picked.kdbx", vm.uiState.value.vaultName)
        assertFalse(vm.uiState.value.offered)
    }

    @Test
    fun `Cancel on a file offered with no vault remembered releases its grant and goes back to first run`() = runTest(dispatcher) {
        files.offeredWritable = true
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        advanceUntilIdle()
        vm.cancelIncoming()
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse(OTHER)), files.released)
        assertEquals(LockUiState(), vm.uiState.value)
        assertTrue(files.chosen.isEmpty())
    }

    @Test
    fun `an Open with that arrives while a password unlock runs shows once that attempt fails`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.unlock("wrong".toCharArray())
        assertTrue(vm.uiState.value.unlocking)
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        assertNull(sessions.current.value)
        assertTrue(vm.uiState.value.openedFromApp)
        assertEquals("Shared.kdbx", vm.uiState.value.vaultName)
    }

    @Test
    fun `an Open with that arrives while a fingerprint unlock runs shows once the prompt is cancelled`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        // The prompt shows when the file arrives; then the user cancels it.
        val answer = kotlinx.coroutines.CompletableDeferred<org.onekash.kashpass.vault.storage.Confirmation>()
        vm.unlockWithBiometric { answer.await() }
        assertTrue(vm.uiState.value.unlocking)
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        answer.complete(org.onekash.kashpass.vault.storage.Confirmation.Cancelled)
        advanceUntilIdle()
        assertNull(sessions.current.value)
        assertTrue(vm.uiState.value.openedFromApp)
        assertEquals("Shared.kdbx", vm.uiState.value.vaultName)
    }

    @Test
    fun `an Open with that arrives while an unlock succeeds waits for the next lock`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        assertNotNull(sessions.current.value)
        sessions.lock()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.openedFromApp)
    }

    @Test
    fun `an offered file that a refresh, a pick or another Open with drops has its grant released`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        files.offeredWritable = true
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        advanceUntilIdle()
        vm.refresh()
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse(OTHER)), files.released)
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        advanceUntilIdle()
        vm.onPicked(Uri.parse(PICKED))
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse(OTHER), Uri.parse(OTHER)), files.released)
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(KEY), writableGrant = true)
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse(OTHER), Uri.parse(OTHER), Uri.parse(OTHER)), files.released)
        assertTrue(vm.uiState.value.offered)
        assertEquals("shared.keyx", vm.uiState.value.vaultName)
    }

    @Test
    fun `an offer overtaken before its grant returns has the grant released`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        files.offeredWritable = true
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        // The grant is taken after the refresh started, so the offer is stale when it returns.
        vm.refresh()
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse(OTHER)), files.taken)
        assertEquals(listOf(Uri.parse(OTHER)), files.released)
        assertFalse(vm.uiState.value.offered)
        assertEquals("Passwords.kdbx", vm.uiState.value.vaultName)
    }

    @Test
    fun `picking the offered file itself keeps its grant`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        files.offeredWritable = true
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        advanceUntilIdle()
        vm.onPicked(Uri.parse(OTHER))
        advanceUntilIdle()
        assertTrue(files.released.isEmpty())
        assertEquals(listOf(Uri.parse(OTHER)), files.chosen)
    }

    @Test
    fun `a file with a writable grant waits for Open this file while another vault is remembered`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        files.offeredWritable = true
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        advanceUntilIdle()
        assertEquals("Shared.kdbx", vm.uiState.value.vaultName)
        assertEquals("Passwords.kdbx", vm.uiState.value.offeredInPlaceOf)
        assertTrue(vm.uiState.value.offered)
        assertFalse(vm.uiState.value.showPasswordField)
        assertTrue("nothing replaced yet", files.chosen.isEmpty())
        vm.openOffered()
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse(OTHER)), files.chosen)
        assertNull(vm.uiState.value.offeredInPlaceOf)
    }

    @Test
    fun `Cancel on an offered file releases its grant and goes back to the remembered vault`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        files.offeredWritable = true
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        advanceUntilIdle()
        vm.cancelIncoming()
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse(OTHER)), files.released)
        assertEquals(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true), vm.uiState.value)
        assertTrue(files.chosen.isEmpty())
    }

    @Test
    fun `a file without a writable grant opens read-only for this session and the next lock drops it`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        assertTrue("the provider isn't asked without a persistable write grant", files.taken.isEmpty())
        val state = vm.uiState.value
        assertEquals("Shared.kdbx", state.vaultName)
        assertTrue(state.openedFromApp)
        assertEquals("making it the vault names the vault it replaces", "Passwords.kdbx", state.openedInPlaceOf)
        assertTrue(state.showPasswordField)
        assertEquals(OTHER, opener.locations.last())
        assertEquals(org.onekash.kashpass.vault.doc.FileAccess.SESSION_ONLY, opener.accesses.last())
        assertEquals(Uri.parse(OTHER), vm.pickStart())
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        val unlocked = sessions.current.value!!
        assertEquals(OTHER, unlocked.location)
        assertEquals(org.onekash.kashpass.session.VaultTarget.SESSION_ONLY, unlocked.target)
        assertEquals("Shared.kdbx", unlocked.sessionName)
        assertEquals(org.onekash.kashpass.vault.doc.FileAccess.SESSION_ONLY, opener.accesses.last())
        assertEquals(
            org.onekash.kashpass.vault.doc.Saveability.ReadOnly(org.onekash.kashpass.vault.doc.ReadOnlyReason.OPENED_FROM_APP),
            unlocked.session.saveability,
        )
        sessions.lock()
        advanceUntilIdle()
        assertEquals(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true), vm.uiState.value)
        assertNull(vm.pickStart())
    }

    @Test
    fun `a file whose provider refuses the writable grant opens for this session`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        files.offeredWritable = false
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = true)
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse(OTHER)), files.taken)
        assertTrue(vm.uiState.value.openedFromApp)
        assertNull(vm.uiState.value.offeredInPlaceOf)
    }

    @Test
    fun `Cancel on a session-only file goes back to the remembered vault`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        vm.cancelIncoming()
        advanceUntilIdle()
        assertEquals(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true), vm.uiState.value)
        assertTrue(files.released.isEmpty())
    }

    @Test
    fun `a session-only file gets no biometric prompt or button, and biometric state isn't checked for it`() = runTest(dispatcher) {
        fingerprintOn()
        keys.seal(OTHER, ByteArray(32), confirmed)
        keys.invalidate(OTHER)
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        val requests = vm.uiState.value.promptRequest
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        vm.onDisappear(changingConfigurations = false)
        vm.onAppear()
        assertEquals(requests, vm.uiState.value.promptRequest)
        assertFalse(vm.uiState.value.biometricOn)
        assertNull(vm.uiState.value.turnedOff)
        assertFalse("delete" to OTHER in keys.calls)
        vm.unlockWithBiometric(confirmed)
        advanceUntilIdle()
        assertNull(sessions.current.value)
    }

    @Test
    fun `a session-only file's key file is read for the unlock and never remembered`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = keyVm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        vm.startKeyFilePick()
        vm.onKeyFilePicked(Uri.parse(KEY))
        advanceUntilIdle()
        assertEquals("shared.keyx", vm.uiState.value.keyFileName)
        assertNull(keyFiles.current(OTHER))
        assertNull(keyFiles.current(LOC))
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(listOf(KEY), keyFiles.onceReads)
        assertEquals(org.onekash.kashpass.vault.doc.UnlockOrigin.PASSWORD_AND_KEY_FILE, sessions.current.value!!.session.opened.origin)
        assertFalse("a session-only file records nothing", keyFiles.keyFileUnlock(OTHER))
        assertFalse(keyFiles.keyFileUnlock(LOC))
        sessions.lock()
        advanceUntilIdle()
        assertNull("the key file goes with the session-only file", vm.uiState.value.keyFileName)
    }

    // A session-only file shown with two key files whose names load until the test completes them.
    private fun sessionKeyVm(): Pair<LockViewModel, List<CompletableDeferred<Unit>>> {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        files.names += mapOf(KEY_2 to "second.keyx")
        val gates = listOf(KEY, KEY_2).map { CompletableDeferred<Unit>().also { gate -> files.nameGates[it] = gate } }
        return keyVm() to gates
    }

    @Test
    fun `the later of two session-only key-file picks wins while the first name loads`() = runTest(dispatcher) {
        val (vm, gates) = sessionKeyVm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        vm.onKeyFilePicked(Uri.parse(KEY))
        runCurrent()
        vm.onKeyFilePicked(Uri.parse(KEY_2))
        runCurrent()
        gates[0].complete(Unit)
        advanceUntilIdle()
        gates[1].complete(Unit)
        advanceUntilIdle()
        assertEquals("second.keyx", vm.uiState.value.keyFileName)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(listOf(KEY_2), keyFiles.onceReads)
    }

    @Test
    fun `removing the session-only key file while a pick's name loads leaves no key file`() = runTest(dispatcher) {
        val (vm, gates) = sessionKeyVm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        vm.onKeyFilePicked(Uri.parse(KEY))
        runCurrent()
        vm.removeKeyFile()
        gates[0].complete(Unit)
        advanceUntilIdle()
        assertNull(vm.uiState.value.keyFileName)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertTrue(keyFiles.onceReads.isEmpty())
    }

    @Test
    fun `handing over the same file again while a key file's name loads drops the pick`() = runTest(dispatcher) {
        val (vm, gates) = sessionKeyVm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        vm.onKeyFilePicked(Uri.parse(KEY))
        runCurrent()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        gates[0].complete(Unit)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.openedFromApp)
        assertNull(vm.uiState.value.keyFileName)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertTrue(keyFiles.onceReads.isEmpty())
    }

    @Test
    fun `an Open with while unlocked changes nothing and is offered after the next lock`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        unlocked(vm)
        val open = sessions.current.value
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        assertSame(open, sessions.current.value)
        assertTrue(open!!.session.isOpen)
        sessions.lock()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.openedFromApp)
        assertEquals("Shared.kdbx", vm.uiState.value.vaultName)
    }

    @Test
    fun `a read-only remembered vault unlocks with provider read-only access`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx", readOnly = true)
        val vm = vm()
        advanceUntilIdle()
        unlocked(vm)
        assertEquals(org.onekash.kashpass.vault.doc.FileAccess.PROVIDER_READ_ONLY, opener.accesses.last())
        assertEquals(
            org.onekash.kashpass.vault.doc.Saveability.ReadOnly(org.onekash.kashpass.vault.doc.ReadOnlyReason.PROVIDER_READ_ONLY),
            sessions.current.value!!.session.saveability,
        )
    }

    @Test
    fun `a session-only unlock, a refused save and a lock write nothing to the stores`() = runTest(dispatcher) {
        val storage = org.onekash.kashpass.vault.testing.FakeVaultStorage()
        val state = org.onekash.kashpass.vault.testing.FakeVaultStateStore()
        val backupStore = org.onekash.kashpass.vault.testing.FakeBackupStore()
        val markers = org.onekash.kashpass.vault.testing.FakeSaveMarkerStore()
        val unlockKeys = org.onekash.kashpass.vault.testing.FakeUnlockKeyStore()
        val realOpener = org.onekash.kashpass.vault.open.VaultOpener.create(storage, state, dispatcher, backupStore, markers)
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + dispatcher)
        val saver = org.onekash.kashpass.vault.save.SafeSaver.create(storage, backupStore, markers, state, dispatcher, scope)
        val coordinator = org.onekash.kashpass.session.SaveCoordinator(sessions, saver, realOpener, scope, storage, backupStore)
        val unlock = org.onekash.kashpass.session.BiometricUnlock(unlockKeys, realOpener, state, sessions)
        storage.put(OTHER, TestVaults.bytes(aesRounds = 1_000UL))
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = LockViewModel(files, realOpener, sessions, unlock, keyFiles)
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        val unlocked = sessions.current.value!!
        assertTrue(unlocked.sessionOnly)
        val result = coordinator.save(unlocked.session.opened.document)
        advanceUntilIdle()
        assertTrue(result.await() is org.onekash.kashpass.vault.save.SaveResult.ReadOnly)
        assertFalse(unlock.offerVisible(sessions.current.value!!))
        sessions.lock()
        advanceUntilIdle()
        for (location in listOf(OTHER, LOC)) {
            assertNull(state.kdfBaseline(location))
            assertNull(state.newestSeen(location))
            assertNull(state.weakWarningDismissedFor(location))
            assertFalse(state.biometricOfferShown(location))
            assertTrue(backupStore.list(location).isEmpty())
            assertNull(markers.get(location))
        }
        assertTrue(backupStore.attempts.isEmpty())
        assertTrue(markers.history.isEmpty())
        assertTrue(unlockKeys.calls.isEmpty())
        assertEquals(0, storage.writes)
        assertNull(keyFiles.current(OTHER))
        assertEquals(RememberedVault(LOC, "Passwords.kdbx"), files.current())
        scope.cancel()
    }

    @Test
    fun `while the lock screen only covers a save, nothing on it can unlock or open`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.showPasswordField)
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        sessions.set(org.onekash.kashpass.session.Unlocked(LOC, opened.session, opened.kdf, false))
        val password = "pw".toCharArray()
        vm.unlock(password)
        vm.openBackup(backup)
        vm.onPicked(android.net.Uri.parse("content://other/vault"))
        advanceUntilIdle()
        assertEquals(emptyList<String>(), opener.calls.filter { it == "openBackup" })
        assertEquals(0, opener.opens)
        assertEquals(null, vm.uiState.value.backupTarget)
        assertTrue("the password is wiped", password.all { it == '\u0000' })
        assertTrue(sessions.current.value!!.session === opened.session)
    }

    @Test
    fun `a much slower file warns before the password is used, and Unlock anyway accepts those settings`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val slow = org.onekash.kashpass.vault.policy.SlowKdf(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(100_000_000UL), 100, 166)
        opener.checkResult = OpenResult.Ready(slow.kdf, weak = false, slow = slow)
        val vm = vm()
        advanceUntilIdle()
        assertEquals(slow, vm.uiState.value.slow)
        assertTrue(vm.uiState.value.showPasswordField)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(listOf<org.onekash.kashpass.vault.header.KdfSettings?>(slow.kdf), opener.acceptedSlow)
    }

    @Test
    fun `a slow result from open shows the warning instead of unlocking`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val slow = org.onekash.kashpass.vault.policy.SlowKdf(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(100_000_000UL), 100, 166)
        opener.openResult = { OpenResult.TooSlow(slow) }
        val vm = vm()
        advanceUntilIdle()
        vm.unlock("x".toCharArray())
        advanceUntilIdle()
        assertEquals(slow, vm.uiState.value.slow)
        assertTrue(vm.uiState.value.showPasswordField)
        assertEquals(null, sessions.current.value)
    }

    private val keys = org.onekash.kashpass.vault.testing.FakeUnlockKeyStore()
    private val vaultState = org.onekash.kashpass.vault.testing.FakeVaultStateStore()
    private val biometric = org.onekash.kashpass.session.BiometricUnlock(keys, opener, vaultState, sessions)
    private val confirmed: suspend (org.onekash.kashpass.vault.storage.CryptoHandle) -> org.onekash.kashpass.vault.storage.Confirmation =
        { org.onekash.kashpass.vault.storage.Confirmation.Confirmed }

    private suspend fun unlockedSession(): org.onekash.kashpass.session.Unlocked {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        return org.onekash.kashpass.session.Unlocked(LOC, opened.session, opened.kdf, false)
    }

    // Seals the test vault's own passphrase hash, which is all the fake opener accepts.
    private suspend fun fingerprintOn() {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest(TestVaults.PASSWORD.toByteArray(Charsets.UTF_8))
        keys.seal(LOC, hash, confirmed)
    }

    @Test
    fun `with fingerprint unlock on, the lock screen requests the prompt once and a touch unlocks`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.biometricOn)
        assertEquals(1, vm.uiState.value.promptRequest)
        vm.unlockWithBiometric(confirmed)
        advanceUntilIdle()
        assertTrue(sessions.current.value != null)
        assertEquals(listOf("openWithKey"), opener.calls.filter { it == "openWithKey" })
    }

    @Test
    fun `cancelling a fingerprint unlock stops the attempt after the prompt and keeps the stored key`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        opener.holdUnlock()
        vm.unlockWithBiometric(confirmed)
        runCurrent()
        assertTrue(vm.uiState.value.unlocking)
        vm.cancelUnlock()
        advanceUntilIdle()
        assertFalse(vm.uiState.value.unlocking)
        assertEquals(1, opener.cancelledUnlocks)
        assertNull(sessions.current.value)
        assertTrue(vm.uiState.value.biometricOn)
        assertEquals(org.onekash.kashpass.vault.storage.StoredKeyState.STORED, keys.state(LOC))
        opener.releaseUnlock()
        vm.unlockWithBiometric(confirmed)
        advanceUntilIdle()
        assertNotNull("a new attempt runs as usual", sessions.current.value)
    }

    @Test
    fun `a lock during a password unlock stops the key derivation and leaves the field for another try`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        opener.holdUnlock()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        runCurrent()
        assertTrue(vm.uiState.value.unlocking)
        sessions.lock()
        advanceUntilIdle()
        assertEquals("the derivation is cancelled", 1, opener.cancelledUnlocks)
        assertFalse(vm.uiState.value.unlocking)
        assertTrue(opener.passwordArrays.single().all { it == '\u0000' })
        assertNull(sessions.current.value)
    }

    @Test
    fun `a lock during a fingerprint unlock stops it and keeps the stored key`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        opener.holdUnlock()
        vm.unlockWithBiometric(confirmed)
        runCurrent()
        assertTrue(vm.uiState.value.unlocking)
        sessions.lock()
        advanceUntilIdle()
        assertEquals(1, opener.cancelledUnlocks)
        assertFalse(vm.uiState.value.unlocking)
        assertNull(sessions.current.value)
        assertEquals(org.onekash.kashpass.vault.storage.StoredKeyState.STORED, keys.state(LOC))
    }

    @Test
    fun `a lock while the fingerprint prompt shows cancels the prompt, not the stored key`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        var promptCancelled = false
        vm.unlockWithBiometric {
            try {
                kotlinx.coroutines.awaitCancellation()
            } finally {
                promptCancelled = true
            }
        }
        runCurrent()
        assertTrue(vm.uiState.value.unlocking)
        sessions.lock()
        advanceUntilIdle()
        assertTrue("the prompt is cancelled", promptCancelled)
        assertFalse(vm.uiState.value.unlocking)
        assertFalse(vm.uiState.value.biometricFailed)
        assertTrue(vm.uiState.value.biometricOn)
        assertEquals(org.onekash.kashpass.vault.storage.StoredKeyState.STORED, keys.state(LOC))
        assertEquals("nothing reached the opener", emptyList<String>(), opener.calls.filter { it == "openWithKey" })
    }

    @Test
    fun `Cancel stops prompting until the next appearance, Use password shows the field`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        vm.unlockWithBiometric { org.onekash.kashpass.vault.storage.Confirmation.Cancelled }
        advanceUntilIdle()
        assertEquals(1, vm.uiState.value.promptRequest)
        vm.onDisappear(changingConfigurations = false)
        vm.onAppear()
        assertEquals("a new appearance asks again", 2, vm.uiState.value.promptRequest)
        vm.unlockWithBiometric { org.onekash.kashpass.vault.storage.Confirmation.UsePassword }
        advanceUntilIdle()
        assertTrue(vm.uiState.value.passwordChosen)
        assertEquals(null, sessions.current.value)
    }

    @Test
    fun `an interruption doesn't switch to the password and prompts again`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        vm.unlockWithBiometric { org.onekash.kashpass.vault.storage.Confirmation.Interrupted }
        advanceUntilIdle()
        assertFalse(vm.uiState.value.passwordChosen)
        vm.onAppear()
        assertEquals(2, vm.uiState.value.promptRequest)
    }

    @Test
    fun `a reason to turn off is shown with the password field`() = runTest(dispatcher) {
        fingerprintOn()
        keys.invalidate(LOC)
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        // Noticed when the lock screen appears, before any prompt.
        assertEquals(org.onekash.kashpass.session.TurnOffReason.NEW_BIOMETRIC, vm.uiState.value.turnedOff)
        assertEquals(0, vm.uiState.value.promptRequest)
        assertFalse(vm.uiState.value.biometricOn)
        assertTrue(vm.uiState.value.showPasswordField)
    }

    @Test
    fun `a key the Keystore can't recover is shown as turned off with the password field`() = runTest(dispatcher) {
        fingerprintOn()
        keys.unrecoverable(LOC)
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        assertEquals(org.onekash.kashpass.session.TurnOffReason.UNRECOVERABLE_KEY, vm.uiState.value.turnedOff)
        assertEquals(0, vm.uiState.value.promptRequest)
        assertFalse(vm.uiState.value.biometricOn)
        assertTrue(vm.uiState.value.showPasswordField)
        assertEquals(null, keys.stored(LOC))
    }

    @Test
    fun `no prompt for a slow file, while a pick is pending, or while a session is set`() = runTest(dispatcher) {
        fingerprintOn()
        val slow = org.onekash.kashpass.vault.policy.SlowKdf(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(100_000_000UL), 100, 166)
        opener.checkResult = OpenResult.Ready(slow.kdf, weak = false, slow = slow)
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        assertEquals(0, vm.uiState.value.promptRequest)
        opener.checkResult = OpenResult.Ready(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(600_000UL), weak = false)
        vm.startPick()
        vm.refresh()
        advanceUntilIdle()
        vm.onAppear()
        assertEquals("the picker is open", 0, vm.uiState.value.promptRequest)
        vm.onPicked(null)
        vm.onAppear()
        assertEquals(1, vm.uiState.value.promptRequest)
    }

    @Test
    fun `a prompt request is served once, so a rotation doesn't prompt again`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        var prompts = 0
        val cancel: suspend (org.onekash.kashpass.vault.storage.CryptoHandle) -> org.onekash.kashpass.vault.storage.Confirmation =
            { prompts++; org.onekash.kashpass.vault.storage.Confirmation.Cancelled }
        vm.servePromptRequest(cancel)
        advanceUntilIdle()
        vm.servePromptRequest(cancel)
        advanceUntilIdle()
        assertEquals(1, prompts)
    }

    @Test
    fun `a pick requested before the lock opens the picker, and the prompt follows it`() = runTest(dispatcher) {
        fingerprintOn()
        sessions.set(unlockedSession())
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        vm.requestPick()
        assertFalse("not served over a session (the save cover)", vm.takePickRequest())
        sessions.lock()
        advanceUntilIdle()
        assertEquals(1, vm.uiState.value.pickRequest)
        assertTrue(vm.takePickRequest())
        assertFalse("served once", vm.takePickRequest())
        assertEquals("no prompt over the picker", 0, vm.uiState.value.promptRequest)
        vm.onPicked(null)
        vm.onAppear()
        assertEquals(1, vm.uiState.value.promptRequest)
    }

    @Test
    fun `each lock requests the prompt again`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        vm.servePromptRequest(confirmed)
        advanceUntilIdle()
        assertTrue(sessions.current.value != null)
        sessions.lock()
        advanceUntilIdle()
        assertEquals(2, vm.uiState.value.promptRequest)
    }

    @Test
    fun `after Cancel a rotation doesn't prompt, a real return does`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        vm.servePromptRequest { org.onekash.kashpass.vault.storage.Confirmation.Cancelled }
        advanceUntilIdle()
        vm.onDisappear(changingConfigurations = true)
        vm.onAppear()
        assertEquals(1, vm.uiState.value.promptRequest)
        vm.onDisappear(changingConfigurations = false)
        vm.onAppear()
        assertEquals(2, vm.uiState.value.promptRequest)
    }

    @Test
    fun `while the prompt shows a password unlock is ignored`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        val gate = CompletableDeferred<org.onekash.kashpass.vault.storage.Confirmation>()
        vm.unlockWithBiometric { gate.await() }
        runCurrent()
        assertTrue(vm.uiState.value.unlocking)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        runCurrent()
        assertEquals(0, opener.opens)
        gate.complete(org.onekash.kashpass.vault.storage.Confirmation.Cancelled)
        advanceUntilIdle()
        assertFalse(vm.uiState.value.unlocking)
    }

    @Test
    fun `no prompt while a backup is the target`() = runTest(dispatcher) {
        fingerprintOn()
        opener.checkResult = OpenResult.Ready(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(600_000UL), weak = false)
        val vm = LockViewModel(files, opener, sessions, biometric)
        vm.servePromptRequest { org.onekash.kashpass.vault.storage.Confirmation.Cancelled }
        advanceUntilIdle()
        val requests = vm.uiState.value.promptRequest
        vm.openBackup(org.onekash.kashpass.vault.backup.BackupInfo("b", java.time.Instant.EPOCH, 10L, org.onekash.kashpass.vault.backup.BackupKind.BEFORE_SAVE, "00"))
        vm.onDisappear(changingConfigurations = false)
        vm.onAppear()
        assertEquals(requests, vm.uiState.value.promptRequest)
    }

    @Test
    fun `after Cancel, showing the lock screen again without a stop doesn't prompt again`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        vm.servePromptRequest { org.onekash.kashpass.vault.storage.Confirmation.Cancelled }
        advanceUntilIdle()
        // The lock screen comes back into composition without the activity stopping.
        vm.onAppear()
        assertEquals(1, vm.uiState.value.promptRequest)
    }

    @Test
    fun `while a picked file is being chosen, the screen shows the check spinner`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.showPasswordField)
        files.gate = CompletableDeferred()
        vm.onPicked(Uri.parse("content://drive/document/doc2"))
        runCurrent()
        assertTrue(vm.uiState.value.checking)
        assertFalse(vm.uiState.value.showPasswordField)
        files.gate!!.complete(Unit)
        advanceUntilIdle()
        assertFalse(vm.uiState.value.checking)
        assertEquals("picked.kdbx", vm.uiState.value.vaultName)
    }

    @Test
    fun `a refused pick puts back the remembered file's screen with the message`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        files.failChoose = true
        vm.onPicked(Uri.parse("content://drive/document/doc2"))
        advanceUntilIdle()
        assertEquals(LockMessage.ChooseFailed, vm.uiState.value.message)
        assertEquals("Passwords.kdbx", vm.uiState.value.vaultName)
        assertTrue(vm.uiState.value.showPasswordField)
        assertFalse(vm.uiState.value.checking)
    }

    @Test
    fun `while a picked file is being chosen, fingerprint unlock of the old file is off and not prompted`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = LockViewModel(files, opener, sessions, biometric)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.biometricOn)
        val prompts = vm.uiState.value.promptRequest
        files.gate = CompletableDeferred()
        vm.onPicked(Uri.parse("content://drive/document/doc2"))
        runCurrent()
        vm.onAppear()
        runCurrent()
        assertFalse(vm.uiState.value.biometricOn)
        assertTrue(vm.uiState.value.checking)
        assertEquals(prompts, vm.uiState.value.promptRequest)
        files.gate!!.complete(Unit)
        advanceUntilIdle()
    }

    @Test
    fun `a check of the old file that ends during a pick drops its result`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        opener.hold()
        vm.refresh()
        runCurrent()
        files.gate = CompletableDeferred()
        vm.onPicked(Uri.parse("content://drive/document/doc2"))
        opener.release()
        runCurrent()
        assertTrue("the pick's spinner stays", vm.uiState.value.checking)
        assertFalse(vm.uiState.value.showPasswordField)
        files.gate!!.complete(Unit)
        advanceUntilIdle()
        assertEquals("picked.kdbx", vm.uiState.value.vaultName)
        assertTrue(vm.uiState.value.showPasswordField)
    }

    @Test
    fun `a file to use while unlocked becomes the vault after the vault locks`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        sessions.set(unlockedSession())
        advanceUntilIdle()
        vm.useFile(Uri.parse("content://drive/document/copy"))
        advanceUntilIdle()
        assertEquals("nothing changes while unlocked", "Passwords.kdbx", files.vault!!.displayName)
        sessions.lock()
        advanceUntilIdle()
        assertEquals(listOf(Uri.parse("content://drive/document/copy")), files.chosen)
        assertEquals("picked.kdbx", vm.uiState.value.vaultName)
        assertTrue(vm.uiState.value.showPasswordField)
    }

    @Test
    fun `a file to use while locked becomes the vault at once`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        vm.useFile(Uri.parse("content://drive/document/copy"))
        advanceUntilIdle()
        assertEquals("picked.kdbx", vm.uiState.value.vaultName)
    }

    @Test
    fun `a refused grant for the file to use keeps the old file and says why`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        sessions.set(unlockedSession())
        advanceUntilIdle()
        vm.useFile(Uri.parse("content://drive/document/copy"))
        files.failChoose = true
        sessions.lock()
        advanceUntilIdle()
        assertEquals("Passwords.kdbx", vm.uiState.value.vaultName)
        assertEquals(LockMessage.ChooseFailed, vm.uiState.value.message)
    }

    private fun TestScope.unlocked(vm: LockViewModel) {
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertNotNull(sessions.current.value)
    }

    @Test
    fun `a copy requested before a lock opens with its own password after the lock`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        unlocked(vm)
        vm.requestBackup(backup)
        sessions.lock()
        advanceUntilIdle()
        val state = vm.uiState.value
        assertEquals(backup, state.backupTarget)
        assertNull("a copy from the list, not the last copy", state.targetLastCopy)
        assertTrue(state.showPasswordField)
        assertNull(state.slow)
        vm.unlock("older-password".toCharArray())
        advanceUntilIdle()
        assertEquals("openBackup", opener.calls.last())
    }

    @Test
    fun `the copy is offered even when the file itself can't be opened`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        unlocked(vm)
        opener.checkResult = OpenResult.Unreadable(StorageFailure.NOT_FOUND, null)
        vm.requestBackup(backup)
        sessions.lock()
        advanceUntilIdle()
        assertEquals(backup, vm.uiState.value.backupTarget)
        assertTrue(vm.uiState.value.showPasswordField)
        assertNull(vm.uiState.value.message)
    }

    @Test
    fun `a slow copy shows its warning on arrival, and Unlock anyway accepts those settings`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val slow = org.onekash.kashpass.vault.policy.SlowKdf(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(100_000_000UL), 100, 166)
        val vm = vm()
        advanceUntilIdle()
        unlocked(vm)
        vm.requestBackup(backup, slow)
        sessions.lock()
        advanceUntilIdle()
        assertEquals(slow, vm.uiState.value.slow)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(slow.kdf, opener.acceptedSlow.last())
    }

    @Test
    fun `a later lock with nothing requested shows the file again, and Cancel goes back to it`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = vm()
        advanceUntilIdle()
        unlocked(vm)
        vm.requestBackup(backup)
        sessions.lock()
        advanceUntilIdle()
        vm.cancelBackup()
        advanceUntilIdle()
        assertNull(vm.uiState.value.backupTarget)
        unlocked(vm)
        sessions.lock()
        advanceUntilIdle()
        assertNull(vm.uiState.value.backupTarget)
    }

    private val keyFiles = org.onekash.kashpass.testing.FakeKeyFiles()

    private fun keyVm(withBiometric: Boolean = false) =
        LockViewModel(files, opener, sessions, if (withBiometric) biometric else null, keyFiles)

    private fun keyFileVault() {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        keyFiles.set(LOC)
    }

    @Test
    fun `fingerprint unlock with a key file and no chip requests the file, shows no prompt and keeps the key`() = runTest(dispatcher) {
        fingerprintOn()
        vaultState.saveBiometricNeedsKeyFile(LOC, true)
        val vm = keyVm(withBiometric = true)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.biometricOn)
        var prompts = 0
        vm.unlockWithBiometric { prompts++; org.onekash.kashpass.vault.storage.Confirmation.Confirmed }
        advanceUntilIdle()
        assertEquals(0, prompts)
        assertTrue(opener.calls.none { it == "openWithKey" })
        assertTrue(vm.uiState.value.keyFileNeeded)
        assertTrue("the password field and Add key file show", vm.uiState.value.passwordChosen)
        assertTrue(vm.uiState.value.biometricOn)
        assertNull(vm.uiState.value.turnedOff)
        assertEquals(org.onekash.kashpass.vault.storage.StoredKeyState.STORED, keys.state(LOC))
        vm.onKeyFilePicked(Uri.parse("content://drive/document/key.keyx"))
        advanceUntilIdle()
        assertFalse(vm.uiState.value.keyFileNeeded)
        assertFalse("the fingerprint button returns with the key file", vm.uiState.value.passwordChosen)
        vm.unlockWithBiometric(confirmed)
        advanceUntilIdle()
        assertEquals(org.onekash.kashpass.vault.doc.UnlockOrigin.STORED_KEY_AND_KEY_FILE, sessions.current.value!!.session.opened.origin)
        assertTrue(keyFiles.keyFileUnlock(LOC))
    }

    @Test
    fun `the remembered key file's name shows with the password field`() = runTest(dispatcher) {
        keyFileVault()
        val vm = keyVm()
        advanceUntilIdle()
        assertEquals(org.onekash.kashpass.testing.FakeKeyFiles.NAME, vm.uiState.value.keyFileName)
    }

    @Test
    fun `picking a key file shows its name, cancelling changes nothing, removing clears it`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        val vm = keyVm()
        advanceUntilIdle()
        vm.startKeyFilePick()
        vm.onKeyFilePicked(null)
        advanceUntilIdle()
        assertNull(vm.uiState.value.keyFileName)
        vm.startKeyFilePick()
        vm.onKeyFilePicked(Uri.parse("content://drive/document/key.keyx"))
        advanceUntilIdle()
        assertEquals("key.keyx", vm.uiState.value.keyFileName)
        assertEquals("key.keyx", keyFiles.current(LOC)?.displayName)
        vm.removeKeyFile()
        advanceUntilIdle()
        assertNull(vm.uiState.value.keyFileName)
        assertNull(keyFiles.current(LOC))
    }

    @Test
    fun `a KeePass vault picked as the key file is refused with its message`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        keyFiles.choice = org.onekash.kashpass.platform.KeyFileChoice.KeePassVault
        val vm = keyVm()
        advanceUntilIdle()
        vm.onKeyFilePicked(Uri.parse(LOC))
        advanceUntilIdle()
        assertNull(vm.uiState.value.keyFileName)
        assertEquals(LockMessage.NotKeyFile, vm.uiState.value.message)
        assertTrue(vm.uiState.value.showPasswordField)
    }

    @Test
    fun `a key file whose grant is refused shows ChooseFailed`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        keyFiles.choice = org.onekash.kashpass.platform.KeyFileChoice.Failed
        val vm = keyVm()
        advanceUntilIdle()
        vm.onKeyFilePicked(Uri.parse("content://drive/document/key.keyx"))
        advanceUntilIdle()
        assertNull(vm.uiState.value.keyFileName)
        assertEquals(LockMessage.ChooseFailed, vm.uiState.value.message)
    }

    @Test
    fun `the password and the key file, read fresh for each attempt, unlock together`() = runTest(dispatcher) {
        keyFileVault()
        val vm = keyVm()
        advanceUntilIdle()
        vm.unlock("wrong".toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.WrongPassword, vm.uiState.value.message)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(2, keyFiles.reads)
        assertEquals(org.onekash.kashpass.vault.doc.UnlockOrigin.PASSWORD_AND_KEY_FILE, sessions.current.value!!.session.opened.origin)
        assertTrue("key-file bytes are zero-filled", keyFiles.returned.all { bytes -> bytes.all { it == 0.toByte() } })
    }

    @Test
    fun `an empty password with a key file opens a key-file-only vault`() = runTest(dispatcher) {
        keyFileVault()
        val vm = keyVm()
        advanceUntilIdle()
        vm.unlock(CharArray(0))
        advanceUntilIdle()
        assertEquals(org.onekash.kashpass.vault.doc.UnlockOrigin.KEY_FILE_ONLY, sessions.current.value!!.session.opened.origin)
        assertTrue(keyFiles.keyFileUnlock(LOC))
    }

    @Test
    fun `a key file that can't be read stops the unlock with its message and keeps the field`() = runTest(dispatcher) {
        keyFileVault()
        val cases = StorageFailure.entries.map { org.onekash.kashpass.vault.storage.KeyFileRead.Failed(it) to LockMessage.KeyFileUnreadable(it) } +
            (org.onekash.kashpass.vault.storage.KeyFileRead.KeePassVault to LockMessage.NotKeyFile)
        val vm = keyVm()
        advanceUntilIdle()
        for ((read, message) in cases) {
            keyFiles.failure = read
            val password = TestVaults.PASSWORD.toCharArray()
            vm.unlock(password)
            advanceUntilIdle()
            assertEquals(message, vm.uiState.value.message)
            assertTrue(vm.uiState.value.showPasswordField)
            assertFalse(vm.uiState.value.unlocking)
            assertTrue("the password is wiped", password.all { it == '\u0000' })
        }
        assertEquals(0, opener.opens)
        assertNull(sessions.current.value)
    }

    @Test
    fun `a damaged key file has its own message`() = runTest(dispatcher) {
        keyFileVault()
        opener.openResult = { OpenResult.KeyFileDamaged }
        val vm = keyVm()
        advanceUntilIdle()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.KeyFileDamaged, vm.uiState.value.message)
        assertTrue(vm.uiState.value.showPasswordField)
    }

    @Test
    fun `a key file too large to read has its own message and keeps the password field`() = runTest(dispatcher) {
        keyFileVault()
        opener.openResult = { OpenResult.KeyFileTooLarge }
        val vm = keyVm()
        advanceUntilIdle()
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.KeyFileTooLarge, vm.uiState.value.message)
        assertTrue(vm.uiState.value.showPasswordField)
        assertTrue(vm.uiState.value.message!!.isKeyFileProblem)
        assertNull("the vault file is not the problem", vm.uiState.value.lastCopy)
    }

    @Test
    fun `a backup opened from the lock screen uses the key file too`() = runTest(dispatcher) {
        keyFileVault()
        val vm = keyVm()
        advanceUntilIdle()
        vm.openBackup(backup)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(1, keyFiles.reads)
        assertEquals(listOf("openBackup"), opener.calls)
        assertNotNull(sessions.current.value!!.backup)
        assertFalse("a backup records nothing", keyFiles.keyFileUnlock(LOC))
    }

    @Test
    fun `a key file that can't be read shows its message on a backup target`() = runTest(dispatcher) {
        keyFileVault()
        keyFiles.failure = org.onekash.kashpass.vault.storage.KeyFileRead.Failed(StorageFailure.NOT_FOUND)
        val vm = keyVm()
        advanceUntilIdle()
        vm.openBackup(backup)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(LockMessage.KeyFileUnreadable(StorageFailure.NOT_FOUND), vm.uiState.value.message)
        assertEquals(backup, vm.uiState.value.backupTarget)
    }

    @Test
    fun `fingerprint unlock with an unreadable key file says so and shows the password field`() = runTest(dispatcher) {
        fingerprintOn()
        keyFiles.set(LOC)
        keyFiles.failure = org.onekash.kashpass.vault.storage.KeyFileRead.Failed(StorageFailure.PERMISSION_REVOKED)
        val vm = keyVm(withBiometric = true)
        advanceUntilIdle()
        vm.unlockWithBiometric(confirmed)
        advanceUntilIdle()
        assertEquals(LockMessage.KeyFileUnreadable(StorageFailure.PERMISSION_REVOKED), vm.uiState.value.message)
        assertTrue(vm.uiState.value.passwordChosen)
        assertTrue(vm.uiState.value.showPasswordField)
        assertEquals(org.onekash.kashpass.vault.storage.StoredKeyState.STORED, keys.state(LOC))
    }

    @Test
    fun `fingerprint unlock whose key file doesn't match keeps the stored key and says so`() = runTest(dispatcher) {
        fingerprintOn()
        keyFiles.set(LOC)
        opener.keyResult = { OpenResult.WrongPassword }
        val vm = keyVm(withBiometric = true)
        advanceUntilIdle()
        vm.unlockWithBiometric(confirmed)
        advanceUntilIdle()
        assertEquals(LockMessage.KeyFileMismatch, vm.uiState.value.message)
        assertNull(vm.uiState.value.turnedOff)
        assertTrue(vm.uiState.value.passwordChosen)
        assertEquals(org.onekash.kashpass.vault.storage.StoredKeyState.STORED, keys.state(LOC))
    }

    @Test
    fun `while the key file picker is open no prompt is requested`() = runTest(dispatcher) {
        fingerprintOn()
        val vm = keyVm(withBiometric = true)
        advanceUntilIdle()
        val before = vm.uiState.value.promptRequest
        vm.startKeyFilePick()
        // The picker covers the activity: it stops, then starts again when the picker returns.
        vm.onDisappear(changingConfigurations = false)
        vm.onAppear()
        advanceUntilIdle()
        assertEquals(before, vm.uiState.value.promptRequest)
        vm.onKeyFilePicked(null)
        vm.onDisappear(changingConfigurations = false)
        vm.onAppear()
        assertEquals(before + 1, vm.uiState.value.promptRequest)
    }

    @Test
    fun `a wrong password after the chip is removed from a vault last unlocked with a key file requests it`() = runTest(dispatcher) {
        keyFileVault()
        val vm = keyVm()
        advanceUntilIdle()
        assertFalse(vm.uiState.value.keyFileUnlockedBefore)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(org.onekash.kashpass.vault.doc.UnlockOrigin.PASSWORD_AND_KEY_FILE, sessions.current.value!!.session.opened.origin)
        assertTrue(keyFiles.keyFileUnlock(LOC))
        sessions.lock()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.keyFileUnlockedBefore)
        vm.removeKeyFile()
        advanceUntilIdle()
        // The vault needs its key file, so the password alone is wrong.
        opener.openResult = { OpenResult.WrongPassword }
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertNull(vm.uiState.value.keyFileName)
        assertEquals(LockMessage.WrongPassword, vm.uiState.value.message)
        assertTrue(vm.uiState.value.keyFileUnlockedBefore)
    }

    @Test
    fun `an unlock without a key file clears the mark`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        keyFiles.saveKeyFileUnlock(LOC, true)
        val vm = keyVm()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.keyFileUnlockedBefore)
        vm.unlock(TestVaults.PASSWORD.toCharArray())
        advanceUntilIdle()
        assertEquals(org.onekash.kashpass.vault.doc.UnlockOrigin.PASSWORD, sessions.current.value!!.session.opened.origin)
        assertFalse(keyFiles.keyFileUnlock(LOC))
        sessions.lock()
        advanceUntilIdle()
        assertFalse(vm.uiState.value.keyFileUnlockedBefore)
    }

    @Test
    fun `a session-only file never shows the mark of the remembered vault`() = runTest(dispatcher) {
        files.vault = RememberedVault(LOC, "Passwords.kdbx")
        keyFiles.saveKeyFileUnlock(LOC, true)
        val vm = keyVm()
        advanceUntilIdle()
        vm.onIncoming(Uri.parse(OTHER), writableGrant = false)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.openedFromApp)
        assertFalse(vm.uiState.value.keyFileUnlockedBefore)
    }

    @Test
    fun `a fingerprint unlock without a key file clears the mark`() = runTest(dispatcher) {
        fingerprintOn()
        keyFiles.saveKeyFileUnlock(LOC, true)
        val vm = keyVm(withBiometric = true)
        advanceUntilIdle()
        vm.unlockWithBiometric(confirmed)
        advanceUntilIdle()
        assertEquals(org.onekash.kashpass.vault.doc.UnlockOrigin.STORED_KEY, sessions.current.value!!.session.opened.origin)
        assertFalse(keyFiles.keyFileUnlock(LOC))
    }
}
