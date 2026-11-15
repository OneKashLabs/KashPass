package org.onekash.kashpass.ui.settings

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.session.BiometricStatus
import org.onekash.kashpass.session.BiometricUnlock
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.testing.FakeUnlockKeyStore
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.CompletableDeferred

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class SettingsViewModelTest {

    private val dispatcher = StandardTestDispatcher()
    private val sessions = SessionHolder()
    private val keys = FakeUnlockKeyStore()
    private val opener = FakeVaultOpener(dispatcher)
    private val biometric = BiometricUnlock(keys, opener, FakeVaultStateStore(), sessions)

    @Before
    fun setUp() = Dispatchers.setMain(dispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    @Test
    fun `opens with the vault's details, toggles fingerprint unlock, reports a failed turn-on and closes on lock`() = runTest(dispatcher) {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        val vm = SettingsViewModel(sessions, biometric, fileName = { "Passwords.kdbx" })
        vm.open()
        advanceUntilIdle()
        val state = vm.state.value!!
        assertEquals("Passwords.kdbx", state.fileName)
        assertTrue("the file itself is open", state.isFile)
        assertEquals(BiometricStatus.Off, state.biometric)
        keys.failSeal = true
        vm.setBiometric(true) { Confirmation.Confirmed }
        advanceUntilIdle()
        assertEquals(BiometricStatus.Off, vm.state.value!!.biometric)
        assertEquals(true, vm.state.value!!.biometricFailed)
        keys.failSeal = false
        vm.setBiometric(true) { Confirmation.Confirmed }
        advanceUntilIdle()
        assertEquals(BiometricStatus.On, vm.state.value!!.biometric)
        assertEquals(false, vm.state.value!!.biometricFailed)
        vm.setBiometric(false) { Confirmation.Confirmed }
        advanceUntilIdle()
        assertEquals(BiometricStatus.Off, vm.state.value!!.biometric)
        sessions.lock()
        advanceUntilIdle()
        assertEquals(null, vm.state.value)
    }

    @Test
    fun `a session-only file shows its name, no biometric switch or backups, and can't turn biometric unlock on`() = runTest(dispatcher) {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL), access = FileAccess.SESSION_ONLY)
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, sessionName = "Shared.kdbx"))
        val vm = SettingsViewModel(sessions, biometric, fileName = { "Passwords.kdbx" })
        vm.open()
        val state = vm.state.value!!
        assertEquals("Shared.kdbx", state.fileName)
        assertFalse(state.biometricShown)
        assertFalse(state.backupsShown)
        vm.setBiometric(true) { Confirmation.Confirmed }
        advanceUntilIdle()
        assertEquals(org.onekash.kashpass.vault.storage.StoredKeyState.NONE, keys.state(TestVaults.LOCATION))
    }

    @Test
    fun `a backup opened read-only can't turn biometric unlock on`() = runTest(dispatcher) {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "b", java.time.Instant.EPOCH, 10L, org.onekash.kashpass.vault.backup.BackupKind.BEFORE_SAVE, "00",
        )
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, backup))
        val vm = SettingsViewModel(sessions, biometric, fileName = { "Passwords.kdbx" })
        vm.open()
        advanceUntilIdle()
        assertEquals(false, vm.state.value!!.isFile)
        vm.setBiometric(true) { Confirmation.Confirmed }
        advanceUntilIdle()
        assertEquals(emptyList<Pair<String, String>>(), keys.calls)
    }

    @Test
    fun `applying stays on until the biometric change ends, also across a reopen`() = runTest(dispatcher) {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        val vm = SettingsViewModel(sessions, biometric, fileName = { "Passwords.kdbx" })
        vm.open()
        advanceUntilIdle()
        assertEquals(false, vm.state.value!!.applying)
        val gate = CompletableDeferred<Unit>()
        vm.setBiometric(true) { gate.await(); Confirmation.Confirmed }
        runCurrent()
        assertEquals(true, vm.state.value!!.applying)
        advanceUntilIdle()
        assertEquals(true, vm.state.value!!.applying)
        vm.close()
        vm.open()
        assertEquals("reopening keeps the count", true, vm.state.value!!.applying)
        gate.complete(Unit)
        advanceUntilIdle()
        assertEquals(false, vm.state.value!!.applying)
    }

    @Test
    fun `opening a backup from Settings closes Settings, a save's session swap doesn't`() = runTest(dispatcher) {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        val file = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false).also(sessions::set)
        val vm = SettingsViewModel(sessions, biometric, fileName = { "Passwords.kdbx" })
        vm.open()
        advanceUntilIdle()
        val saved = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        sessions.replace(file, saved.session)
        advanceUntilIdle()
        assertTrue("a save swaps the session; Settings stays", vm.state.value != null)
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "b", java.time.Instant.EPOCH, 10L, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "00",
        )
        val copy = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        sessions.replace(sessions.current.value!!, copy.session, backup = backup)
        advanceUntilIdle()
        assertEquals("the backup shows instead of Settings", null, vm.state.value)
    }

    @Test
    fun `About's rows rise again each time About opens, and not on a rotation in between`() = runTest(dispatcher) {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        val vm = SettingsViewModel(sessions, biometric, fileName = { "Passwords.kdbx" })
        vm.open()
        vm.openAbout()
        assertFalse(vm.aboutRowsPlayed)
        vm.markAboutRowsPlayed()
        assertTrue("a rotation finds them played", vm.aboutRowsPlayed)
        vm.closeAbout()
        vm.openAbout()
        assertFalse(vm.aboutRowsPlayed)
    }

    @Test
    fun `About opens over Settings and closes with Settings, on lock and on reopen`() = runTest(dispatcher) {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        val unlocked = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false)
        sessions.set(unlocked)
        val vm = SettingsViewModel(sessions, biometric, fileName = { "Passwords.kdbx" })
        vm.openAbout()
        assertEquals("About needs Settings open", null, vm.state.value)
        vm.open()
        assertFalse(vm.state.value!!.about)
        vm.openAbout()
        assertTrue(vm.state.value!!.about)
        vm.closeAbout()
        assertFalse(vm.state.value!!.about)
        vm.openAbout()
        vm.close()
        vm.open()
        assertFalse("reopening Settings doesn't bring About back", vm.state.value!!.about)
        vm.openAbout()
        sessions.lock()
        advanceUntilIdle()
        assertEquals(null, vm.state.value)
        sessions.set(unlocked)
        vm.open()
        assertFalse(vm.state.value!!.about)
    }

    @Test
    fun `the biometric switch is hidden for a vault opened with a key file alone`() = runTest(dispatcher) {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL, password = null, keyPart = TestVaults.KEY_FILE_PART)
        val opened = TestVaults.unlock(bytes, password = "", keyFile = TestVaults.KEY_FILE)
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        val vm = SettingsViewModel(sessions, biometric, fileName = { "Passwords.kdbx" })
        vm.open()
        assertFalse(vm.state.value!!.biometricShown)
        sessions.lock()
        val withPassword = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        sessions.set(Unlocked(TestVaults.LOCATION, withPassword.session, withPassword.kdf, false))
        vm.open()
        assertTrue(vm.state.value!!.biometricShown)
    }
}
