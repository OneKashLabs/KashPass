package org.onekash.kashpass.ui.browse

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.onekash.kashpass.vault.index.FieldValue
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.FieldKind
import org.onekash.kashpass.vault.index.MatchSource
import org.onekash.kashpass.vault.index.SearchMatch
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.FakeUnlockKeyStore
import org.onekash.kashpass.session.BiometricUnlock
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.storage.Confirmation

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class BrowseViewModelTest {

    private val dispatcher = StandardTestDispatcher()
    private val sessions = SessionHolder()
    private val opener = FakeVaultOpener(dispatcher)
    private val copies = mutableListOf<String>()

    @Before
    fun setUp() = Dispatchers.setMain(dispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    private suspend fun unlock(bytes: ByteArray = browser) {
        val result = TestVaults.unlock(bytes)
        sessions.set(Unlocked(TestVaults.LOCATION, result.session, result.kdf, result.showWeakWarning))
    }

    // Counts work sent to compute, which the resolution of an opened entry runs on.
    private var computed = 0
    private val compute = object : kotlinx.coroutines.CoroutineDispatcher() {
        override fun dispatch(context: kotlin.coroutines.CoroutineContext, block: Runnable) {
            computed++
            dispatcher.dispatch(context, block)
        }
    }

    private fun vm() = BrowseViewModel(sessions, opener, compute = compute) { text -> copies += text; true }

    // Lets the view model's flow collection run before reading its state.
    private fun BrowseViewModel.current(): BrowseUiState? {
        dispatcher.scheduler.advanceUntilIdle()
        return uiState.value
    }

    private fun BrowseViewModel.state() = checkNotNull(current()) { "locked" }

    private fun BrowseViewModel.titles() = state().rows.map { it.title }

    @Test
    fun `the browser lists entries outside the bin A to Z, untitled last, under All`() = runTest(dispatcher) {
        unlock()
        val state = vm().state()
        assertEquals(listOf("Example Bank", "Example Mail", "Router", "Work Mail", null), state.rows.map { it.title })
        assertEquals(Chip.All, state.selectedChip)
        assertFalse(state.vaultEmpty)
        val router = state.rows.single { it.title == "Router" }
        assertNull(router.groupName)
    }

    @Test
    fun `chips are All, the groups with entries, then the recycle bin, and they filter`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        val labels = vm.state().chips.map { (it as? Chip.Group)?.label ?: it.toString() }
        assertEquals(listOf("All", "Banking", "Root / Email", "Work / Email", "RecycleBin"), labels)

        vm.selectChip(vm.state().chips.first { it is Chip.Group && it.label == "Work / Email" })
        assertEquals(listOf("Work Mail"), vm.titles())
        vm.selectChip(Chip.RecycleBin)
        assertEquals(listOf("Old Bank"), vm.titles())
        assertTrue(vm.state().rows.single().inRecycleBin)
        vm.selectChip(Chip.All)
        assertEquals(5, vm.state().rows.size)
    }

    @Test
    fun `a query filters by non-secret text and clearing it returns to the selected chip`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        vm.selectChip(vm.state().chips.first { it is Chip.Group && it.label == "Banking" })
        assertFalse(vm.state().searching)
        vm.setQuery("   ")
        assertFalse(vm.state().searching)
        vm.setQuery("a-1234")
        assertTrue(vm.state().searching)
        assertEquals(listOf("Example Mail"), vm.titles())
        vm.setQuery("mail-pass")
        assertEquals(emptyList<String?>(), vm.titles())
        assertEquals("mail-pass", vm.state().query)
        vm.setQuery("old bank")
        assertEquals(emptyList<String?>(), vm.titles())
        vm.setQuery("")
        assertEquals(listOf("Example Bank", null), vm.titles())
    }

    @Test
    fun `letter headers show under All only, and rows name their group under All and in search results`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        assertTrue(vm.state().letterHeaders)
        assertTrue(vm.state().groupInRows)
        vm.selectChip(vm.state().chips.first { it is Chip.Group && it.label == "Banking" })
        assertFalse(vm.state().letterHeaders)
        assertFalse(vm.state().groupInRows)
        vm.selectChip(Chip.RecycleBin)
        assertFalse(vm.state().groupInRows)
        vm.setQuery("mail")
        assertFalse(vm.state().letterHeaders)
        assertTrue(vm.state().groupInRows)
    }

    @Test
    fun `while searching each shown row has its match, and outside search there are none`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        assertEquals(emptyMap<String, SearchMatch>(), vm.state().matches)
        vm.setQuery("mail.example")
        val mail = vm.state().rows.single()
        assertEquals(MatchSource.URL, vm.state().matches[mail.id]?.source)
        vm.setQuery("a-1234")
        assertEquals(MatchSource.CUSTOM_VALUE, vm.state().matches.values.single().source)
        vm.setQuery("mail")
        assertEquals(vm.state().rows.map { it.id }.toSet(), vm.state().matches.keys)
        vm.setQuery("")
        assertEquals(emptyMap<String, SearchMatch>(), vm.state().matches)
    }

    @Test
    fun `openSingleResult opens the only search result and nothing else`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        vm.setQuery("a-1234")
        vm.openSingleResult()
        assertEquals("Example Mail", vm.state().openEntry?.title)
        vm.closeEntry()
        vm.setQuery("mail")
        vm.openSingleResult()
        assertNull(vm.state().openEntry)
        vm.setQuery("no-such-thing")
        vm.openSingleResult()
        assertNull(vm.state().openEntry)
        // A chip holding one entry is not a search result.
        vm.setQuery("")
        vm.selectChip(vm.state().chips.first { it is Chip.Group && it.label == "Work / Email" })
        vm.openSingleResult()
        assertNull(vm.state().openEntry)
    }

    @Test
    fun `search focus is requested once per unlocked session`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        assertTrue(vm.state().searchFocusPending)
        vm.consumeSearchFocus()
        assertFalse(vm.state().searchFocusPending)
        vm.setQuery("x")
        assertFalse(vm.state().searchFocusPending)
        // A second view model for the same session (the activity was destroyed and recreated while
        // unlocked) doesn't request focus again.
        assertFalse(vm().state().searchFocusPending)
        sessions.lock()
        unlock()
        assertTrue(vm.state().searchFocusPending)
    }

    @Test
    fun `match reasons are not rebuilt for changes that keep the query and chip`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        vm.setQuery("mail")
        val before = vm.state().matches
        vm.openEntry(vm.state().rows.first().id)
        vm.toggleReveal("Password")
        assertSame(before, vm.state().matches)
        vm.setQuery("mail.")
        assertNotSame(before, vm.state().matches)
    }

    @Test
    fun `a vault with no entries outside the bin reports empty`() = runTest(dispatcher) {
        unlock(empty)
        assertTrue(vm().state().vaultEmpty)
    }

    @Test
    fun `opening an entry shows its details, reveal toggles per field and resets on close`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        val mail = vm.state().rows.single { it.title == "Example Mail" }
        vm.openEntry(mail.id)
        val details = checkNotNull(vm.state().openEntry)
        assertEquals(
            listOf(FieldKind.USER_NAME, FieldKind.PASSWORD, FieldKind.URL, FieldKind.CUSTOM, FieldKind.CUSTOM, FieldKind.NOTES),
            details.fields.map { it.kind },
        )
        assertEquals(emptySet<String>(), vm.state().revealed)
        vm.toggleReveal("Password")
        assertEquals(setOf("Password"), vm.state().revealed)
        vm.toggleReveal("otp")
        vm.toggleReveal("Password")
        assertEquals(setOf("otp"), vm.state().revealed)

        vm.closeEntry()
        assertNull(vm.state().openEntry)
        assertEquals(emptySet<String>(), vm.state().revealed)
    }

    @Test
    fun `opening another entry hides what the previous one revealed`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        vm.openEntry(vm.state().rows.single { it.title == "Example Mail" }.id)
        vm.toggleReveal("Password")
        vm.openEntry(vm.state().rows.single { it.title == "Example Bank" }.id)
        assertEquals("Example Bank", vm.state().openEntry?.title)
        assertEquals(emptySet<String>(), vm.state().revealed)
    }

    @Test
    fun `copy hands the field value to the clipboard`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        vm.openEntry(vm.state().rows.single { it.title == "Example Mail" }.id)
        val fields = vm.state().openEntry!!.fields
        assertEquals(CopyOutcome.COPIED, vm.copy(fields.single { it.name == "Password" }))
        assertEquals(CopyOutcome.COPIED, vm.copy(fields.single { it.name == "otp" }))
        assertEquals(listOf("mail-pass", "otpauth://totp/mail?secret=JBSWY3DPEHPK3PXP"), copies)
    }

    private suspend fun openHolder(): Pair<BrowseViewModel, List<org.onekash.kashpass.vault.index.EntryField>> {
        unlock(TestVaults.referenceVault())
        val vm = vm()
        vm.openEntry(vm.state().rows.single { it.title == "Reference Holder" }.id)
        return vm to vm.state().openEntry!!.fields
    }

    private fun List<org.onekash.kashpass.vault.index.EntryField>.named(name: String) = single { it.name == name }

    @Test
    fun `the open entry's fields are shown resolved, a value inserting a password masked`() = runTest(dispatcher) {
        val (vm, _) = openHolder()
        val shown = vm.state().shownFields!!
        assertEquals("bob", shown.getValue("UserName").value.reveal())
        assertTrue(shown.getValue("UserName").value is FieldValue.Plain)
        assertEquals("https://bob.example", shown.getValue("URL").value.reveal())
        assertTrue(shown.getValue("Password").value is FieldValue.Protected)
        assertTrue(shown.getValue("Notes").insertsPassword)
        assertTrue(shown.getValue("Notes").value is FieldValue.Protected)
        assertTrue(shown.getValue("Notes").keepsPlaceholders)
        // {S:Missing} names no field of the entry, so it stays as written.
        assertFalse(shown.getValue("Hint").keepsPlaceholders)
        // The list row and search keep the stored text.
        assertEquals("{REF:U@T:Example Bank}", vm.state().rows.single { it.title == "Reference Holder" }.userName)
    }

    @Test
    fun `a referenced user name copies the resolved text at once`() = runTest(dispatcher) {
        val (vm, fields) = openHolder()
        assertEquals(CopyOutcome.COPIED, vm.copy(fields.named("UserName")))
        assertEquals(listOf("bob"), copies)
        assertNull(vm.state().copyConfirm)
    }

    @Test
    fun `a value inserting another entry's password copies only after a confirm`() = runTest(dispatcher) {
        val (vm, fields) = openHolder()
        assertEquals(CopyOutcome.CONFIRM, vm.copy(fields.named("Password")))
        assertEquals(emptyList<String>(), copies)
        assertEquals("Password", vm.state().copyConfirm)
        assertTrue(vm.confirmCopy(fields.named("Password")))
        assertEquals(listOf("bank-pass"), copies)
        assertNull(vm.state().copyConfirm)
    }

    @Test
    fun `cancel, closing, another entry and a lock drop the confirm without copying`() = runTest(dispatcher) {
        val (vm, fields) = openHolder()
        vm.copy(fields.named("Password"))
        vm.cancelCopy()
        assertNull(vm.state().copyConfirm)
        vm.copy(fields.named("Password"))
        vm.closeEntry()
        assertNull(vm.state().copyConfirm)
        vm.openEntry(vm.state().rows.single { it.title == "Reference Holder" }.id)
        vm.copy(fields.named("Password"))
        vm.openEntry(vm.state().rows.single { it.title == "Example Bank" }.id)
        assertNull(vm.state().copyConfirm)
        vm.openEntry(vm.state().rows.single { it.title == "Reference Holder" }.id)
        vm.copy(fields.named("Password"))
        sessions.lock()
        assertNull(vm.current())
        assertFalse(vm.confirmCopy(fields.named("Password")))
        assertEquals(emptyList<String>(), copies)
    }

    @Test
    fun `before the open entry is resolved nothing shows and copy copies nothing`() = runTest(dispatcher) {
        unlock(TestVaults.referenceVault())
        val vm = vm()
        val id = vm.state().rows.single { it.title == "Reference Holder" }.id
        val fields = sessions.current.value!!.session.index.details(id)!!.fields
        vm.openEntry(id)
        assertEquals(CopyOutcome.FAILED, vm.copy(fields.named("UserName")))
        assertEquals(emptyList<String>(), copies)
        assertNotNull(vm.state().shownFields)
    }

    @Test
    fun `an entry is resolved once, not again on reveal`() = runTest(dispatcher) {
        val (vm, _) = openHolder()
        val after = computed
        vm.toggleReveal("Password")
        vm.state()
        vm.toggleReveal("Password")
        vm.state()
        assertEquals(after, computed)
    }

    @Test
    fun `weak settings show the banner until dismissed, and the dismissal is stored`() = runTest(dispatcher) {
        unlock(weak)
        val vm = vm()
        assertEquals(KdfSettings.AesKdf(6_000UL), vm.state().weakKdf)
        vm.dismissWeakWarning()
        assertNull(vm.state().weakKdf)
        assertEquals(listOf(TestVaults.LOCATION to KdfSettings.AesKdf(6_000UL)), opener.dismissed)
    }

    @Test
    fun `dismissing the weak-settings banner of a session-only file never calls the opener`() = runTest(dispatcher) {
        val result = TestVaults.unlock(weak, access = org.onekash.kashpass.vault.doc.FileAccess.SESSION_ONLY)
        sessions.set(Unlocked(TestVaults.LOCATION, result.session, result.kdf, result.showWeakWarning))
        val vm = vm()
        assertEquals(KdfSettings.AesKdf(6_000UL), vm.state().weakKdf)
        vm.dismissWeakWarning()
        advanceUntilIdle()
        assertNull(vm.state().weakKdf)
        assertTrue(opener.dismissed.isEmpty())
        assertTrue(opener.calls.isEmpty())
    }

    @Test
    fun `Use this version on a session-only file never calls the opener`() = runTest(dispatcher) {
        val opened = TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL), access = org.onekash.kashpass.vault.doc.FileAccess.SESSION_ONLY)
        val opener = FakeVaultOpener()
        val coordinator = SaveCoordinator(sessions, FakeVaultSaver(), opener, backgroundScope)
        val fileNewest = java.time.Instant.parse("2026-01-01T00:00:00Z")
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, olderThan = java.time.Instant.parse("2026-06-01T00:00:00Z"), fileNewest = fileNewest))
        assertTrue(sessions.current.value!!.sessionOnly)
        val vm = BrowseViewModel(sessions, opener, coordinator) { true }
        advanceUntilIdle()
        vm.acceptOlderFile()
        advanceUntilIdle()
        assertTrue(opener.accepted.isEmpty())
        assertTrue(opener.calls.isEmpty())
    }

    @Test
    fun `data after the end of the file shows a row until dismissed, only while the vault can be saved`() = runTest(dispatcher) {
        val result = TestVaults.unlock(browser)
        sessions.set(Unlocked(TestVaults.LOCATION, result.session, result.kdf, false, bytesAfterEnd = true))
        val vm = vm()
        assertTrue(vm.state().bytesAfterEnd)
        vm.dismissBytesAfterEnd()
        assertFalse(vm.state().bytesAfterEnd)
        val readOnly = TestVaults.unlock(browser, access = org.onekash.kashpass.vault.doc.FileAccess.SESSION_ONLY)
        sessions.set(Unlocked(TestVaults.LOCATION, readOnly.session, readOnly.kdf, false, bytesAfterEnd = true))
        assertFalse(vm.state().bytesAfterEnd)
        unlock()
        assertFalse(vm.state().bytesAfterEnd)
    }

    @Test
    fun `settings KeePass 2 accepts show no banner`() = runTest(dispatcher) {
        unlock()
        assertNull(vm().state().weakKdf)
    }

    @Test
    fun `lock drops the state, and the next unlock starts from All with no query`() = runTest(dispatcher) {
        unlock()
        val vm = vm()
        vm.setQuery("mail")
        vm.selectChip(Chip.RecycleBin)
        vm.openEntry(vm.state().rows.first().id)
        sessions.lock()
        assertNull(vm.current())
        assertNull(sessions.current.value)

        unlock()
        val state = vm.state()
        assertEquals("", state.query)
        assertEquals(Chip.All, state.selectedChip)
        assertNull(state.openEntry)
        assertEquals(5, state.rows.size)
    }

    private companion object {
        // Encoding runs the KDF, so each vault is generated once per test JVM.
        val browser: ByteArray by lazy { TestVaults.browserVault() }
        val weak: ByteArray by lazy { TestVaults.browserVault(aesRounds = 6_000UL) }
        val empty: ByteArray by lazy { TestVaults.bytes(entries = emptyList()) }
    }

    @Test
    fun `an older file shows its banner until Use this version`() = runTest(dispatcher) {
        val opened = TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL))
        val seen = java.time.Instant.parse("2026-06-01T00:00:00Z")
        val opener = org.onekash.kashpass.vault.testing.FakeVaultOpener()
        val coordinator = org.onekash.kashpass.session.SaveCoordinator(sessions, org.onekash.kashpass.vault.testing.FakeVaultSaver(), opener, backgroundScope)
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false, olderThan = seen, fileNewest = java.time.Instant.parse("2026-01-01T00:00:00Z")))
        val vm = BrowseViewModel(sessions, opener, coordinator) { true }
        advanceUntilIdle()
        assertEquals(seen, vm.uiState.value!!.olderThan)
        assertTrue("editing still works", vm.uiState.value!!.canEdit)
        vm.acceptOlderFile()
        advanceUntilIdle()
        assertNull(vm.uiState.value!!.olderThan)
    }

    @Test
    fun `the fingerprint offer is computed once per unlock, survives a session swap and Not now hides it`() = runTest(dispatcher) {
        val keys = org.onekash.kashpass.vault.testing.FakeUnlockKeyStore()
        val store = org.onekash.kashpass.vault.testing.FakeVaultStateStore()
        val biometric = org.onekash.kashpass.session.BiometricUnlock(keys, opener, store, sessions)
        val opened = TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL))
        val first = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false)
        sessions.set(first)
        val vm = BrowseViewModel(sessions, opener, biometric = biometric) { true }
        advanceUntilIdle()
        assertTrue(vm.uiState.value!!.biometricOffer)
        vm.offerShown()
        advanceUntilIdle()
        assertTrue("shown, but stays for this unlock", vm.uiState.value!!.biometricOffer)
        assertTrue(store.biometricOfferShown(TestVaults.LOCATION))
        val again = TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL))
        sessions.replace(first, again.session)
        advanceUntilIdle()
        assertTrue("a save's session swap keeps the card", vm.uiState.value!!.biometricOffer)
        vm.dismissOffer()
        advanceUntilIdle()
        assertFalse(vm.uiState.value!!.biometricOffer)
        sessions.lock()
        sessions.set(Unlocked(TestVaults.LOCATION, TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL)).session, opened.kdf, false))
        advanceUntilIdle()
        assertFalse("offered once per file", vm.uiState.value!!.biometricOffer)
    }

    @Test
    fun `turning on from the card confirms with the file name, and a failure says so and keeps the card`() = runTest(dispatcher) {
        val keys = org.onekash.kashpass.vault.testing.FakeUnlockKeyStore()
        val biometric = org.onekash.kashpass.session.BiometricUnlock(keys, opener, org.onekash.kashpass.vault.testing.FakeVaultStateStore(), sessions)
        val opened = TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL))
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        val vm = BrowseViewModel(sessions, opener, biometric = biometric) { true }
        advanceUntilIdle()
        val turnedOn = mutableListOf<String>()
        var failed = 0
        backgroundScope.launch { vm.biometricTurnedOn.collect { turnedOn += it } }
        backgroundScope.launch { vm.biometricFailed.collect { failed++ } }
        runCurrent()
        keys.failSeal = true
        vm.enableBiometric({ org.onekash.kashpass.vault.storage.Confirmation.Confirmed }, "Passwords.kdbx")
        advanceUntilIdle()
        // The collectors run in the background scope, which advanceUntilIdle doesn't wait for.
        runCurrent()
        assertEquals(1, failed)
        assertTrue("the card stays", vm.uiState.value!!.biometricOffer)
        vm.enableBiometric({ org.onekash.kashpass.vault.storage.Confirmation.Cancelled }, "Passwords.kdbx")
        advanceUntilIdle()
        runCurrent()
        assertEquals("Cancel is the owner's choice, no message", 1, failed)
        keys.failSeal = false
        vm.enableBiometric({ org.onekash.kashpass.vault.storage.Confirmation.Confirmed }, "Passwords.kdbx")
        advanceUntilIdle()
        runCurrent()
        assertEquals(listOf("Passwords.kdbx"), turnedOn)
        assertFalse(vm.uiState.value!!.biometricOffer)
    }

    @Test
    fun `working follows the save coordinator`() = runTest(dispatcher) {
        unlock()
        val saves = SaveCoordinator(sessions, FakeVaultSaver(), opener, backgroundScope, compute = dispatcher)
        val vm = BrowseViewModel(sessions, opener, saves) { true }
        assertFalse(vm.state().working)
        opener.hold()
        val reload = async { saves.reload() }
        runCurrent()
        assertTrue(vm.state().working)
        assertTrue("edits wait only on saves", vm.state().canEdit)
        opener.release()
        reload.await()
        assertFalse(vm.state().working)
    }

    @Test
    fun `the card shows enabling until turning on ends, whatever the result`() = runTest(dispatcher) {
        val keys = FakeUnlockKeyStore()
        val biometric = BiometricUnlock(keys, opener, FakeVaultStateStore(), sessions)
        unlock()
        val vm = BrowseViewModel(sessions, opener, biometric = biometric) { true }
        for (answer in listOf(Confirmation.Cancelled, Confirmation.Confirmed)) {
            for (failSeal in listOf(true, false)) {
                keys.failSeal = failSeal
                val gate = CompletableDeferred<Unit>()
                vm.enableBiometric({ gate.await(); answer }, "Passwords.kdbx")
                runCurrent()
                assertTrue(vm.state().enabling)
                gate.complete(Unit)
                advanceUntilIdle()
                assertFalse("$answer, failSeal=$failSeal", vm.state().enabling)
            }
        }
    }

    @Test
    fun `a second Turn on while the first runs is ignored`() = runTest(dispatcher) {
        val biometric = BiometricUnlock(FakeUnlockKeyStore(), opener, FakeVaultStateStore(), sessions)
        unlock()
        val vm = BrowseViewModel(sessions, opener, biometric = biometric) { true }
        val gate = CompletableDeferred<Unit>()
        var prompts = 0
        vm.enableBiometric({ prompts++; gate.await(); Confirmation.Confirmed }, "Passwords.kdbx")
        vm.enableBiometric({ prompts++; Confirmation.Cancelled }, "Passwords.kdbx")
        runCurrent()
        assertEquals(1, prompts)
        assertTrue(vm.state().enabling)
        gate.complete(Unit)
        advanceUntilIdle()
        assertFalse(vm.state().enabling)
    }
}
