package org.onekash.kashpass.ui.edit

import java.time.Instant
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.RefreshResult
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.Writability
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class EditorViewModelTest {

    private val dispatcher = StandardTestDispatcher()
    private val sessions = SessionHolder()
    private val saver = FakeVaultSaver()
    private val opener = FakeVaultOpener()
    private val now = Instant.parse("2026-10-20T12:00:00Z")
    private lateinit var unlocked: Unlocked
    private lateinit var vm: EditorViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
        val opened = runBlocking { TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL)) }
        unlocked = Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false)
        sessions.set(unlocked)
        val coordinator = SaveCoordinator(sessions, saver, opener, CoroutineScope(SupervisorJob() + dispatcher), compute = dispatcher)
        vm = EditorViewModel(sessions, coordinator, { now }, dispatcher)
    }

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun rows() = sessions.current.value!!.session.index.rows(Chip.All, "")

    private fun id(title: String) = rows().first { it.title == title }.id

    @Test
    fun `adding starts with the default user name, a generated password and the chip's group`() = runTest(dispatcher) {
        val email = (sessions.current.value!!.session.index.chips.first { it is Chip.Group && it.label.contains("Email") } as Chip.Group).id
        vm.startAdd(email)
        advanceUntilIdle()
        val state = vm.state.value!!
        assertTrue(state.adding)
        assertEquals(email, state.groupId)
        assertEquals(20, vm.password.text.length)
        assertTrue(vm.password.text.all { it.isLetterOrDigit() })
        assertTrue("the recycle bin is never offered", state.groups.none { it.label == "Recycle Bin" })
        vm.startAdd("no-such-group")
        advanceUntilIdle()
        assertNull(vm.state.value!!.groupId)
    }

    @Test
    fun `generate uses the chosen length and symbols, and the settings reset with the editor`() = runTest(dispatcher) {
        vm.startAdd(null)
        advanceUntilIdle()
        vm.setLength(12)
        vm.setSymbols(true)
        vm.generate()
        assertEquals(12, vm.password.text.length)
        vm.setLength(100)
        assertEquals(64, vm.state.value!!.length)
        vm.close()
        assertEquals("", vm.password.text.toString())
        vm.startAdd(null)
        advanceUntilIdle()
        assertEquals(20, vm.state.value!!.length)
        assertFalse(vm.state.value!!.symbols)
    }

    @Test
    fun `a new entry is saved at once, the editor closes and the session holds it`() = runTest(dispatcher) {
        vm.startAdd(null)
        advanceUntilIdle()
        vm.setTitle("Phone account")
        vm.save()
        advanceUntilIdle()
        assertNull(vm.state.value)
        assertEquals(listOf("save" to TestVaults.LOCATION), saver.calls)
        assertTrue(rows().any { it.title == "Phone account" })
    }

    @Test
    fun `New entry re-reads the file first and opens on the latest version`() = runTest(dispatcher) {
        val notices = mutableListOf<EditorNotice>()
        backgroundScope.launch { vm.messages.collect { notices += it } }
        runCurrent()
        val desktop = runBlocking { TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL)) }
        opener.refreshResult = { RefreshResult.Reloaded(desktop) }
        vm.startAdd("group-gone-in-the-new-version")
        advanceUntilIdle()
        runCurrent()
        assertTrue("refresh" in opener.calls)
        assertEquals(listOf(EditorNotice.UPDATED), notices)
        assertTrue(sessions.current.value!!.session === desktop.session)
        assertNull("a group missing in the latest version falls back to the top level", vm.state.value!!.groupId)
    }

    @Test
    fun `New entry on an unreadable file reports it, and after a timeout Try again checks again`() = runTest(dispatcher) {
        val notices = mutableListOf<EditorNotice>()
        backgroundScope.launch { vm.messages.collect { notices += it } }
        runCurrent()
        opener.refreshResult = { RefreshResult.Failed(OpenResult.Unreadable(StorageFailure.IO_FAILURE)) }
        vm.startAdd(null)
        advanceUntilIdle()
        runCurrent()
        assertEquals(listOf(EditorNotice.CHECK_FAILED), notices)
        assertNull(vm.state.value)
        opener.refreshResult = { RefreshResult.Failed(OpenResult.Unreadable(StorageFailure.TIMED_OUT)) }
        vm.startAdd(null)
        advanceUntilIdle()
        runCurrent()
        assertEquals(EditorNotice.TIMED_OUT, notices.last())
        opener.refreshResult = { RefreshResult.Unchanged }
        vm.retryCheck()
        advanceUntilIdle()
        assertTrue(vm.state.value!!.adding)
    }

    @Test
    fun `a second New entry tap while the check runs is ignored`() = runTest(dispatcher) {
        vm.startAdd(null)
        vm.startAdd(null)
        advanceUntilIdle()
        assertEquals(1, opener.calls.count { it == "refresh" })
        assertTrue(vm.state.value!!.adding)
    }

    @Test
    fun `closing an unchanged editor closes at once`() = runTest(dispatcher) {
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        vm.requestClose()
        assertNull(vm.state.value)
        vm.startAdd(null)
        advanceUntilIdle()
        vm.requestClose()
        assertNull(vm.state.value)
    }

    @Test
    fun `closing after a change offers Discard first and the second close discards`() = runTest(dispatcher) {
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        vm.setNotes("changed")
        vm.requestClose()
        assertTrue(vm.state.value!!.discardConfirm)
        assertEquals("changed", vm.state.value!!.notes)
        vm.requestClose()
        assertNull(vm.state.value)
        assertTrue(saver.calls.isEmpty())
        assertEquals("", vm.password.text.toString())
    }

    @Test
    fun `a password or generated change counts, and undoing the edit by hand does not`() = runTest(dispatcher) {
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        vm.password.edit { append("x") }
        vm.requestClose()
        assertTrue(vm.state.value!!.discardConfirm)
        vm.close()

        vm.startEdit(id("Router"))
        advanceUntilIdle()
        vm.setTitle("Other")
        vm.setTitle("Router")
        vm.requestClose()
        assertNull("the fields match the entry again", vm.state.value)

        vm.startAdd(null)

        advanceUntilIdle()
        vm.generate()
        vm.requestClose()
        assertTrue("a regenerated password is a change", vm.state.value!!.discardConfirm)
    }

    @Test
    fun `close requests are ignored while a save runs, and a refused save keeps the confirm`() = runTest(dispatcher) {
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        vm.setNotes("changed")
        saver.result = { vault, _ -> SaveResult.NotWritable(vault, Writability.NO_WRITE_GRANT) }
        vm.save()
        assertTrue(vm.state.value!!.saving)
        vm.requestClose()
        assertFalse(vm.state.value!!.discardConfirm)
        advanceUntilIdle()
        assertNotNull(vm.state.value!!.problem)
        vm.requestClose()
        assertTrue("the edit is still unsaved", vm.state.value!!.discardConfirm)
    }

    @Test
    fun `the dismiss rule blocks while saving, dismisses clean forms and confirms dirty ones once`() {
        assertEquals(EditorDismiss.BLOCKED, resolveEditorDismiss(saving = true, hasChanges = true, confirmShowing = true))
        assertEquals(EditorDismiss.DISMISS, resolveEditorDismiss(saving = false, hasChanges = false, confirmShowing = false))
        assertEquals(EditorDismiss.SHOW_CONFIRM, resolveEditorDismiss(saving = false, hasChanges = true, confirmShowing = false))
        assertEquals(EditorDismiss.DISMISS, resolveEditorDismiss(saving = false, hasChanges = true, confirmShowing = true))
    }

    @Test
    fun `an edit with nothing changed closes without saving`() = runTest(dispatcher) {
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        assertEquals("Router", vm.state.value!!.title)
        assertEquals("router-pass", vm.password.text.toString())
        vm.save()
        advanceUntilIdle()
        assertNull(vm.state.value)
        assertTrue(saver.calls.isEmpty())
    }

    @Test
    fun `a title edit keeps a protected password holding a character XML can't carry as text`() = runTest(dispatcher) {
        val entry = "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>" +
            "<String><Key>Title</Key><Value>Control</Value></String>" +
            "<String><Key>Password</Key><Value Protected=\"True\">{{p:ab\u0001c}}</Value></String></Entry>"
        val opened = runBlocking { TestVaults.unlock(TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry))) }
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        vm.startEdit(id("Control"))
        advanceUntilIdle()
        assertEquals("ab\u0001c", vm.password.text.toString())
        vm.setTitle("Control 2")
        vm.save()
        advanceUntilIdle()
        val document = sessions.current.value!!.session.opened.document
        val draft = org.onekash.kashpass.vault.edit.EntryEdits.draftOf(document, id("Control 2"))!!
        assertEquals("ab\u0001c", draft.password.reveal())
    }

    @Test
    fun `the editor shows and saves field references as stored`() = runTest(dispatcher) {
        val opened = runBlocking { TestVaults.unlock(TestVaults.referenceVault()) }
        sessions.set(Unlocked(TestVaults.LOCATION, opened.session, opened.kdf, false))
        vm.startEdit(id("Reference Holder"))
        advanceUntilIdle()
        assertEquals("{REF:U@T:Example Bank}", vm.state.value!!.userName)
        assertEquals("{REF:P@I:${TestVaults.refHex(11)}}", vm.password.text.toString())
        vm.setTitle("Reference Holder 2")
        vm.save()
        advanceUntilIdle()
        val document = sessions.current.value!!.session.opened.document
        val draft = org.onekash.kashpass.vault.edit.EntryEdits.draftOf(document, id("Reference Holder 2"))!!
        assertEquals("{REF:U@T:Example Bank}", draft.userName)
        assertEquals("{REF:P@I:${TestVaults.refHex(11)}}", draft.password.reveal())
        assertEquals("https://{REF:U@T:Example Bank}.example", draft.url)
        assertEquals("pw {REF:P@T:Example Bank} and {S:Account}", draft.notes)
    }

    @Test
    fun `a changed edit is saved and reported`() = runTest(dispatcher) {
        val notices = mutableListOf<EditorNotice>()
        backgroundScope.launch { vm.messages.collect { notices += it } }
        runCurrent()
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        vm.setTitle("Home router")
        vm.save()
        advanceUntilIdle()
        runCurrent()
        assertNull(vm.state.value)
        assertEquals(listOf(EditorNotice.SAVED), notices)
        assertTrue(rows().any { it.title == "Home router" })
        assertEquals(1, saver.saved.size)
    }

    @Test
    fun `a file changed elsewhere reloads before editing, or reports the entry gone`() = runTest(dispatcher) {
        val notices = mutableListOf<EditorNotice>()
        backgroundScope.launch { vm.messages.collect { notices += it } }
        runCurrent()
        val router = id("Router")
        // The "desktop" renamed Router; the refresh hands back that version.
        val desktop = runBlocking { TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL)) }
        opener.refreshResult = { RefreshResult.Reloaded(desktop) }
        val desktopRouter = desktop.session.index.rows(Chip.All, "").first { it.title == "Router" }.id
        vm.startEdit(desktopRouter)
        advanceUntilIdle()
        // advanceUntilIdle leaves work that only background coroutines (the collector) have.
        runCurrent()
        assertEquals(listOf(EditorNotice.UPDATED), notices)
        assertNotNull(vm.state.value)
        notices.clear()
        vm.close()
        val again = runBlocking { TestVaults.unlock(TestVaults.browserVault(aesRounds = 1_000UL)) }
        opener.refreshResult = { RefreshResult.Reloaded(again) }
        vm.startEdit(router)
        advanceUntilIdle()
        runCurrent()
        assertEquals(listOf(EditorNotice.ENTRY_GONE), notices)
        assertNull(vm.state.value)
        opener.refreshResult = { RefreshResult.Failed(OpenResult.WrongPassword) }
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        runCurrent()
        assertEquals(EditorNotice.CHECK_FAILED, notices.last())
    }

    @Test
    fun `an edit check the file doesn't answer in time says so, and Try again checks again`() = runTest(dispatcher) {
        val notices = mutableListOf<EditorNotice>()
        backgroundScope.launch { vm.messages.collect { notices += it } }
        runCurrent()
        opener.refreshResult = { RefreshResult.Failed(OpenResult.Unreadable(StorageFailure.TIMED_OUT)) }
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        runCurrent()
        assertEquals(listOf(EditorNotice.TIMED_OUT), notices)
        assertNull(vm.state.value)
        opener.refreshResult = { RefreshResult.Unchanged }
        vm.retryCheck()
        advanceUntilIdle()
        assertEquals("Router", vm.state.value!!.title)
    }

    @Test
    fun `a refused save keeps the editor open with the reason`() = runTest(dispatcher) {
        saver.result = { vault, _ -> SaveResult.NotWritable(vault, Writability.NO_WRITE_GRANT) }
        vm.startAdd(null)
        advanceUntilIdle()
        vm.setTitle("Keep me")
        vm.save()
        advanceUntilIdle()
        val state = vm.state.value!!
        assertFalse(state.saving)
        assertEquals(Writability.NO_WRITE_GRANT, (state.problem as SaveResult.NotWritable).reason)
        assertEquals("Keep me", state.title)
    }

    @Test
    fun `a save that throws keeps the editor open with the edits and reports it`() = runTest(dispatcher) {
        saver.result = { _, _ -> throw IllegalStateException("unexpected") }
        vm.startAdd(null)
        advanceUntilIdle()
        vm.setTitle("Keep me")
        vm.save()
        advanceUntilIdle()
        val state = vm.state.value!!
        assertFalse(state.saving)
        assertTrue(state.problem is SaveResult.UnexpectedError)
        assertEquals("Keep me", state.title)
    }

    @Test
    fun `controls report saving while a save runs`() = runTest(dispatcher) {
        saver.hold()
        vm.startAdd(null)
        advanceUntilIdle()
        vm.save()
        runCurrent()
        assertTrue(vm.state.value!!.saving)
        vm.save()
        runCurrent()
        assertEquals("a second save waits for the first", 1, saver.calls.size)
        saver.release()
        advanceUntilIdle()
        assertNull(vm.state.value)
    }

    @Test
    fun `a lock while the edit is being built drops the save without a crash`() = runTest(dispatcher) {
        vm.startAdd(null)
        advanceUntilIdle()
        vm.setTitle("Too late")
        vm.save()
        // The edit is built on the compute dispatcher; the lock lands before it finishes.
        sessions.lock()
        advanceUntilIdle()
        assertNull(vm.state.value)
        assertTrue(saver.calls.isEmpty())
    }

    @Test
    fun `a lock discards the edit and wipes the password field`() = runTest(dispatcher) {
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        vm.setTitle("unsaved")
        sessions.lock()
        advanceUntilIdle()
        assertNull(vm.state.value)
        assertEquals("", vm.password.text.toString())
        assertTrue(saver.calls.isEmpty())
    }

    @Test
    fun `groups for a new entry come from the document`() = runTest(dispatcher) {
        vm.startAdd(null)
        advanceUntilIdle()
        assertEquals(EntryEdits.groups(sessions.current.value!!.session.opened.document), vm.state.value!!.groups)
        assertEquals(true, vm.state.first()!!.adding)
    }


    @Test
    fun `an edit check on a file whose unlock settings became much slower says so`() = runTest(dispatcher) {
        val notices = mutableListOf<EditorNotice>()
        backgroundScope.launch { vm.messages.collect { notices += it } }
        runCurrent()
        opener.refreshResult = { RefreshResult.Failed(OpenResult.TooSlow(org.onekash.kashpass.vault.policy.SlowKdf(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(100_000_000UL), 100, 166))) }
        vm.startEdit(id("Router"))
        advanceUntilIdle()
        runCurrent()
        assertEquals(listOf(EditorNotice.SLOW), notices)
        assertNull(vm.state.value)
    }
}
