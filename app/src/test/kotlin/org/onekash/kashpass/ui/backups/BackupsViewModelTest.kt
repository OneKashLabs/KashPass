package org.onekash.kashpass.ui.backups

import java.time.Duration
import java.time.Instant
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.session.BackupSettings
import org.onekash.kashpass.session.SaveBackupResult
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.TestVaults
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadows.ShadowLooper

/**
 * The Backups list over the real opener, saver and fakes of storage: listing, opening while
 * unlocked or locked, and saving a backup weaker than the file's settings as a new file.
 */
@RunWith(RobolectricTestRunner::class)
class BackupsViewModelTest {

    private val loc = TestVaults.LOCATION
    private val storage = FakeVaultStorage()
    private val state = FakeVaultStateStore()
    private val backups = FakeBackupStore()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sessions = SessionHolder()
    private val opener = VaultOpener.create(storage, state, Dispatchers.IO, backups, FakeSaveMarkerStore())
    private val saver = SafeSaver.create(storage, backups, FakeSaveMarkerStore(), state, Dispatchers.IO, scope)
    private val coordinator = SaveCoordinator(sessions, saver, opener, scope, storage, backups)
    private var pending = false
    private val settings = BackupSettings(state, backups, sessions) { pending }
    private lateinit var vm: BackupsViewModel

    @Before
    fun setUp() {
        Dispatchers.setMain(Dispatchers.Unconfined)
        vm = BackupsViewModel(sessions, coordinator, opener, settings)
    }

    // A sheet over a live vault with [n] older copies kept before saves, newest first in the list.
    // The Undo window the sheet passes with each swipe.
    private var window = 60_000L

    private fun sheetWith(n: Int, window: Long = 60_000L): List<BackupInfo> {
        this.window = window
        state.keep = 30
        repeat(n) {
            keep(TestVaults.bytes(aesRounds = 500UL + it.toULong()))
            backups.now = { Instant.now().plus(Duration.ofMinutes(it + 1L)) }
        }
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        vm.show()
        await { vm.state.value?.items?.size == n + 1 }
        return vm.state.value!!.items!!
    }

    private fun stored() = runBlocking { backups.list(loc).map { it.id } }

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun await(condition: () -> Boolean) {
        val until = System.currentTimeMillis() + 10_000
        while (!condition() && System.currentTimeMillis() < until) {
            ShadowLooper.idleMainLooper()
            Thread.sleep(20)
        }
        assertTrue("timed out", condition())
    }

    private fun unlockLive(bytes: ByteArray) = runBlocking {
        storage.put(loc, bytes)
        val opened = opener.open(loc, TestVaults.PASSWORD.toCharArray()) as OpenResult.Unlocked
        sessions.set(Unlocked(loc, opened.session, opened.kdf, false))
    }

    private fun keep(bytes: ByteArray): BackupInfo = runBlocking { (backups.add(loc, bytes, BackupKind.BEFORE_SAVE) as BackupResult.Added).info }

    @Test
    fun `the list shows the open vault's backups newest first`() {
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        keep(TestVaults.bytes(aesRounds = 500UL))
        backups.now = { Instant.now().plus(Duration.ofMinutes(1)) }
        val newer = keep(TestVaults.bytes(aesRounds = 700UL))
        vm.show()
        await { vm.state.value?.items?.size == 3 }
        assertEquals(newer, vm.state.value!!.items!!.first())
    }

    @Test
    fun `a lock closes the list, and nothing opens while locked`() {
        val backup = keep(TestVaults.bytes(aesRounds = 500UL))
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        vm.show()
        await { vm.state.value?.items != null }
        sessions.lock()
        await { vm.state.value == null }
        vm.show()
        vm.select(backup)
        assertNull(vm.state.value)
    }

    private fun save(copy: String) = runBlocking { coordinator.saveBackupAsNewFile(copy) }

    @Test
    fun `a backup weaker than the file opens read-only and saves as a new file, the vault file unchanged`() {
        val current = TestVaults.bytes(aesRounds = 1_000UL)
        val older = TestVaults.bytes(aesRounds = 500UL)
        val backup = keep(older)
        unlockLive(current)
        vm.show()
        vm.select(backup)
        await { vm.state.value == null }
        val opened = sessions.current.value!!
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.BACKUP), opened.session.saveability)
        assertEquals(backup, opened.backup)
        assertEquals("opening the backup leaves the baseline", KdfSettings.AesKdf(1_000UL), state.kdfBaseline(loc))
        val copy = storage.createDocument("Passwords (backup).kdbx")
        assertEquals(SaveBackupResult.Saved("Passwords (backup).kdbx"), save(copy))
        assertTrue(storage.bytes(copy)!!.contentEquals(older))
        assertTrue("the vault file is never written", storage.bytes(loc)!!.contentEquals(current))
        assertEquals(KdfSettings.AesKdf(1_000UL), state.kdfBaseline(loc))
    }

    @Test
    fun `a backup damaged on the device is reported when picked and when saved`() {
        val current = TestVaults.bytes(aesRounds = 1_000UL)
        val older = TestVaults.bytes(aesRounds = 500UL)
        val damaged = keep(TestVaults.bytes(aesRounds = 600UL))
        backups.corrupt(loc, damaged.id)
        unlockLive(current)
        vm.show()
        vm.select(damaged)
        await { vm.state.value?.damaged == true }
        assertNull(sessions.current.value!!.backup)

        val backup = keep(older)
        vm.select(backup)
        await { vm.state.value == null }
        backups.corrupt(loc, backup.id)
        val copy = storage.createDocument("Passwords (backup).kdbx")
        assertEquals(SaveBackupResult.BackupDamaged, save(copy))
        assertEquals("nothing was written", 0, storage.bytes(copy)!!.size)
        assertTrue(storage.bytes(loc)!!.contentEquals(current))
    }

    @Test
    fun `a copy whose write fails is Failed and the vault file is unchanged`() {
        val current = TestVaults.bytes(aesRounds = 1_000UL)
        val backup = keep(TestVaults.bytes(aesRounds = 500UL))
        unlockLive(current)
        vm.show()
        vm.select(backup)
        await { vm.state.value == null }
        val copy = storage.createDocument("Passwords (backup).kdbx")
        storage.failWrites(copy, org.onekash.kashpass.vault.storage.StorageFailure.IO_FAILURE, afterOpen = true)
        assertEquals(SaveBackupResult.Failed(copy), save(copy))
        assertTrue(storage.bytes(loc)!!.contentEquals(current))
    }

    @Test
    fun `a backup opened from the lock screen saves as a new file`() {
        val older = TestVaults.bytes(aesRounds = 500UL)
        val backup = keep(older)
        storage.put(loc, TestVaults.bytes(aesRounds = 1_000UL))
        val opened = runBlocking { opener.openBackup(loc, backup, TestVaults.PASSWORD.toCharArray()) } as OpenResult.Unlocked
        sessions.set(Unlocked(loc, opened.session, opened.kdf, false, backup))
        val copy = storage.createDocument("Passwords (backup).kdbx")
        assertTrue(save(copy) is SaveBackupResult.Saved)
        assertTrue(storage.bytes(copy)!!.contentEquals(older))
    }

    @Test
    fun `nothing is saved with no backup open or after a lock`() {
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        val copy = storage.createDocument("Passwords (backup).kdbx")
        assertNull("the file itself is open", save(copy))
        sessions.lock()
        assertNull(save(copy))
        assertEquals(0, storage.bytes(copy)!!.size)
    }

    @Test
    fun `a backup whose unlock settings are much slower than the file's is refused with a way forward`() {
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        val slow = keep(org.onekash.kashpass.vault.testing.RawKdbx.parse(TestVaults.bytes(aesRounds = 1_000UL))
            .withKdf { it.with("R", org.onekash.kashpass.vault.testing.RawDictionary.UINT64, org.onekash.kashpass.vault.testing.u64(100_000_000UL)) }.toBytes())
        vm.show()
        vm.select(slow)
        await { vm.state.value?.slow == true }
        assertNull(sessions.current.value!!.backup)
    }

    @Test
    fun `the list loads the count to keep, whether a save is unverified, and that the file is open`() {
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        state.keep = 10
        pending = true
        vm.show()
        await { vm.state.value?.items != null }
        val shown = vm.state.value!!
        assertEquals(10, shown.keep)
        assertTrue(shown.pinned)
        assertTrue(shown.isFile)
        assertTrue(shown.canChangeBackups)
    }

    @Test
    fun `lowering the count trims the copies and the list shows the rest`() {
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        repeat(3) { keep(TestVaults.bytes(aesRounds = 500UL + it.toULong())) }
        state.keep = 10
        vm.show()
        await { vm.state.value?.items?.size == 4 }
        vm.setKeep(2, confirmed = 2)
        await { vm.state.value?.items?.size == 2 }
        assertEquals(2, vm.state.value!!.keep)
        assertEquals(2, state.keep)
        assertEquals(false, vm.state.value!!.applying)
    }

    @Test
    fun `a change that would remove more than confirmed is refused and shown again with the new count`() {
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        repeat(3) { keep(TestVaults.bytes(aesRounds = 500UL + it.toULong())) }
        state.keep = 10
        vm.show()
        await { vm.state.value?.items?.size == 4 }
        vm.setKeep(2, confirmed = 1)
        await { vm.state.value?.askKeep == 2 }
        assertEquals("nothing deleted", 4, runBlocking { backups.list(loc) }.size)
        assertEquals(10, vm.state.value!!.keep)
        vm.dismissAsk()
        assertNull(vm.state.value!!.askKeep)
    }

    @Test
    fun `with a backup open the count can't change`() {
        val older = keep(TestVaults.bytes(aesRounds = 500UL))
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        vm.show()
        vm.select(older)
        await { vm.state.value == null }
        vm.show()
        await { vm.state.value?.items != null }
        assertEquals(false, vm.state.value!!.isFile)
        assertEquals(false, vm.state.value!!.canChangeBackups)
        vm.setKeep(1, confirmed = 5)
        await { vm.state.value?.applying == false }
        assertEquals(2, runBlocking { backups.list(loc) }.size)
    }

    @Test
    fun `a staged delete hides the copy and offers Undo, and the newest can't be staged`() {
        val items = sheetWith(2)
        vm.stageDelete(items[0], window.milliseconds)
        assertEquals(3, vm.state.value!!.items!!.size)
        vm.stageDelete(items[1], window.milliseconds)
        assertEquals(listOf(items[0], items[2]), vm.state.value!!.items)
        assertEquals(1, vm.state.value!!.undo)
        assertEquals("nothing deleted yet", 3, stored().size)
    }

    @Test
    fun `Undo brings the copy back and deletes nothing`() {
        val items = sheetWith(2, window = 300)
        vm.stageDelete(items[1], window.milliseconds)
        vm.undoDelete()
        assertEquals(items, vm.state.value!!.items)
        assertEquals(0, vm.state.value!!.undo)
        Thread.sleep(600)
        ShadowLooper.idleMainLooper()
        assertEquals(3, stored().size)
    }

    @Test
    fun `the copy is deleted when the window ends`() {
        val items = sheetWith(2, window = 300)
        vm.stageDelete(items[1], window.milliseconds)
        vm.stageDelete(items[2], window.milliseconds)
        await { stored().size == 1 }
        assertEquals(listOf(items[0].id), stored())
        assertEquals(0, vm.state.value!!.undo)
        assertEquals(listOf(items[0]), vm.state.value!!.items)
    }

    @Test
    fun `closing the sheet deletes at once`() {
        val items = sheetWith(2)
        vm.stageDelete(items[1], window.milliseconds)
        vm.close()
        await { stored().size == 2 }
        assertTrue(items[1].id !in stored())
    }

    @Test
    fun `opening a copy deletes the staged one first`() {
        val items = sheetWith(2)
        vm.stageDelete(items[2], window.milliseconds)
        vm.select(items[1])
        await { vm.state.value == null }
        assertEquals(listOf(items[0].id, items[1].id), stored())
        assertEquals(items[1], sessions.current.value!!.backup)
    }

    @Test
    fun `a lock deletes with the location taken when it was staged`() {
        val items = sheetWith(2)
        vm.stageDelete(items[1], window.milliseconds)
        sessions.lock()
        await { stored().size == 2 }
        assertTrue(items[1].id !in stored())
    }

    @Test
    fun `a staged copy stays hidden when a count change reloads the list`() {
        val items = sheetWith(2)
        vm.stageDelete(items[2], window.milliseconds)
        vm.setKeep(5, confirmed = 0)
        await { vm.state.value?.keep == 5 && vm.state.value?.applying == false }
        assertEquals(listOf(items[0], items[1]), vm.state.value!!.items)
    }

    @Test
    fun `a delete refused at the end comes back with the reason`() {
        val items = sheetWith(2, window = 300)
        vm.stageDelete(items[1], window.milliseconds)
        backups.pinned = setOf(loc)
        await { vm.state.value?.undo == 0 }
        assertEquals(items, vm.state.value!!.items)
        assertEquals(BackupsNotice.PINNED, vm.state.value!!.notice)
        vm.noticeShown()
        assertNull(vm.state.value!!.notice)
        backups.pinned = emptySet()
        backups.failDeletes = true
        vm.stageDelete(items[1], window.milliseconds)
        await { vm.state.value?.notice == BackupsNotice.FAILED }
        assertEquals(items, vm.state.value!!.items)
    }

    @Test
    fun `nothing is staged while a save is unverified`() {
        val items = sheetWith(2)
        pending = true
        vm.show()
        await { vm.state.value?.pinned == true }
        vm.stageDelete(items[1], window.milliseconds)
        assertEquals(0, vm.state.value!!.undo)
        assertEquals(false, vm.state.value!!.canDelete)
    }

    @Test
    fun `a copy under an older password offers to open it with that password`() {
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        val older = keep(TestVaults.bytes(aesRounds = 500UL, password = "older-password"))
        vm.show()
        vm.select(older)
        await { vm.state.value?.opening == false }
        val shown = vm.state.value!!
        assertTrue(shown.failed)
        assertTrue(shown.oldPassword)
        assertEquals(PasswordTarget(older, null), shown.passwordTarget)
        assertNull("the file stays open", sessions.current.value!!.backup)
    }

    @Test
    fun `a damaged copy offers no password`() {
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        val damaged = keep(TestVaults.bytes(aesRounds = 600UL))
        backups.corrupt(loc, damaged.id)
        vm.show()
        vm.select(damaged)
        await { vm.state.value?.damaged == true }
        assertNull(vm.state.value!!.passwordTarget)
        assertEquals(false, vm.state.value!!.oldPassword)
    }

    @Test
    fun `a slow copy offers to open it with its password, with the slow settings`() {
        unlockLive(TestVaults.bytes(aesRounds = 1_000UL))
        val slow = keep(org.onekash.kashpass.vault.testing.RawKdbx.parse(TestVaults.bytes(aesRounds = 1_000UL))
            .withKdf { it.with("R", org.onekash.kashpass.vault.testing.RawDictionary.UINT64, org.onekash.kashpass.vault.testing.u64(100_000_000UL)) }.toBytes())
        vm.show()
        vm.select(slow)
        await { vm.state.value?.slow == true }
        val target = vm.state.value!!.passwordTarget!!
        assertEquals(slow, target.backup)
        assertEquals(KdfSettings.AesKdf(100_000_000UL), target.slow!!.kdf)
    }

    @Test
    fun `Open with its password deletes a staged copy, closes the sheet, then hands the copy over`() {
        val items = sheetWith(2)
        val older = keep(TestVaults.bytes(aesRounds = 400UL, password = "older-password"))
        vm.show()
        await { vm.state.value?.items?.size == 4 }
        vm.stageDelete(items[1], window.milliseconds)
        vm.select(older)
        await { vm.state.value?.passwordTarget != null }
        // Selecting ran the staged delete; stage another to see Open with its password run it too.
        vm.stageDelete(items[2], window.milliseconds)
        var handed: PasswordTarget? = null
        var storedThen: List<String>? = null
        vm.openWithPassword { target ->
            handed = target
            storedThen = stored()
        }
        await { handed != null && storedThen != null }
        assertEquals(older, handed!!.backup)
        assertTrue("deleted before the hand-over", items[2].id !in storedThen!!)
        assertNull(vm.state.value)
        assertNotNull("the vault is still open; the caller locks", sessions.current.value)
    }

    @Test
    fun `nothing is staged while a copy is opening or a backup is open`() {
        assertEquals(false, BackupsUiState(emptyList(), opening = true).canDelete)
        assertEquals(false, BackupsUiState(emptyList(), isFile = false).canDelete)
    }

    @Test
    fun `lowering the count with a delete staged runs the delete first, then trims`() {
        val items = sheetWith(2)
        vm.stageDelete(items[2], window.milliseconds)
        vm.setKeep(1, confirmed = 1)
        await { vm.state.value?.keep == 1 && vm.state.value?.applying == false }
        assertNull(vm.state.value!!.askKeep)
        assertEquals(listOf(items[0].id), stored())
    }

    @Test
    fun `a staged copy already gone counts as deleted, with no notice`() {
        val items = sheetWith(2, window = 300)
        vm.stageDelete(items[2], window.milliseconds)
        runBlocking { backups.keepNewest(loc, 2) }
        // Undo reads 0 as soon as the commit starts; the list follows once it ends.
        await { vm.state.value?.undo == 0 && vm.state.value?.items == listOf(items[0], items[1]) }
        assertNull(vm.state.value!!.notice)
    }

    @Test
    fun `a staged copy that became the newest comes back with no notice`() {
        val items = sheetWith(2, window = 300)
        vm.stageDelete(items[1], window.milliseconds)
        // The newer copy goes outside the sheet, so the staged one is the newest when it runs.
        backups.drop(loc, items[0].id)
        // Undo reads 0 as soon as the commit starts; the list follows once it ends.
        await { vm.state.value?.undo == 0 && vm.state.value?.items?.any { it.id == items[1].id } == true }
        assertNull(vm.state.value!!.notice)
    }
}
