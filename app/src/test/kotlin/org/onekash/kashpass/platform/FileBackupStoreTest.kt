package org.onekash.kashpass.platform

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import java.io.File
import java.time.Duration
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.backup.BackupDeletion
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.backup.Sha256
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class FileBackupStoreTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val loc = "content://com.google.android.apps.docs.storage/document/acc%3D1%3Bdoc%3D42"
    private var clock = Instant.parse("2026-10-20T12:00:00Z")
    private val root by lazy { temp.newFolder("backups") }
    private var keep = 3
    private val pinned = mutableSetOf<String>()
    private val store by lazy { FileBackupStore(root, Dispatchers.IO, keep = { keep }, pinned = { it in pinned }) { clock } }

    private fun folder() = File(root, Sha256.ofLocation(loc))

    @Test
    fun `a backup is the exact bytes under a generated name in a folder keyed by the location hash`() = runBlocking<Unit> {
        val bytes = ByteArray(5_000) { it.toByte() }
        val added = store.add(loc, bytes, BackupKind.OPENED) as BackupResult.Added
        assertEquals("${clock.toEpochMilli()}-opened-${Sha256.hex(bytes)}.kdbx", added.info.id)
        assertEquals(listOf(added.info.id), folder().list()!!.toList())
        assertArrayEquals(bytes, store.read(loc, added.info.id))
        assertEquals(listOf(added.info), store.list(loc))
        assertEquals(5_000L, added.info.size)
        assertFalse("the location never appears on disk", root.walk().any { it.name.contains("docs.storage") })
    }

    @Test
    fun `bytes equal to the newest backup are not kept twice`() = runBlocking<Unit> {
        store.add(loc, byteArrayOf(1), BackupKind.OPENED)
        clock += Duration.ofMinutes(1)
        assertEquals(BackupResult.SameAsNewest, store.add(loc, byteArrayOf(1), BackupKind.BEFORE_SAVE))
        clock += Duration.ofMinutes(1)
        store.add(loc, byteArrayOf(2), BackupKind.BEFORE_SAVE)
        clock += Duration.ofMinutes(1)
        assertTrue(store.add(loc, byteArrayOf(1), BackupKind.OPENED) is BackupResult.Added)
        assertEquals(listOf(BackupKind.OPENED, BackupKind.BEFORE_SAVE, BackupKind.OPENED), store.list(loc).map { it.kind })
    }

    @Test
    fun `opened and saved copies trim to the backup count, a before-save copy trims nothing`() = runBlocking<Unit> {
        repeat(5) {
            store.add(loc, byteArrayOf(it.toByte()), BackupKind.OPENED)
            clock += Duration.ofDays(1)
        }
        assertEquals(listOf<Byte>(4, 3, 2), store.list(loc).map { store.read(loc, it.id)!!.single() })
        store.add(loc, byteArrayOf(9), BackupKind.BEFORE_SAVE)
        assertEquals("the before-save copy is added, nothing goes", 4, store.list(loc).size)
        keep = 1
        clock += Duration.ofMinutes(1)
        store.add(loc, byteArrayOf(10), BackupKind.SAVED)
        assertEquals(listOf<Byte>(10), store.list(loc).map { store.read(loc, it.id)!!.single() })
    }

    @Test
    fun `keepNewest trims to a count, returns how many went, and never throws`() = runBlocking<Unit> {
        keep = 30
        repeat(5) {
            store.add(loc, byteArrayOf(it.toByte()), BackupKind.OPENED)
            clock += Duration.ofMinutes(1)
        }
        assertEquals(3, store.keepNewest(loc, 2))
        assertEquals(2, store.list(loc).size)
        assertEquals(0, store.keepNewest("content://never/seen", 1))
    }

    @Test
    fun `a folder with a pending save marker keeps every copy`() = runBlocking<Unit> {
        keep = 1
        pinned += Sha256.ofLocation(loc)
        repeat(3) {
            store.add(loc, byteArrayOf(it.toByte()), BackupKind.OPENED)
            clock += Duration.ofMinutes(1)
        }
        assertEquals(3, store.list(loc).size)
        assertEquals(0, store.keepNewest(loc, 1))
        store.pruneAll()
        assertEquals(3, store.list(loc).size)
        pinned.clear()
        store.pruneAll()
        assertEquals(1, store.list(loc).size)
    }

    @Test
    fun `read refuses names this store never generated`() = runBlocking<Unit> {
        val added = store.add(loc, byteArrayOf(1), BackupKind.OPENED) as BackupResult.Added
        File(root, "secret.txt").writeText("x")
        for (id in listOf("../secret.txt", "../../etc/passwd", "secret.txt", added.info.id + "/", "")) assertNull(id, store.read(loc, id))
        assertArrayEquals(byteArrayOf(1), store.read(loc, added.info.id))
    }

    @Test
    fun `a backup that can't be written fails without leaving files`() = runBlocking<Unit> {
        val blocked = temp.newFile("not-a-folder")
        val broken = FileBackupStore(blocked, Dispatchers.IO) { clock }
        assertEquals(BackupResult.Failed, broken.add(loc, byteArrayOf(1), BackupKind.BEFORE_SAVE))
        assertEquals(emptyList<Any>(), broken.list(loc))
    }

    @Test
    fun `a leftover temporary file is removed on the next add`() = runBlocking<Unit> {
        folder().mkdirs()
        File(folder(), "1-opened-${"0".repeat(64)}.kdbx.tmp").writeText("partial")
        store.add(loc, byteArrayOf(1), BackupKind.OPENED)
        assertTrue(folder().list()!!.none { it.endsWith(".tmp") })
    }

    @Test
    fun `a backup of saved bytes is named and listed as saved`() = runBlocking<Unit> {
        val added = store.add(loc, byteArrayOf(3), BackupKind.SAVED) as BackupResult.Added
        assertEquals("${clock.toEpochMilli()}-saved-${Sha256.hex(byteArrayOf(3))}.kdbx", added.info.id)
        assertEquals(listOf(BackupKind.SAVED), store.list(loc).map { it.kind })
        assertArrayEquals(byteArrayOf(3), store.read(loc, added.info.id))
    }

    @Test
    fun `pruning at start trims every vault to the count and removes leftovers`() = runBlocking<Unit> {
        val other = "content://other/vault"
        keep = 30
        repeat(12) {
            store.add(loc, byteArrayOf(it.toByte()), BackupKind.OPENED)
            store.add(other, byteArrayOf(it.toByte()), BackupKind.OPENED)
            clock += Duration.ofDays(1)
        }
        val otherFolder = File(root, Sha256.ofLocation(other))
        File(otherFolder, "3-saved-${"3".repeat(64)}.kdbx.tmp").writeBytes(byteArrayOf(9))
        File(root, "stray.txt").writeText("not a folder")
        keep = 3
        store.pruneAll()
        assertEquals(3, store.list(loc).size)
        assertEquals(3, store.list(other).size)
        assertTrue(otherFolder.list()!!.none { it.endsWith(".tmp") })
        assertTrue("files that aren't folders are left alone", File(root, "stray.txt").exists())
    }

    @Test
    fun `pruning never throws, even over a root that isn't a folder`() = runBlocking<Unit> {
        FileBackupStore(temp.newFile("plain"), Dispatchers.IO) { clock }.pruneAll()
        FileBackupStore(File(temp.root, "missing"), Dispatchers.IO) { clock }.pruneAll()
    }

    @Test
    fun `the app keeps backups in noBackupFilesDir`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val graphRoot = org.onekash.kashpass.AppGraph.backupRoot(context)
        assertEquals(File(context.noBackupFilesDir, "backups"), graphRoot)
    }

    @Test
    fun `keepNewest counts only the copies it deleted, and a copy it can't delete doesn't throw`() = runBlocking<Unit> {
        keep = 30
        repeat(3) {
            store.add(loc, byteArrayOf(it.toByte()), BackupKind.OPENED)
            clock += Duration.ofMinutes(1)
        }
        folder().setWritable(false)
        try {
            assertEquals(0, store.keepNewest(loc, 1))
            assertEquals(3, store.list(loc).size)
        } finally {
            folder().setWritable(true)
        }
        assertEquals(2, store.keepNewest(loc, 1))
    }

    @Test
    fun `a copy named with a clock that ran ahead can't push out the copy written last`() = runBlocking<Unit> {
        keep = 1
        clock += Duration.ofDays(400)
        store.add(loc, byteArrayOf(1), BackupKind.OPENED)
        clock -= Duration.ofDays(400)
        val saved = store.add(loc, byteArrayOf(2), BackupKind.SAVED) as BackupResult.Added
        assertEquals(listOf(saved.info.id), store.list(loc).map { it.id })
    }

    private suspend fun three(): List<String> {
        keep = 30
        repeat(3) {
            store.add(loc, byteArrayOf(it.toByte()), BackupKind.OPENED)
            clock += Duration.ofMinutes(1)
        }
        return store.list(loc).map { it.id }
    }

    @Test
    fun `delete removes one older copy and its file`() = runBlocking<Unit> {
        val (newest, middle, oldest) = three()
        assertEquals(BackupDeletion.Deleted, store.delete(loc, middle))
        assertEquals(listOf(newest, oldest), store.list(loc).map { it.id })
        assertFalse(File(folder(), middle).exists())
    }

    @Test
    fun `the newest copy is never deleted`() = runBlocking<Unit> {
        val (newest) = three()
        assertEquals(BackupDeletion.Newest, store.delete(loc, newest))
        assertEquals(3, store.list(loc).size)
    }

    @Test
    fun `nothing is deleted while a save of the location is unverified`() = runBlocking<Unit> {
        val (_, middle) = three()
        pinned += folder().name
        assertEquals(BackupDeletion.Pinned, store.delete(loc, middle))
        assertEquals(3, store.list(loc).size)
    }

    @Test
    fun `a copy that is gone, or a name the store never made, is not found`() = runBlocking<Unit> {
        val (_, middle) = three()
        store.delete(loc, middle)
        assertEquals(BackupDeletion.NotFound, store.delete(loc, middle))
        assertEquals(BackupDeletion.NotFound, store.delete(loc, "../../shared_prefs/x.xml"))
        assertEquals(BackupDeletion.NotFound, store.delete("content://other", middle))
        assertEquals(2, store.list(loc).size)
    }

    @Test
    fun `a copy that can't be deleted fails without throwing`() = runBlocking<Unit> {
        val (_, middle) = three()
        folder().setWritable(false)
        try {
            assertEquals(BackupDeletion.Failed, store.delete(loc, middle))
        } finally {
            folder().setWritable(true)
        }
        assertEquals(3, store.list(loc).size)
    }

    @Test
    fun `a delete and an add run one after the other, so the add's trim sees the delete`() = runBlocking<Unit> {
        val (_, middle, oldest) = three()
        keep = 2
        clock += Duration.ofMinutes(1)
        val added = kotlinx.coroutines.coroutineScope {
            val delete = async(Dispatchers.IO) { store.delete(loc, middle) }
            val add = async(Dispatchers.IO) { store.add(loc, byteArrayOf(9), BackupKind.OPENED) }
            delete.await() to add.await()
        }
        assertTrue(added.second is BackupResult.Added)
        // Whichever ran first, two copies remain and the oldest is gone or deleted: never three.
        assertEquals(2, store.list(loc).size)
        assertFalse(store.list(loc).any { it.id == oldest } && store.list(loc).any { it.id == middle })
    }
}
