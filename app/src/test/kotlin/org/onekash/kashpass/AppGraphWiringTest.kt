package org.onekash.kashpass

import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.storage.DeadlineStorage
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class AppGraphWiringTest {

    @Test
    fun `every provider call goes through the one deadline storage`() {
        val graph = ApplicationProvider.getApplicationContext<KashPassApp>().graph
        assertTrue(graph.storage is DeadlineStorage)
        assertSame(graph.storage, graph.saves.storage)
    }

    @Test
    fun `biometric unlock is wired and, without a Keystore, unavailable`() {
        val graph = ApplicationProvider.getApplicationContext<KashPassApp>().graph
        assertTrue(graph.biometricUnlock.status("content://x") is org.onekash.kashpass.session.BiometricStatus.Unavailable)
    }

    @Test
    fun `the backup store keeps the saved count and a pending marker pins its folder`() {
        val graph = ApplicationProvider.getApplicationContext<KashPassApp>().graph
        val loc = "content://wiring/test"
        // Run off the main thread: the graph's start-up pruning holds the store's lock until it
        // resumes on the main thread.
        val work = java.util.concurrent.Executors.newSingleThreadExecutor().submit<List<Int>> {
            kotlinx.coroutines.runBlocking {
                graph.state.saveBackupKeep(1)
                graph.backups.add(loc, byteArrayOf(1), org.onekash.kashpass.vault.backup.BackupKind.OPENED)
                graph.backups.add(loc, byteArrayOf(2), org.onekash.kashpass.vault.backup.BackupKind.SAVED)
                val trimmed = graph.backups.list(loc).size
                graph.markers.set(loc, "a", "b")
                graph.backups.add(loc, byteArrayOf(3), org.onekash.kashpass.vault.backup.BackupKind.SAVED)
                val pinned = graph.backups.list(loc).size
                graph.markers.clear(loc)
                listOf(trimmed, pinned)
            }
        }
        while (!work.isDone) {
            org.robolectric.shadows.ShadowLooper.idleMainLooper()
            Thread.sleep(10)
        }
        assertEquals(listOf(1, 2), work.get())
    }
}
