package org.onekash.kashpass.platform

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.testing.FakeUriGrants
import org.onekash.kashpass.vault.storage.KeyFileRead
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class KeyFileAccessTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val resolver = context.contentResolver
    private val store = PrefsVaultStateStore(context)
    private val storage = FakeVaultStorage().apply {
        put(KEY, TestVaults.KEY_FILE)
        put(OTHER_KEY, TestVaults.KEY_FILE)
        put(VAULT_FILE, TestVaults.bytes(aesRounds = 1_000UL))
    }
    private val names = mapOf(KEY to "vault.keyx", OTHER_KEY to "other.key")
    private val access = KeyFileAccess(ResolverUriGrants(resolver), store, storage, Dispatchers.Unconfined) { names[it.toString()] }

    private fun persisted() = resolver.persistedUriPermissions.associate { it.uri.toString() to (it.isReadPermission to it.isWritePermission) }

    private fun choose(uri: String) = runBlocking { access.choose(VAULT, Uri.parse(uri)) }

    @Test
    fun `a key file whose provider throws is chosen and its read fails, without an exception`() {
        val throwing = SafVaultStorage(Dispatchers.Unconfined, { throw IllegalArgumentException("provider") }, { null })
        val access = KeyFileAccess(ResolverUriGrants(resolver), store, throwing, Dispatchers.Unconfined) { names[it.toString()] }
        assertEquals(KeyFileChoice.Chosen, runBlocking { access.choose(VAULT, Uri.parse(KEY)) })
        assertEquals(KeyFileRead.Failed(StorageFailure.IO_FAILURE), runBlocking { access.read(VAULT) })
    }

    @Test
    fun `choosing a key file takes a read grant only and remembers its name for the vault`() {
        assertEquals(KeyFileChoice.Chosen, choose(KEY))
        assertEquals(mapOf(KEY to (true to false)), persisted())
        assertEquals(RememberedKeyFile(KEY, "vault.keyx"), access.current(VAULT))
        assertNull(access.current("content://drive/document/elsewhere"))
    }

    @Test
    fun `choosing another key file releases the previous one's grant`() {
        choose(KEY)
        choose(OTHER_KEY)
        assertEquals(setOf(OTHER_KEY), persisted().keys)
        assertEquals("other.key", access.current(VAULT)?.displayName)
    }

    @Test
    fun `removing the key file forgets it and releases its grant`() = runBlocking {
        choose(KEY)
        access.remove(VAULT)
        assertNull(access.current(VAULT))
        assertEquals(emptySet<String>(), persisted().keys)
    }

    @Test
    fun `a KeePass vault is refused as a key file and keeps no grant`() {
        choose(KEY)
        assertEquals(KeyFileChoice.KeePassVault, choose(VAULT_FILE))
        assertEquals(setOf(KEY), persisted().keys)
        assertEquals(RememberedKeyFile(KEY, "vault.keyx"), access.current(VAULT))
    }

    @Test
    fun `the vault itself is refused as its key file and keeps its read and write grant`() = runBlocking {
        ResolverUriGrants(resolver).take(Uri.parse(VAULT), UriGrants.READ_WRITE)
        assertEquals(KeyFileChoice.KeePassVault, access.choose(VAULT, Uri.parse(VAULT)))
        assertEquals(mapOf(VAULT to (true to true)), persisted())
        assertNull(access.current(VAULT))
    }

    @Test
    fun `a refused grant keeps the previous key file`() = runBlocking {
        choose(KEY)
        val failing = KeyFileAccess(FakeUriGrants(refuseAll = true), store, storage, Dispatchers.Unconfined) { null }
        assertEquals(KeyFileChoice.Failed, failing.choose(VAULT, Uri.parse(OTHER_KEY)))
        assertEquals(RememberedKeyFile(KEY, "vault.keyx"), access.current(VAULT))
    }

    @Test
    fun `a key file without a display name shows its last path segment`() {
        choose("content://drive/document/key9")
        storage.put("content://drive/document/key9", TestVaults.KEY_FILE)
        assertEquals("key9", access.current(VAULT)?.displayName)
    }

    @Test
    fun `each read goes to the provider and reports its failures`() = runBlocking {
        assertEquals(KeyFileRead.None, access.read(VAULT))
        choose(KEY)
        val read = access.read(VAULT) as KeyFileRead.Bytes
        assertArrayEquals(TestVaults.KEY_FILE, read.bytes)
        val before = storage.reads
        access.read(VAULT)
        assertEquals(before + 1, storage.reads)
        storage.fail(KEY, StorageFailure.PERMISSION_REVOKED)
        assertEquals(KeyFileRead.Failed(StorageFailure.PERMISSION_REVOKED), access.read(VAULT))
        storage.put(KEY, TestVaults.bytes(aesRounds = 1_000UL))
        storage.recover(KEY)
        assertEquals(KeyFileRead.KeePassVault, access.read(VAULT))
    }

    @Test
    fun `choosing a key file reads only its first 8 bytes`() = runBlocking {
        val big = ByteArray(10 * 1024 * 1024) { (it % 251).toByte() }
        storage.put(KEY, big)
        assertEquals(KeyFileChoice.Chosen, choose(KEY))
        assertEquals(listOf(8), storage.prefixReads)
        assertEquals(0, storage.reads)
        // The unlock reads the whole file again.
        assertArrayEquals(big, (access.read(VAULT) as KeyFileRead.Bytes).bytes)
        assertEquals(1, storage.reads)
        assertArrayEquals(big, (access.readOnce(Uri.parse(KEY)) as KeyFileRead.Bytes).bytes)
        assertEquals(listOf(8), storage.prefixReads)
    }

    @Test
    fun `the checked prefix is zero-filled for a key file and for a KeePass vault`() {
        assertEquals(KeyFileChoice.Chosen, choose(KEY))
        assertEquals(8, storage.lastReturned!!.size)
        assertTrue(storage.lastReturned!!.all { it == 0.toByte() })
        assertEquals(KeyFileChoice.KeePassVault, choose(VAULT_FILE))
        assertEquals(8, storage.lastReturned!!.size)
        assertTrue(storage.lastReturned!!.all { it == 0.toByte() })
    }

    @Test
    fun `a file shorter than 8 bytes is a key file`() {
        storage.put(KEY, byteArrayOf(1, 2, 3))
        assertEquals(KeyFileChoice.Chosen, choose(KEY))
        assertEquals(RememberedKeyFile(KEY, "vault.keyx"), access.current(VAULT))
        assertTrue(storage.lastReturned!!.all { it == 0.toByte() })
    }

    @Test
    fun `a key file that can't be read when chosen is remembered`() {
        storage.fail(KEY, StorageFailure.IO_FAILURE)
        assertEquals(KeyFileChoice.Chosen, choose(KEY))
        assertEquals(RememberedKeyFile(KEY, "vault.keyx"), access.current(VAULT))
        assertEquals(setOf(KEY), persisted().keys)
    }

    @Test
    fun `nothing about the key file but its location and name is stored`() {
        choose(KEY)
        val prefs = context.getSharedPreferences(PrefsVaultStateStore.FILE, Context.MODE_PRIVATE).all
        val key = String(TestVaults.KEY_FILE, Charsets.UTF_8).substringAfter("<Data").substringAfter(">").trim().substringBefore(" ")
        assertTrue(prefs.values.none { it.toString().contains(key) })
    }

    private companion object {
        const val VAULT = "content://drive/document/doc1"
        const val KEY = "content://drive/document/key1"
        const val OTHER_KEY = "content://drive/document/key2"
        const val VAULT_FILE = "content://drive/document/doc5"
    }
}
