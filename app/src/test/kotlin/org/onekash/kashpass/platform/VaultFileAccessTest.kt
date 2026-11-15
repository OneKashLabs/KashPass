package org.onekash.kashpass.platform

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.Executors
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.testing.FakeUriGrants
import org.onekash.kashpass.vault.header.KdfSettings
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class VaultFileAccessTest {

    @After
    fun resetProvider() = FakeDocumentsProvider.reset()

    @Test
    fun `the production display name comes from OpenableColumns and a failing provider gives null`() {
        val resolver = ApplicationProvider.getApplicationContext<Context>().contentResolver
        Robolectric.setupContentProvider(FakeDocumentsProvider::class.java, FakeDocumentsProvider.AUTHORITY)
        val name = VaultFileAccess.displayNameFrom(resolver)
        assertEquals("Passwords.kdbx", name(FakeDocumentsProvider.URI))
        FakeDocumentsProvider.failure = IllegalStateException("provider restarting")
        assertNull(name(FakeDocumentsProvider.URI))
        assertNull(name(Uri.parse("content://no.such.authority/doc")))
    }

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val resolver = context.contentResolver
    private val store = PrefsVaultStateStore(context)
    private val names = mutableMapOf(OLD to "Old.kdbx", NEW to "New.kdbx")
    private val ioThreads = Executors.newSingleThreadExecutor { Thread(it, "file-access-io") }
    private val ioThreadNames = mutableListOf<String>()
    private val access = VaultFileAccess(ResolverUriGrants(resolver), store, ioThreads.asCoroutineDispatcher()) {
        ioThreadNames += Thread.currentThread().name
        names[it.toString()]
    }

    private fun choose(uri: Uri) = runBlocking { access.choose(uri) }

    @After
    fun stopIo() = ioThreads.shutdown()

    @Test
    fun `choosing does its provider calls on the injected dispatcher, not the caller's thread`() {
        choose(Uri.parse(OLD))
        // Coroutine debug mode appends " @coroutine#n" to the thread name.
        assertEquals(listOf("file-access-io"), ioThreadNames.map { it.substringBefore(" @") })
    }

    private fun persisted() = resolver.persistedUriPermissions.associate { it.uri.toString() to (it.isReadPermission to it.isWritePermission) }

    @Test
    fun `choosing a file takes a persistable read and write grant and remembers its name`() {
        assertEquals(ChooseResult.Chosen, choose(Uri.parse(OLD)))
        assertEquals(mapOf(OLD to (true to true)), persisted())
        assertEquals(RememberedVault(OLD, "Old.kdbx"), access.current())
    }

    @Test
    fun `choosing a different file releases the old grant and clears both files' KDF state`() {
        choose(Uri.parse(OLD))
        store.saveKdfBaseline(OLD, KdfSettings.AesKdf(600_000UL))
        store.saveKdfBaseline(NEW, KdfSettings.AesKdf(600_000UL))
        choose(Uri.parse(NEW))
        assertEquals(setOf(NEW), persisted().keys)
        assertNull(store.kdfBaseline(OLD))
        assertNull(store.kdfBaseline(NEW))
        assertEquals(RememberedVault(NEW, "New.kdbx"), access.current())
    }

    @Test
    fun `re-choosing the same file keeps access and resets its baseline`() {
        choose(Uri.parse(OLD))
        store.saveKdfBaseline(OLD, KdfSettings.AesKdf(700_000UL))
        store.saveWeakWarningDismissed(OLD, KdfSettings.AesKdf(6_000UL))
        choose(Uri.parse(OLD))
        assertEquals(setOf(OLD), persisted().keys)
        assertNull(store.kdfBaseline(OLD))
        assertNull(store.weakWarningDismissedFor(OLD))
    }

    @Test
    fun `when taking the new grant fails, the old vault and its grant are unchanged`() {
        choose(Uri.parse(OLD))
        store.saveKdfBaseline(OLD, KdfSettings.AesKdf(600_000UL))
        val failing = VaultFileAccess(FakeUriGrants(refuseAll = true), store, ioThreads.asCoroutineDispatcher()) { names[it.toString()] }

        assertEquals(ChooseResult.Failed, runBlocking { failing.choose(Uri.parse(NEW)) })
        assertEquals(setOf(OLD), persisted().keys)
        assertEquals(RememberedVault(OLD, "Old.kdbx"), failing.current())
        assertEquals(KdfSettings.AesKdf(600_000UL), store.kdfBaseline(OLD))
    }

    @Test
    fun `when the write grant is refused, a read grant alone is taken and the vault is remembered read-only`() {
        val grants = FakeUriGrants(readOnly = setOf(OLD))
        val access = VaultFileAccess(grants, store, ioThreads.asCoroutineDispatcher()) { names[it.toString()] }
        assertEquals(ChooseResult.Chosen, runBlocking { access.choose(Uri.parse(OLD)) })
        assertEquals(listOf("take $OLD READ_WRITE", "take $OLD READ"), grants.calls)
        assertEquals(RememberedVault(OLD, "Old.kdbx", readOnly = true), access.current())
        // The read-only vault's grant is released with the flags it was taken with.
        runBlocking { access.choose(Uri.parse(NEW)) }
        assertEquals("release $OLD READ", grants.calls[3])
        assertEquals(RememberedVault(NEW, "New.kdbx", readOnly = false), access.current())
    }

    @Test
    fun `a file whose provider refuses reading too is not chosen`() {
        val refusing = VaultFileAccess(FakeUriGrants(refuseAll = true), store, ioThreads.asCoroutineDispatcher()) { names[it.toString()] }
        assertEquals(ChooseResult.Failed, runBlocking { refusing.choose(Uri.parse(OLD)) })
        assertNull(refusing.current())
    }

    @Test
    fun `a file offered by another app takes a read and write grant, and declining it releases the grant`() {
        assertTrue(runBlocking { access.takeOffered(Uri.parse(NEW)) })
        assertEquals(mapOf(NEW to (true to true)), persisted())
        runBlocking { access.releaseOffered(Uri.parse(NEW)) }
        assertTrue(persisted().isEmpty())
        val refusing = VaultFileAccess(FakeUriGrants(readOnly = setOf(NEW)), store, ioThreads.asCoroutineDispatcher()) { null }
        assertFalse(runBlocking { refusing.takeOffered(Uri.parse(NEW)) })
    }

    @Test
    fun `declining an offered file keeps the grants of the remembered vault and its key file`() {
        choose(Uri.parse(OLD))
        ResolverUriGrants(resolver).take(Uri.parse(KEY), UriGrants.READ)
        store.saveKeyFile(OLD, KEY, "vault.keyx")
        runBlocking {
            access.releaseOffered(Uri.parse(OLD))
            access.releaseOffered(Uri.parse(KEY))
        }
        assertEquals(mapOf(OLD to (true to true), KEY to (true to false)), persisted())
    }

    @Test
    fun `the offered file's name comes from the provider, else its last path segment`() {
        assertEquals("New.kdbx", runBlocking { access.displayName(Uri.parse(NEW)) })
        names.remove(NEW)
        assertEquals("doc2", runBlocking { access.displayName(Uri.parse(NEW)) })
    }

    @Test
    fun `a file without a display name falls back to its last path segment`() {
        names.remove(NEW)
        choose(Uri.parse(NEW))
        assertEquals("doc2", access.current()?.displayName)
    }

    @Test
    fun `a new instance returns the remembered vault`() {
        choose(Uri.parse(OLD))
        val again = VaultFileAccess(ResolverUriGrants(resolver), PrefsVaultStateStore(context), ioThreads.asCoroutineDispatcher()) { null }
        assertEquals(RememberedVault(OLD, "Old.kdbx"), again.current())
        assertEquals(setOf(OLD), persisted().keys)
    }


    @Test
    fun `at start every persisted grant but the vault's and its key file's is released`() = runBlocking<Unit> {
        val grants = FakeUriGrants()
        val access = VaultFileAccess(grants, store, ioThreads.asCoroutineDispatcher()) { names[it.toString()] }
        access.choose(Uri.parse(OLD))
        grants.take(Uri.parse(KEY), UriGrants.READ)
        store.saveKeyFile(OLD, KEY, "vault.keyx")
        // An offer and a key file left behind by a process that ended before releasing them.
        grants.take(Uri.parse(NEW), UriGrants.READ_WRITE)
        grants.take(Uri.parse(STRAY), UriGrants.READ)
        access.releaseUnusedGrants()
        assertEquals(mapOf(OLD to UriGrants.READ_WRITE, KEY to UriGrants.READ), grants.held())
        assertTrue("release $NEW READ_WRITE" in grants.calls)
        assertTrue("release $STRAY READ" in grants.calls)
    }

    @Test
    fun `at start with no vault remembered every persisted grant is released, on the real resolver too`() {
        val grants = ResolverUriGrants(resolver)
        grants.take(Uri.parse(NEW), UriGrants.READ_WRITE)
        grants.take(Uri.parse(STRAY), UriGrants.READ)
        assertEquals(setOf(NEW, STRAY), persisted().keys)
        access.releaseUnusedGrants()
        assertTrue(persisted().isEmpty())
    }

    private companion object {
        const val STRAY = "content://drive/document/stray4"
        const val OLD = "content://drive/document/doc1"
        const val NEW = "content://drive/document/doc2"
        const val KEY = "content://drive/document/key3"
    }

    @Test
    fun `choosing another file deletes the stored fingerprint key of the previous one, not of the same file`() = runBlocking<Unit> {
        val keys = org.onekash.kashpass.vault.testing.FakeUnlockKeyStore()
        val withKeys = VaultFileAccess(ResolverUriGrants(resolver), store, ioThreads.asCoroutineDispatcher(), keys) { names[it.toString()] }
        withKeys.choose(Uri.parse(OLD))
        keys.seal(OLD, ByteArray(32) { 1 }) { org.onekash.kashpass.vault.storage.Confirmation.Confirmed }
        withKeys.choose(Uri.parse(OLD))
        assertEquals(org.onekash.kashpass.vault.storage.StoredKeyState.STORED, keys.state(OLD))
        store.saveBiometricNeedsKeyFile(OLD, true)
        withKeys.choose(Uri.parse(OLD))
        assertTrue("re-choosing keeps the key and its key-file mark", store.biometricNeedsKeyFile(OLD))
        withKeys.choose(Uri.parse(NEW))
        assertEquals(org.onekash.kashpass.vault.storage.StoredKeyState.NONE, keys.state(OLD))
        assertFalse("the deleted key's key-file mark goes with it", store.biometricNeedsKeyFile(OLD))
    }

    @Test
    fun `choosing another file forgets that the previous one was unlocked with a key file`() {
        choose(Uri.parse(OLD))
        store.saveKeyFileUnlock(OLD, true)
        choose(Uri.parse(OLD))
        assertTrue("re-choosing the same file keeps the mark", store.keyFileUnlock(OLD))
        choose(Uri.parse(NEW))
        assertFalse(store.keyFileUnlock(OLD))
    }

    @Test
    fun `the old vault's key file chosen as the new vault keeps its read and write grant`() {
        choose(Uri.parse(OLD))
        ResolverUriGrants(resolver).take(Uri.parse(KEY), UriGrants.READ)
        store.saveKeyFile(OLD, KEY, "vault.keyx")
        choose(Uri.parse(KEY))
        assertEquals(mapOf(KEY to (true to true)), persisted())
        assertNull(store.keyFile(OLD))
    }

    @Test
    fun `choosing another vault forgets its key file and releases the key file's read grant`() {
        choose(Uri.parse(OLD))
        ResolverUriGrants(resolver).take(Uri.parse(KEY), UriGrants.READ)
        store.saveKeyFile(OLD, KEY, "vault.keyx")
        choose(Uri.parse(OLD))
        assertEquals(RememberedKeyFile(KEY, "vault.keyx"), store.keyFile(OLD))
        assertEquals(mapOf(OLD to (true to true), KEY to (true to false)), persisted())
        choose(Uri.parse(NEW))
        assertNull(store.keyFile(OLD))
        assertNull(store.keyFile(NEW))
        assertEquals(setOf(NEW), persisted().keys)
    }
}
