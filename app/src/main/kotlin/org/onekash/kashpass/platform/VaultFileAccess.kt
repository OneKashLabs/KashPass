package org.onekash.kashpass.platform

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import androidx.core.net.toUri
import android.provider.OpenableColumns
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import org.onekash.kashpass.vault.storage.UnlockKeyStore

/** Persistable URI grants, separated from the resolver so a failing grant can be tested. */
interface UriGrants {
    /** Takes a persistable grant with [flags]; throws SecurityException when refused. */
    fun take(uri: Uri, flags: Int)

    /** Releases the grant [take] took with the same [flags]. */
    fun release(uri: Uri, flags: Int)

    /** Returns every persisted grant KashPass holds, each with its [READ] or [READ_WRITE] flags. */
    fun persisted(): List<Pair<Uri, Int>>

    companion object {
        /** Read only: key files, and a vault whose provider refuses a write grant. */
        const val READ = Intent.FLAG_GRANT_READ_URI_PERMISSION

        /** Read and write: the vault file, so saving needs no second pick. */
        const val READ_WRITE = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
    }
}

/** [UriGrants] over the content resolver. */
class ResolverUriGrants(private val resolver: ContentResolver) : UriGrants {
    override fun take(uri: Uri, flags: Int) = resolver.takePersistableUriPermission(uri, flags)
    override fun release(uri: Uri, flags: Int) = try {
        resolver.releasePersistableUriPermission(uri, flags)
    } catch (e: SecurityException) {
        // Already gone (file deleted or grant revoked); nothing left to release.
    }

    override fun persisted(): List<Pair<Uri, Int>> = resolver.persistedUriPermissions.map { permission ->
        val read = if (permission.isReadPermission) Intent.FLAG_GRANT_READ_URI_PERMISSION else 0
        val write = if (permission.isWritePermission) Intent.FLAG_GRANT_WRITE_URI_PERMISSION else 0
        permission.uri to (read or write)
    }
}

/** Returns [nameOf]'s name for [uri], or the URI's last path segment when it gives none. */
internal fun nameOrSegment(uri: Uri, nameOf: (Uri) -> String?): String = nameOf(uri) ?: uri.lastPathSegment.orEmpty()

/** Outcome of [VaultFiles.choose]. */
enum class ChooseResult { Chosen, Failed }

/** Remembers the vault file for the lock screen. */
interface VaultFiles {
    /** Returns the remembered vault, or null before the first pick. */
    fun current(): RememberedVault?

    /** Makes [uri] the vault; see [VaultFileAccess.choose]. Main-safe. */
    suspend fun choose(uri: Uri): ChooseResult

    /**
     * Takes a persistable read and write grant for [uri], a file another app handed over;
     * returns false when the provider refuses it. Main-safe.
     */
    suspend fun takeOffered(uri: Uri): Boolean

    /**
     * Releases the grant [takeOffered] took for [uri] once the offer is dropped, unless [uri] is
     * the remembered vault or its key file. Main-safe.
     */
    suspend fun releaseOffered(uri: Uri)

    /** Returns the provider's name for [uri], or its last path segment. Main-safe. */
    suspend fun displayName(uri: Uri): String
}

/**
 * Remembers the one vault file the user picked. Choosing a file, the same one included, resets
 * that file's KDF baseline and weak-warning dismissal: re-picking is how the user accepts settings
 * that were refused as a downgrade. Choosing a different file deletes the previous one's stored
 * biometric unlock key and its key-file mark, forgets its key file and whether it was unlocked
 * with one, and releases the key file's read grant. A file whose provider refuses a write grant
 * is remembered read-only ([RememberedVault.readOnly]).
 */
class VaultFileAccess(
    private val grants: UriGrants,
    private val store: PrefsVaultStateStore,
    private val io: CoroutineDispatcher,
    private val unlockKeys: UnlockKeyStore? = null,
    private val nameOf: (Uri) -> String?,
) : VaultFiles {

    override fun current(): RememberedVault? = store.vault()

    /**
     * Makes [uri] the vault. The new grant is taken first: read and write, or read alone when the
     * provider refuses writing. Only when one succeeds is the previous vault's grant released, with
     * the flags it was taken with, so a refused grant leaves the old vault usable. The grant calls
     * and the name query go to the provider (another app), so they run on [io].
     */
    override suspend fun choose(uri: Uri): ChooseResult = withContext(io) {
        val flags = takeGrant(uri) ?: return@withContext ChooseResult.Failed
        val previous = current()
        if (previous != null && previous.location != uri.toString()) {
            grants.release(previous.location.toUri(), grantFlags(previous))
            // A key file picked as the new vault keeps the read and write grant taken for it.
            store.keyFile(previous.location)?.takeIf { it.location != uri.toString() }?.let {
                grants.release(it.location.toUri(), UriGrants.READ)
            }
            store.clearKeyFile()
            store.clear(previous.location)
            unlockKeys?.delete(previous.location)
            store.saveBiometricNeedsKeyFile(previous.location, false)
            store.saveKeyFileUnlock(previous.location, false)
        }
        store.clear(uri.toString())
        store.saveVault(uri.toString(), nameOrSegment(uri, nameOf), readOnly = flags == UriGrants.READ)
        ChooseResult.Chosen
    }

    // The flags of the grant taken, or null when the provider refuses reading too.
    private fun takeGrant(uri: Uri): Int? = try {
        grants.take(uri, UriGrants.READ_WRITE)
        UriGrants.READ_WRITE
    } catch (e: SecurityException) {
        try {
            grants.take(uri, UriGrants.READ)
            UriGrants.READ
        } catch (e: SecurityException) {
            null
        }
    }

    private fun grantFlags(vault: RememberedVault) = if (vault.readOnly) UriGrants.READ else UriGrants.READ_WRITE

    override suspend fun takeOffered(uri: Uri): Boolean = withContext(io) {
        try {
            grants.take(uri, UriGrants.READ_WRITE)
            true
        } catch (e: SecurityException) {
            false
        }
    }

    // Releasing the remembered vault's or key file's URI would take its own grant away.
    override suspend fun releaseOffered(uri: Uri) = withContext(io) {
        val location = uri.toString()
        val vault = current()
        if (location == vault?.location || location == vault?.let { store.keyFile(it.location) }?.location) return@withContext
        grants.release(uri, UriGrants.READ_WRITE)
    }

    /**
     * Releases every persisted grant that is neither the remembered vault's nor its key file's:
     * one left by a process that ended while a file was offered, before its grant was released.
     * Call it once at process start, before any pick or offer takes a grant. The grant list and
     * the releases go to the system, not to a provider, so it runs on the caller's thread.
     */
    fun releaseUnusedGrants() {
        val vault = current()
        val keep = setOfNotNull(vault?.location, vault?.let { store.keyFile(it.location) }?.location)
        for ((uri, flags) in grants.persisted()) {
            if (uri.toString() !in keep) grants.release(uri, flags)
        }
    }

    override suspend fun displayName(uri: Uri): String = withContext(io) { nameOrSegment(uri, nameOf) }

    companion object {
        /** Reads the picker's display name for [uri] from the provider. */
        fun displayNameFrom(resolver: ContentResolver): (Uri) -> String? = { uri ->
            try {
                resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                    if (it.moveToFirst()) it.getString(0) else null
                }
            } catch (e: RuntimeException) {
                // A provider can throw anything here (revoked grant, unknown document, restart);
                // choose() then falls back to the URI's last segment.
                null
            }
        }
    }
}
