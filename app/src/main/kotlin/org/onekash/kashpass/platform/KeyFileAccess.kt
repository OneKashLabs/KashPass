package org.onekash.kashpass.platform

import android.net.Uri
import androidx.core.net.toUri
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import org.onekash.kashpass.vault.storage.KeyFileRead
import org.onekash.kashpass.vault.storage.VaultStorage
import org.onekash.kashpass.vault.storage.readKeyFile
import org.onekash.kashpass.vault.storage.startsWithKeePassSignature

/** Outcome of [KeyFiles.choose]. */
enum class KeyFileChoice {
    Chosen,

    /** The provider refused the grant; the previous key file stays. */
    Failed,

    /** The file is a KeePass vault; the previous key file stays. */
    KeePassVault,
}

/** Remembers and reads the vault's key file for the lock screen. */
interface KeyFiles {
    /** Returns the key file remembered for the vault at [vault], or null. */
    fun current(vault: String): RememberedKeyFile?

    /** Makes [uri] the key file of the vault at [vault]; see [KeyFileAccess.choose]. Main-safe. */
    suspend fun choose(vault: String, uri: Uri): KeyFileChoice

    /** Forgets the key file of the vault at [vault] and releases its grant. Main-safe. */
    suspend fun remove(vault: String)

    /** Reads the key file of the vault at [vault] for one unlock. Main-safe. */
    suspend fun read(vault: String): KeyFileRead

    /**
     * Reads the key file at [uri] for one unlock, with the picker's grant for this session;
     * nothing is remembered and no grant is kept. Main-safe.
     */
    suspend fun readOnce(uri: Uri): KeyFileRead

    /** Returns true when the last unlock of the vault at [vault] used a key file. */
    fun keyFileUnlock(vault: String): Boolean

    /** Records whether an unlock of the vault at [vault] used a key file ([used]). */
    fun saveKeyFileUnlock(vault: String, used: Boolean)
}

/**
 * Remembers one key file for the remembered vault, by location and display name only. The key
 * file is read again for every unlock and its bytes are never stored. Key files get a read grant
 * only ([UriGrants.READ]); [VaultFileAccess.choose] forgets the key file when another vault is
 * chosen. [KeyFileAccessTest] pins each rule.
 */
class KeyFileAccess(
    private val grants: UriGrants,
    private val store: PrefsVaultStateStore,
    /** The app's deadline storage, so a read stops after 30 s. */
    private val storage: VaultStorage,
    private val io: CoroutineDispatcher,
    private val displayName: (Uri) -> String?,
) : KeyFiles {

    override fun current(vault: String): RememberedKeyFile? = store.keyFile(vault)

    /**
     * Takes a read grant for [uri] and checks its first 8 bytes for a KeePass signature
     * ([startsWithKeePassSignature]); the whole file is read only at unlock. A KeePass vault is
     * refused and its grant released, and the vault at [vault] is refused without a grant or a
     * read. Otherwise [uri] becomes the key file and the previous key file's grant is released. A
     * file that can't be read now is remembered too; the unlock reports why.
     */
    override suspend fun choose(vault: String, uri: Uri): KeyFileChoice = withContext(io) {
        // Releasing a read grant on the vault would remove read from its read and write grant.
        if (uri.toString() == vault) return@withContext KeyFileChoice.KeePassVault
        try {
            grants.take(uri, UriGrants.READ)
        } catch (e: SecurityException) {
            return@withContext KeyFileChoice.Failed
        }
        val previous = current(vault)
        if (storage.startsWithKeePassSignature(uri.toString())) {
            if (previous?.location != uri.toString()) grants.release(uri, UriGrants.READ)
            return@withContext KeyFileChoice.KeePassVault
        }
        if (previous != null && previous.location != uri.toString()) grants.release(previous.location.toUri(), UriGrants.READ)
        store.saveKeyFile(vault, uri.toString(), nameOrSegment(uri, displayName))
        KeyFileChoice.Chosen
    }

    override suspend fun remove(vault: String) = withContext(io) {
        val previous = current(vault) ?: return@withContext
        grants.release(previous.location.toUri(), UriGrants.READ)
        store.clearKeyFile()
    }

    override suspend fun read(vault: String): KeyFileRead {
        val keyFile = current(vault) ?: return KeyFileRead.None
        return storage.readKeyFile(keyFile.location)
    }

    override suspend fun readOnce(uri: Uri): KeyFileRead = storage.readKeyFile(uri.toString())

    override fun keyFileUnlock(vault: String): Boolean = store.keyFileUnlock(vault)

    override fun saveKeyFileUnlock(vault: String, used: Boolean) = store.saveKeyFileUnlock(vault, used)
}
