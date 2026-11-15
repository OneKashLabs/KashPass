package org.onekash.kashpass.testing

import android.net.Uri
import org.onekash.kashpass.platform.KeyFileChoice
import org.onekash.kashpass.platform.KeyFiles
import org.onekash.kashpass.platform.RememberedKeyFile
import org.onekash.kashpass.vault.storage.KeyFileRead
import org.onekash.kashpass.vault.testing.TestVaults

/**
 * Shared fake of [KeyFiles]. Remembers one key file per vault location, as the real store does.
 * [read] returns a new copy of [content] each time, or [failure] when set; [choose] returns
 * [choice] and remembers the file only when that is [KeyFileChoice.Chosen]. [reads] counts reads
 * and [returned] keeps every array handed out, so a test can check each one was zero-filled.
 * [readOnce] reads [content] for any location, records it in [onceReads] and remembers nothing.
 * [saveKeyFileUnlock] keeps one mark per vault location, as the real store does.
 */
class FakeKeyFiles : KeyFiles {

    private val remembered = mutableMapOf<String, RememberedKeyFile>()

    /** The key file's bytes; [TestVaults.KEY_FILE] by default. */
    var content: ByteArray = TestVaults.KEY_FILE

    /** What [read] returns instead of the bytes, when set. */
    var failure: KeyFileRead? = null

    /** What [choose] returns. */
    var choice: KeyFileChoice = KeyFileChoice.Chosen

    var reads = 0
        private set

    val returned = mutableListOf<ByteArray>()

    /** Remembers [name] as [vault]'s key file without a pick. */
    fun set(vault: String, name: String = NAME) {
        remembered[vault] = RememberedKeyFile("content://fake/key/$name", name)
    }

    override fun current(vault: String): RememberedKeyFile? = remembered[vault]

    override suspend fun choose(vault: String, uri: Uri): KeyFileChoice {
        if (choice == KeyFileChoice.Chosen) remembered[vault] = RememberedKeyFile(uri.toString(), uri.lastPathSegment.orEmpty())
        return choice
    }

    override suspend fun remove(vault: String) {
        remembered.remove(vault)
    }

    override suspend fun read(vault: String): KeyFileRead {
        if (remembered[vault] == null) return KeyFileRead.None
        reads++
        failure?.let { return it }
        return KeyFileRead.Bytes(content.copyOf().also { returned += it })
    }

    /** Every location [readOnce] read, in order. */
    val onceReads = mutableListOf<String>()

    override suspend fun readOnce(uri: Uri): KeyFileRead {
        onceReads += uri.toString()
        reads++
        failure?.let { return it }
        return KeyFileRead.Bytes(content.copyOf().also { returned += it })
    }

    private val keyFileUnlocks = mutableSetOf<String>()

    override fun keyFileUnlock(vault: String): Boolean = vault in keyFileUnlocks

    override fun saveKeyFileUnlock(vault: String, used: Boolean) {
        if (used) keyFileUnlocks += vault else keyFileUnlocks -= vault
    }

    companion object {
        const val NAME = "vault.keyx"
    }
}
