package org.onekash.kashpass.testing

import android.net.Uri
import kotlinx.coroutines.CompletableDeferred
import org.onekash.kashpass.platform.ChooseResult
import org.onekash.kashpass.platform.RememberedVault
import org.onekash.kashpass.platform.VaultFiles

/**
 * Shared fake of [VaultFiles]. [choose] remembers the file as "picked.kdbx" unless [failChoose],
 * after [gate] completes when set. [takeOffered] answers [offeredWritable] and records the file in
 * [taken]; [releaseOffered] records it in [released] unless it is the remembered vault, whose
 * grant the real one keeps. Names come from [names], else the last path segment, after the
 * file's entry in [nameGates] completes when there is one.
 */
class FakeVaultFiles : VaultFiles {
    var vault: RememberedVault? = null
    var failChoose = false
    var gate: CompletableDeferred<Unit>? = null
    val chosen = mutableListOf<Uri>()

    /** What [takeOffered] answers. */
    var offeredWritable = false
    val taken = mutableListOf<Uri>()
    val released = mutableListOf<Uri>()
    val names = mutableMapOf<String, String>()
    val nameGates = mutableMapOf<String, CompletableDeferred<Unit>>()

    override fun current() = vault

    override suspend fun choose(uri: Uri): ChooseResult {
        gate?.await()
        if (failChoose) return ChooseResult.Failed
        chosen += uri
        vault = RememberedVault(uri.toString(), "picked.kdbx")
        return ChooseResult.Chosen
    }

    override suspend fun takeOffered(uri: Uri): Boolean {
        taken += uri
        return offeredWritable
    }

    override suspend fun releaseOffered(uri: Uri) {
        if (uri.toString() != vault?.location) released += uri
    }

    override suspend fun displayName(uri: Uri): String {
        nameGates[uri.toString()]?.await()
        return names[uri.toString()] ?: uri.lastPathSegment.orEmpty()
    }
}
