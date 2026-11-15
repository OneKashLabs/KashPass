package org.onekash.kashpass.vault.testing

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.save.CopyResult
import org.onekash.kashpass.vault.save.PreparedSave
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.save.VaultSaving

/**
 * Shared fake of [VaultSaving] for app tests: records every call, answers with a scripted result
 * (by default a successful save), runs them one at a time as the real saver does, and can hold a
 * save in progress until [release].
 */
class FakeVaultSaver : VaultSaving {

    override val isSaving = MutableStateFlow(false)

    /** Every call, in order: "save", "retry", "copy" or "backupCopy", with the location. */
    val calls = mutableListOf<Pair<String, String>>()

    /** The vaults passed to [save], in order. */
    val saved = mutableListOf<OpenedVault>()

    /** The result of the next saves. */
    var result: (OpenedVault, PreparedSave) -> SaveResult = { vault, _ -> SaveResult.Saved(vault.withBaseline(OpenedVault.Baseline.Known("0".repeat(64)))) }

    /** The result of the next copies. */
    var copyResult: (String) -> CopyResult = { CopyResult.Saved("copy.kdbx") }

    private var gate: CompletableDeferred<Unit>? = null

    /** Makes the next saves suspend until [release]. */
    fun hold() {
        gate = CompletableDeferred()
    }

    /** Lets held saves finish. */
    fun release() {
        gate?.complete(Unit)
        gate = null
    }

    /** A prepared save for [vault], as a failed save hands out. */
    fun prepared(vault: OpenedVault, location: String = TestVaults.LOCATION) = PreparedSave(location, ByteArray(0), "", vault)

    override suspend fun save(location: String, vault: OpenedVault): SaveResult = run("save", location) {
        saved += vault
        result(vault, prepared(vault, location))
    }

    override suspend fun retry(prepared: PreparedSave): SaveResult = run("retry", prepared.location) { result(prepared.vault, prepared) }

    override suspend fun saveCopy(prepared: PreparedSave, copyLocation: String): CopyResult = run("copy", copyLocation) { copyResult(copyLocation) }

    override suspend fun saveBackupCopy(backupBytes: ByteArray, backupVault: OpenedVault, copyLocation: String): CopyResult =
        run("backupCopy", copyLocation) { copyResult(copyLocation) }

    // One at a time, as the real saver runs them; the next save starts after a held one ends.
    private val mutex = Mutex()

    private suspend fun <T> run(name: String, location: String, block: () -> T): T = mutex.withLock {
        calls += name to location
        isSaving.value = true
        try {
            gate?.await()
            block()
        } finally {
            isSaving.value = false
        }
    }
}
