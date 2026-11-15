package org.onekash.kashpass.vault.save

import kotlinx.coroutines.flow.StateFlow
import org.onekash.kashpass.vault.doc.OpenedVault

/** Saves vaults by [SafeSaver]'s steps. The app depends on this, never on the implementation. */
interface VaultSaving {

    /** True while a save, retry or copy runs. */
    val isSaving: StateFlow<Boolean>

    /** Saves [vault] (the edited document with the session's baseline) to [location]. */
    suspend fun save(location: String, vault: OpenedVault): SaveResult

    /**
     * Writes [prepared]'s bytes again, from the re-read on, after a failure that left the file
     * unchanged.
     */
    suspend fun retry(prepared: PreparedSave): SaveResult

    /**
     * Writes [prepared]'s bytes into [copyLocation], a new file from the create-document picker,
     * and verifies them; [CopyResult.Refused] when the target holds bytes or can't be read.
     */
    suspend fun saveCopy(prepared: PreparedSave, copyLocation: String): CopyResult

    /**
     * Writes [backupBytes] (a backup, opened as [backupVault]) unchanged into [copyLocation], a new
     * file from the create-document picker, and verifies it with the backup's key. Refused without
     * writing when the header doesn't parse, its KDF settings are out of bounds, or the target
     * holds bytes or can't be read. This is the only write of a backup's bytes; none goes over
     * the vault file. [SafeSaverTest] pins it.
     */
    suspend fun saveBackupCopy(backupBytes: ByteArray, backupVault: OpenedVault, copyLocation: String): CopyResult
}
