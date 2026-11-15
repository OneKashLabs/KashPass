package org.onekash.kashpass.vault.save

import java.time.Duration
import java.time.Instant
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.backup.SaveMarkerStore
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.HeaderRead
import org.onekash.kashpass.vault.doc.KdfEngine
import org.onekash.kashpass.vault.doc.Encoded
import org.onekash.kashpass.vault.doc.KeyDerivation
import org.onekash.kashpass.vault.doc.NewestChange
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.SaveKeyCache
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.VaultKey
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.policy.KdfPolicy
import org.onekash.kashpass.vault.storage.ReadResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.VaultStateStore
import org.onekash.kashpass.vault.storage.VaultStorage
import org.onekash.kashpass.vault.storage.WriteResult
import org.onekash.kashpass.vault.storage.Writability
import org.onekash.kashpass.vault.storage.maxVaultBytes

/**
 * Saves a vault in these steps; a failed step stops the rest, and nothing reaches the file before
 * step 7:
 * 1. refuse a read-only vault or a location that isn't writable;
 * 2. encode the whole vault in memory with KashPass's own encoder ([VaultXmlCodec.encode]:
 *    fresh master seed, IV, KDF salt and inner stream key; the attachment pool rebuilt from the
 *    attachments the saved values name); the written header's KDF settings pass the policy
 *    before any derivation, and a refusal, a lack of memory or a failure ends the save here, as
 *    does an encoded file over the save caps ([fitsHeap]);
 * 3. parse the encoded header and check its KDF settings against the policy, so no save writes
 *    settings an open would refuse;
 * 4. re-read the file and compare its SHA-256 with the baseline: any difference is a conflict,
 *    and a provider that doesn't answer in time is [SaveResult.NotReachable];
 * 5. keep the re-read bytes as a backup;
 * 6. set the pending-save marker;
 * 7. write in one pass with mode "rwt", stopping to wait after [writeTimeout];
 * 8. read back, compare the SHA-256 with the encoded bytes, and decrypt with the session key,
 *    every hash checked; [save] reuses the key step 2 derived ([SaveKeyCache]), [retry]
 *    derives it again;
 * 9. clear the marker and keep the written bytes as a backup (best effort).
 *
 * An unexpected exception in any step ends the save as [SaveResult.UnexpectedError] and a copy as
 * [CopyResult.Failed]; a cancellation is rethrown.
 *
 * Saves run one at a time. A write the provider hasn't finished when the timeout passes keeps
 * running in [writers]; the result is classified by re-reading the file, the marker stays until
 * that write ends, and a later write to the same file waits for it first. [SafeSaverTest] pins
 * the order, each failure and each classification.
 */
class SafeSaver internal constructor(
    private val storage: VaultStorage,
    private val backups: BackupStore,
    private val markers: SaveMarkerStore,
    private val state: VaultStateStore,
    private val io: CoroutineDispatcher,
    /**
     * Runs provider writes; they outlive a save that stopped waiting for them. Never the global
     * scope.
     */
    private val writers: CoroutineScope,
    private val writeTimeout: Duration = Duration.ofSeconds(30),
    private val maxHeapBytes: () -> Long = { Runtime.getRuntime().maxMemory() },
    /** Derives keys; [save] wraps it in a [SaveKeyCache] for the length of the call. */
    private val kdf: KeyDerivation = KdfEngine(),
    private val encode: (VaultDocument, KeyDerivation) -> Encoded = { document, keys -> VaultXmlCodec.encode(document, derive = keys) },
    private val readBack: (ByteArray, VaultKey, VaultXmlCodec.Limits, KeyDerivation) -> Boolean =
        { b, c, l, k -> VaultXmlCodec.readBack(b, c, l, k, maxHeapBytes()) },
    private val now: () -> Instant = Instant::now,
) : VaultSaving {

    private val mutex = Mutex()
    private val saving = MutableStateFlow(false)
    private val inFlight = HashMap<String, Deferred<WriteResult>>()

    override val isSaving: StateFlow<Boolean> = saving.asStateFlow()

    override suspend fun save(location: String, vault: OpenedVault): SaveResult = serialized {
        val progress = Progress(vault)
        // One derivation per save: the read-back of the written bytes reuses the encode's key.
        // Retry and the copies derive through [kdf], so no derived key outlives a call.
        SaveKeyCache(kdf).use { keys -> guarded(progress) { saveSteps(location, vault, progress, keys) } }
    }

    private suspend fun saveSteps(location: String, vault: OpenedVault, progress: Progress, keys: KeyDerivation): SaveResult {
        (vault.saveability as? Saveability.ReadOnly)?.let { return SaveResult.ReadOnly(vault, it) }
        val writable = storage.writability(location)
        // A provider that doesn't answer in time can answer on Retry, which needs the bytes.
        if (writable != Writability.WRITABLE && writable != Writability.TIMED_OUT) return SaveResult.NotWritable(vault, writable)
        val encoded = try {
            encode(vault.document, keys)
        } catch (e: OutOfMemoryError) {
            return SaveResult.NotEnoughMemory(vault)
        }
        val bytes = when (encoded) {
            is Encoded.Bytes -> encoded.bytes
            is Encoded.Refused -> return SaveResult.KdfRefused(vault, encoded.rejection)
            Encoded.NotEnoughMemory -> return SaveResult.NotEnoughMemory(vault)
            Encoded.Failed -> return SaveResult.UnexpectedError(vault, null)
        }
        if (!fitsHeap(encoded.xmlBytes, encoded.payloadBytes, bytes.size)) return SaveResult.NotEnoughMemory(vault)
        val settings = when (val read = encodedHeader(bytes)) {
            is HeaderRead.Valid -> read.header.kdf
            is HeaderRead.Invalid -> return if (read.result == Decoded.NotEnoughMemory) SaveResult.NotEnoughMemory(vault) else SaveResult.KdfRefused(vault, null)
        }
        KdfPolicy.checkBounds(settings)?.let { return SaveResult.KdfRefused(vault, it) }
        val baseline = (vault.baseline as? OpenedVault.Baseline.Known)?.sha256
        val prepared = PreparedSave(location, bytes, Sha256.hex(bytes), vault).also { progress.prepared = it }
        if (writable == Writability.TIMED_OUT) return SaveResult.NotReachable(vault, prepared)
        // An unknown baseline can never match, so the save stops as a conflict.
        return write(prepared, expected = baseline ?: UNKNOWN, progress, keys)
    }

    override suspend fun retry(prepared: PreparedSave): SaveResult = serialized {
        val progress = Progress(prepared.vault, prepared)
        val baseline = (prepared.vault.baseline as? OpenedVault.Baseline.Known)?.sha256
        guarded(progress) { write(prepared, expected = baseline ?: UNKNOWN, progress, kdf) }
    }

    override suspend fun saveCopy(prepared: PreparedSave, copyLocation: String): CopyResult = serialized {
        copyGuarded(copyLocation) { saveCopyNow(prepared, copyLocation) }
    }

    // Writes [prepared]'s bytes to [copyLocation] in one pass, then reads them back and decrypts
    // them with [prepared]'s key; the vault file, its backups and its marker are not touched.
    // A copy never replaces bytes: the target must read back empty, as a new document does.
    private suspend fun saveCopyNow(prepared: PreparedSave, copyLocation: String): CopyResult {
        val target = readRemote(copyLocation)
        if (target !is Remote.Read || target.bytes.isNotEmpty()) return CopyResult.Refused(copyLocation)
        if (!earlierWriteEnded(copyLocation)) return CopyResult.Failed(copyLocation)
        val result = writeWaiting(copyLocation, prepared.bytes)
        val verified = result is Write.Done && result.result == WriteResult.Written && verify(copyLocation, prepared, kdf)
        return if (verified) CopyResult.Saved(storage.metadata(copyLocation).displayName) else CopyResult.Failed(copyLocation)
    }

    override suspend fun saveBackupCopy(backupBytes: ByteArray, backupVault: OpenedVault, copyLocation: String): CopyResult = serialized {
        copyGuarded(copyLocation) {
            // The backup is written as it is, so its document's sizes are the file's.
            val document = backupVault.document
            if (!fitsHeap(document.xmlBytes, VaultXmlCodec.payloadBytes(document), backupBytes.size)) return@serialized CopyResult.Refused(copyLocation)
            val kdf = (encodedHeader(backupBytes) as? HeaderRead.Valid)?.header?.kdf ?: return@serialized CopyResult.Refused(copyLocation)
            if (KdfPolicy.checkBounds(kdf) != null) return@serialized CopyResult.Refused(copyLocation)
            saveCopyNow(PreparedSave(copyLocation, backupBytes, Sha256.hex(backupBytes), backupVault), copyLocation)
        }
    }

    // What a save reached, so an unexpected exception is reported with the encoded bytes and the
    // baseline the file state allows.
    private class Progress(val vault: OpenedVault, var prepared: PreparedSave? = null) {
        var writeStarted = false
    }

    // Turns an unexpected exception from [steps] into [SaveResult.UnexpectedError]: the baseline
    // stays known until the write starts, and is unknown after.
    private inline fun guarded(progress: Progress, steps: () -> SaveResult): SaveResult = try {
        steps()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        val vault = if (progress.writeStarted) progress.vault.withBaseline(OpenedVault.Baseline.Unknown) else progress.vault
        SaveResult.UnexpectedError(vault, progress.prepared)
    }

    // An unexpected exception from [steps] is a failed copy: the target can hold part of one.
    private inline fun copyGuarded(copyLocation: String, steps: () -> CopyResult): CopyResult = try {
        steps()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        CopyResult.Failed(copyLocation)
    }

    private suspend fun <T> serialized(block: suspend () -> T): T = mutex.withLock {
        saving.value = true
        try {
            withContext(io) { block() }
        } finally {
            saving.value = false
        }
    }

    /**
     * Steps 4 to 9 for [prepared]. [expected] is the SHA-256 the file must have; [progress]
     * records the start of the write; [keys] derives the key for the read-back.
     */
    private suspend fun write(prepared: PreparedSave, expected: String, progress: Progress, keys: KeyDerivation): SaveResult {
        val vault = prepared.vault
        val location = prepared.location
        // Before anything else, so an unfinished earlier write keeps its marker and its file.
        if (!earlierWriteEnded(location)) return SaveResult.WriterStillRunning(vault, prepared)
        val read = readRemote(location)
        if (read is Remote.TimedOut) return SaveResult.NotReachable(vault, prepared)
        val remote = (read as? Remote.Read)?.bytes
        if (remote == null || Sha256.hex(remote) != expected) return SaveResult.Conflict(vault, prepared)
        if (backups.add(location, remote, BackupKind.BEFORE_SAVE) == BackupResult.Failed) {
            return SaveResult.BackupFailed(vault, prepared)
        }
        // A marker an earlier unverified save left stays if this write changes nothing: the file
        // is as damaged as before, and the marker keeps its backups from being trimmed.
        val earlier = markers.get(location)
        val unmark = { if (earlier == null) markers.clear(location) else markers.set(location, earlier.oldSha256, earlier.newSha256) }
        markers.set(location, expected, prepared.sha256)
        progress.writeStarted = true
        val written = writeWaiting(location, prepared.bytes)
        val unknown = vault.withBaseline(OpenedVault.Baseline.Unknown)
        return when {
            written is Write.Done && written.result == WriteResult.Written -> verified(prepared, keys)
            written is Write.Done && written.result is WriteResult.Failed && !written.result.afterOpen -> {
                unmark()
                SaveResult.WriteFailed(vault, prepared)
            }
            // Failed after opening, or running past the timeout: re-read the file to classify it.
            else -> when (current(location)) {
                prepared.sha256 -> verified(prepared, keys)
                expected -> {
                    if (inFlight[location]?.isActive != true) unmark()
                    SaveResult.NotSavedUnchanged(vault, prepared)
                }
                else -> SaveResult.MaybeDamaged(unknown, prepared)
            }
        }
    }

    // Steps 8 and 9; on failure the baseline becomes unknown and the marker stays.
    private suspend fun verified(prepared: PreparedSave, keys: KeyDerivation): SaveResult {
        val vault = prepared.vault
        if (!verify(prepared.location, prepared, keys)) return SaveResult.VerifyFailed(vault.withBaseline(OpenedVault.Baseline.Unknown), prepared)
        if (inFlight[prepared.location]?.isActive != true) markers.clear(prepared.location)
        // The file holds this document, so its newest change is the one to compare a
        // later open with, even when it is earlier than before (an UNDO restores old times).
        NewestChange.of(vault.document, now())?.let { state.saveNewestSeen(prepared.location, it) }
        // Best effort, unlike the backup before the write: the save already succeeded.
        try {
            backups.add(prepared.location, prepared.bytes, BackupKind.SAVED)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // The file holds the save; only the offline copy is one save behind.
        }
        return SaveResult.Saved(vault.withBaseline(OpenedVault.Baseline.Known(prepared.sha256)))
    }

    // True when [location] holds [prepared]'s bytes and KashPass's own decoder opens them with the
    // vault's key, derived by [keys]; the decode checks the header hash and HMAC, every block HMAC,
    // the decryption and the XML.
    private suspend fun verify(location: String, prepared: PreparedSave, keys: KeyDerivation): Boolean {
        val back = readFile(location) ?: return false
        if (Sha256.hex(back) != prepared.sha256) return false
        return try {
            readBack(back, prepared.vault.document.credentials, VaultXmlCodec.Limits.forHeap(maxHeapBytes()), keys)
        } catch (e: CancellationException) {
            throw e
        } catch (e: OutOfMemoryError) {
            false
        } catch (e: Exception) {
            false
        }
    }

    private sealed interface Remote {
        class Read(val bytes: ByteArray) : Remote
        data object TimedOut : Remote
        data object Unreadable : Remote
    }

    // A provider can throw anything across the binder, and a large file can exhaust the heap;
    // either is an unreadable file here, as in the opener.
    private suspend fun readRemote(location: String): Remote = try {
        when (val read = storage.readFresh(location, maxVaultBytes(maxHeapBytes()))) {
            is ReadResult.Bytes -> Remote.Read(read.bytes)
            is ReadResult.Failed -> if (read.cause == StorageFailure.TIMED_OUT) Remote.TimedOut else Remote.Unreadable
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: OutOfMemoryError) {
        Remote.Unreadable
    } catch (e: Exception) {
        Remote.Unreadable
    }

    private suspend fun readFile(location: String): ByteArray? = (readRemote(location) as? Remote.Read)?.bytes

    private suspend fun current(location: String): String? = readFile(location)?.let(Sha256::hex)

    private sealed interface Write {
        data class Done(val result: WriteResult) : Write
        data object TimedOut : Write
    }

    // Waits at most [writeTimeout] for a write to [location] that an earlier save stopped waiting
    // for.
    private suspend fun earlierWriteEnded(location: String): Boolean {
        val earlier = inFlight[location]?.takeIf { it.isActive } ?: return true
        return withTimeoutOrNull(writeTimeout.toMillis()) { earlier.await() } != null
    }

    /** Starts the write in [writers] and waits at most [writeTimeout] for it. */
    private suspend fun writeWaiting(location: String, bytes: ByteArray): Write {
        val job = writers.async(io) { storage.write(location, bytes) }
        inFlight[location] = job
        return withTimeoutOrNull(writeTimeout.toMillis()) { job.await() }?.let(Write::Done) ?: Write.TimedOut
    }

    // The header of [bytes] read within this heap's budget; an OutOfMemoryError is
    // Invalid(NotEnoughMemory), as in the opener.
    private fun encodedHeader(bytes: ByteArray): HeaderRead = try {
        VaultXmlCodec.header(bytes, maxHeapBytes())
    } catch (e: OutOfMemoryError) {
        HeaderRead.Invalid(Decoded.NotEnoughMemory)
    }

    // The save caps for this heap: a file with [xmlBytes] of XML, a decompressed payload of
    // [payloadBytes] and [fileBytes] in all is written only if this heap holds the open document,
    // the file and its read-back together. Each cap is at most the read-back's own limit
    // ([VaultXmlCodec.Limits], [maxVaultBytes]). The read-back also inflates inline attachment
    // values stored compressed (a Binary Value with Compressed="True" and no Ref) from the same
    // decompression limit, which this check does not count, so a vault with such values near
    // that limit can pass here and fail its read-back. An OutOfMemoryError in the read-back is a
    // failed verification.
    private fun fitsHeap(xmlBytes: Long, payloadBytes: Long, fileBytes: Int): Boolean {
        val heap = maxHeapBytes()
        val limits = VaultXmlCodec.Limits.forHeap(heap)
        return xmlBytes <= limits.save && payloadBytes <= limits.payloadSave && fileBytes <= maxVaultBytes(heap)
    }

    companion object {
        // Never a real SHA-256 (not hex), so an unknown baseline always reads as changed.
        private const val UNKNOWN = "unknown"

        /** Builds the production saver; [writers] must outlive screens (the app's scope). */
        fun create(
            storage: VaultStorage,
            backups: BackupStore,
            markers: SaveMarkerStore,
            state: VaultStateStore,
            io: CoroutineDispatcher,
            writers: CoroutineScope,
        ): VaultSaving = SafeSaver(storage, backups, markers, state, io, writers)
    }
}
