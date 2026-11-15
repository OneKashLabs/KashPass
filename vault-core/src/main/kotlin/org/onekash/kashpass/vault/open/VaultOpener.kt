package org.onekash.kashpass.vault.open

import java.time.Instant
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.backup.SaveMarkerStore
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.doc.CheckedHeader
import org.onekash.kashpass.vault.doc.DecodeFailure
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.HeaderRead
import org.onekash.kashpass.vault.doc.KeyFile
import org.onekash.kashpass.vault.doc.KeyFileResult
import org.onekash.kashpass.vault.doc.NewestChange
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.doc.VaultKey
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.policy.KdfPolicy
import org.onekash.kashpass.vault.storage.ReadResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.VaultStateStore
import org.onekash.kashpass.vault.storage.VaultStorage
import org.onekash.kashpass.vault.storage.maxVaultBytes

/**
 * Opens vaults with every check in order: one read, one header read ([VaultXmlCodec.header]),
 * KDF bounds, downgrade against the last unlock, the work-factor check ([KdfPolicy.slowness],
 * derived only once the user accepts settings that take far longer), and only then key derivation
 * on the same bytes with the same header: the settings checked, compared and stored as the
 * baseline are the ones the key is derived with. The XML is read by
 * [VaultXmlCodec], which keeps it exactly as written so a save changes only what was edited.
 *
 * Each call that takes a [FileAccess] picks its stores from it ([storesFor]). [backups],
 * [dismissWeakWarning] and [acceptNewest] take no access and always use the real stores; the app
 * never calls them for a session-only vault.
 *
 * Every successful open of the file keeps its bytes as a backup. Backups open read-only through
 * the same checks except the downgrade comparison: they are copies KashPass kept, and opening one
 * never changes the remembered settings. The work check compares them with the file's
 * remembered settings: a copy that takes far longer to unlock than the file derives only after
 * the user accepts those settings.
 *
 * [check], [open], [openWithKey] and [reopen] add the last good copy ([lastGoodCopy]) to a
 * Damaged or Unreadable result (not to one that is too large) and to a NotEnoughMemory result of
 * the header checks (not of the read or the decryption); [NoBackups] has none to add.
 * [VaultOpenerTest], [ReloadTest], [BackupOpeningTest] and [LastGoodCopyTest] pin each step.
 */
class VaultOpener internal constructor(
    private val storage: VaultStorage,
    state: VaultStateStore,
    private val io: CoroutineDispatcher,
    private val maxHeapBytes: () -> Long = { Runtime.getRuntime().maxMemory() },
    private val now: () -> Instant = Instant::now,
    backups: BackupStore = NoBackups,
    markers: SaveMarkerStore = NoMarkers,
    private val readHeader: (ByteArray, Long) -> HeaderRead = VaultXmlCodec::header,
    private val decode: (ByteArray, CheckedHeader, VaultKey, VaultXmlCodec.Budget) -> Decoded,
) : VaultOpening {

    /** The stores one call reads and writes. */
    private class Stores(val state: VaultStateStore, val backups: BackupStore, val markers: SaveMarkerStore)

    // The real stores, reached only through [storesFor] and the calls that take no access.
    private val kept = Stores(state, backups, markers)

    /**
     * Returns the stores for [access]. A [FileAccess.SESSION_ONLY] open gets [NoState],
     * [NoBackups] and [NoMarkers], so no KDF baseline, weak-warning dismissal, newest change,
     * backup or save marker is read or written for it, and it has no last good copy. Every other
     * access gets the real stores.
     */
    private fun storesFor(access: FileAccess): Stores = if (access == FileAccess.SESSION_ONLY) KEEP_NOTHING else kept

    override suspend fun check(location: String, access: FileAccess): OpenResult = withContext(io) {
        val stores = storesFor(access)
        when (val read = readAndCheck(location, stores.state)) {
            is Checked.Fail -> withLastCopy(location, read, read.result, stores)
            is Checked.Ok -> OpenResult.Ready(
                read.header.kdf,
                KdfPolicy.isWeak(read.header.kdf),
                KdfPolicy.slowness(stores.state.kdfBaseline(location), read.header.kdf),
                lostCutOffSave = settleCutOffMarker(location, read, stores.markers),
            )
        }
    }

    // Applies the marker rule of [VaultOpening.check] and returns lostCutOffSave. Other bytes keep
    // the marker, so [lastGoodCopy] puts its old copy first if the file then fails to decrypt.
    private fun settleCutOffMarker(location: String, read: Checked.Ok, markers: SaveMarkerStore): Boolean {
        val marker = markers.get(location) ?: return false
        if (read.sha256 == marker.newSha256 || read.sha256 == marker.oldSha256) markers.clear(location)
        return read.sha256 != marker.newSha256
    }

    override suspend fun open(location: String, password: CharArray, acceptedSlow: KdfSettings?, keyFile: ByteArray?, access: FileAccess): OpenResult = try {
        withKeyPart(keyFile) { part -> openWith(location, acceptedSlow, attempts(password, part), access) }
    } finally {
        password.fill('\u0000')
        keyFile?.fill(0)
    }

    /**
     * [key] is the 32-byte passphrase hash a password session hands out ([VaultSession.unlockKey]):
     * the password part of the composite key, followed by the key file's part when the vault has
     * one. A key of another length can't have come from a session and is a wrong password, after
     * the key file is read as [open] reads it.
     */
    override suspend fun openWithKey(location: String, key: ByteArray, acceptedSlow: KdfSettings?, keyFile: ByteArray?, access: FileAccess): OpenResult = try {
        withKeyPart(keyFile) { part ->
            if (key.size != VaultKey.HASH_BYTES) return@withKeyPart OpenResult.WrongPassword
            val origin = if (part == null) UnlockOrigin.STORED_KEY else UnlockOrigin.STORED_KEY_AND_KEY_FILE
            openWith(location, acceptedSlow, listOf(Attempt(origin) { VaultKey.passwordHash(key, part) }), access)
        }
    } finally {
        key.fill(0)
        keyFile?.fill(0)
    }

    /** The key, built only when the checks pass, and what it was built from. */
    private class Attempt(val origin: UnlockOrigin, val credentials: () -> VaultKey)

    // Parses [keyFile] on [io] (hashing a large file takes time), with this heap's XML limit, and
    // zero-fills the part after [block]. A key file that can't be read stops here.
    private suspend fun withKeyPart(keyFile: ByteArray?, block: suspend (ByteArray?) -> OpenResult): OpenResult = withContext(io) {
        if (keyFile == null) return@withContext block(null)
        val part = when (val parsed = KeyFile.parse(keyFile, KeyFile.maxXmlBytes(maxHeapBytes()))) {
            KeyFileResult.Damaged -> return@withContext OpenResult.KeyFileDamaged
            KeyFileResult.NotEnoughMemory -> return@withContext OpenResult.KeyFileTooLarge
            is KeyFileResult.Key -> parsed.part
        }
        try {
            block(part)
        } finally {
            part.fill(0)
        }
    }

    // The ways [password] and the key file's [part] unlock a vault, tried in order.
    private fun attempts(password: CharArray, part: ByteArray?): List<Attempt> = when {
        part == null -> listOf(Attempt(UnlockOrigin.PASSWORD) { VaultKey.password(password) })
        password.isNotEmpty() -> listOf(Attempt(UnlockOrigin.PASSWORD_AND_KEY_FILE) { VaultKey.password(password, part) })
        // A key-file-only vault is built without a password or with an empty one; both are tried.
        else -> listOf(
            Attempt(UnlockOrigin.KEY_FILE_ONLY) { VaultKey.keyFile(part) },
            Attempt(UnlockOrigin.KEY_FILE_ONLY) { VaultKey.password(CharArray(0), part) },
        )
    }

    // One read, every check, then the derivation with each of [attempts] in turn until one
    // isn't a wrong password.
    private suspend fun openWith(location: String, acceptedSlow: KdfSettings?, attempts: List<Attempt>, access: FileAccess): OpenResult = withContext(io) {
        val stores = storesFor(access)
        when (val read = readAndCheck(location, stores.state)) {
            is Checked.Fail -> withLastCopy(location, read, read.result, stores)
            is Checked.Ok -> tooSlow(location, read, acceptedSlow, stores.state) ?: when (val opened = unlockFirst(location, read, attempts, backup = null, access)) {
                // The file decrypted and verified, so a cut-off save needs no last copy.
                is OpenResult.Unlocked -> opened.also { stores.markers.clear(location) }
                else -> withLastCopy(location, read, opened, stores, headerChecked = true)
            }
        }
    }

    override suspend fun dismissWeakWarning(location: String, kdf: KdfSettings) = withContext(io) {
        kept.state.saveWeakWarningDismissed(location, kdf)
    }

    override suspend fun refresh(location: String, session: VaultSession): RefreshResult = withContext(io) {
        val credentials = session.opened.document.credentials
        val baseline = (session.opened.baseline as? OpenedVault.Baseline.Known)?.sha256
        val access = session.opened.access
        val origin = session.opened.origin
        val stores = storesFor(access)
        val read = readAndCheck(location, stores.state)
        checkOpen(session)
        when (read) {
            is Checked.Fail -> RefreshResult.Failed(read.result)
            is Checked.Ok -> if (baseline != null && read.sha256 == baseline) {
                RefreshResult.Unchanged
            } else {
                val slow = tooSlow(location, read, accepted = null, stores.state)
                if (slow != null) return@withContext RefreshResult.Failed(slow)
                when (val opened = unlock(location, read, credentials, origin, backup = null, access)) {
                    is OpenResult.Unlocked -> RefreshResult.Reloaded(opened)
                    else -> RefreshResult.Failed(opened)
                }
            }
        }
    }

    override suspend fun reopen(location: String, session: VaultSession): OpenResult = withContext(io) {
        val credentials = session.opened.document.credentials
        val access = session.opened.access
        val origin = session.opened.origin
        val stores = storesFor(access)
        val read = readAndCheck(location, stores.state)
        checkOpen(session)
        when (read) {
            is Checked.Fail -> withLastCopy(location, read, read.result, stores)
            is Checked.Ok -> tooSlow(location, read, accepted = null, stores.state)
                ?: withLastCopy(location, read, unlock(location, read, credentials, origin, backup = null, access), stores, headerChecked = true)
        }
    }

    // A lock during the file read released [session]: stop before any key derivation, decryption,
    // state write or backup, with the exception VaultSession.opened gives for a released session.
    // VaultOpenerTest's 'stops refresh/reopen before any key derivation' tests pin it.
    private fun checkOpen(session: VaultSession) = check(session.isOpen) { "session released" }

    override suspend fun acceptNewest(location: String, time: Instant) = withContext(io) { kept.state.saveNewestSeen(location, time) }

    override suspend fun backups(location: String): List<BackupInfo> = withContext(io) { kept.backups.list(location) }

    override suspend fun openBackup(
        location: String,
        backup: BackupInfo,
        password: CharArray,
        lastCopy: LastCopyReason?,
        acceptedSlow: KdfSettings?,
        keyFile: ByteArray?,
        access: FileAccess,
    ): OpenResult = try {
        withKeyPart(keyFile) { part -> openBackupWith(location, backup, attempts(password, part), lastCopy, acceptedSlow, access) }
    } finally {
        password.fill('\u0000')
        keyFile?.fill(0)
    }

    // A backup opened from a last copy stays a last copy, so its banner keeps the same buttons.
    override suspend fun openBackup(location: String, backup: BackupInfo, session: VaultSession): OpenResult = withContext(io) {
        // One read of the session; the attempt keeps the key, not the document.
        val opened = session.opened
        val lastCopy = when ((opened.saveability as? Saveability.ReadOnly)?.reason) {
            ReadOnlyReason.LAST_COPY -> LastCopyReason.UNAVAILABLE
            ReadOnlyReason.LAST_COPY_CORRUPTED -> LastCopyReason.CORRUPTED
            ReadOnlyReason.LAST_COPY_CORRUPTED_AFTER_HEADER -> LastCopyReason.CORRUPTED_AFTER_HEADER
            else -> null
        }
        val credentials = opened.document.credentials
        val attempt = Attempt(opened.origin) { credentials }
        openBackupWith(location, backup, listOf(attempt), lastCopy, acceptedSlow = null, opened.access)
    }

    private suspend fun openBackupWith(
        location: String,
        backup: BackupInfo,
        attempts: List<Attempt>,
        lastCopy: LastCopyReason?,
        acceptedSlow: KdfSettings?,
        access: FileAccess,
    ): OpenResult {
        val stores = storesFor(access)
        val bytes = stores.backups.read(location, backup.id) ?: return OpenResult.Unreadable(StorageFailure.NOT_FOUND)
        // Phone storage can fail too; a changed backup is never decrypted or returned as the vault.
        if (Sha256.hex(bytes) != backup.sha256) return OpenResult.BackupDamaged
        val reason = when (lastCopy) {
            null -> ReadOnlyReason.BACKUP
            LastCopyReason.UNAVAILABLE -> ReadOnlyReason.LAST_COPY
            LastCopyReason.CORRUPTED -> ReadOnlyReason.LAST_COPY_CORRUPTED
            LastCopyReason.CORRUPTED_AFTER_HEADER -> ReadOnlyReason.LAST_COPY_CORRUPTED_AFTER_HEADER
        }
        // The bounds apply; the downgrade comparison against the live file's baseline doesn't.
        return when (val checked = checkBytes(bytes, baseline = null)) {
            is Checked.Fail -> checked.result
            is Checked.Ok -> tooSlow(location, checked, acceptedSlow, stores.state)
                ?: unlockFirst(location, checked, attempts, Backup(backup, reason), access)
        }
    }

    private class Backup(val info: BackupInfo, val reason: ReadOnlyReason)

    // Before any derivation: a file whose work jumped (KdfPolicy.slowness against the remembered
    // settings) derives only once the user accepted those exact settings.
    private fun tooSlow(location: String, checked: Checked.Ok, accepted: KdfSettings?, state: VaultStateStore): OpenResult.TooSlow? {
        val slow = KdfPolicy.slowness(state.kdfBaseline(location), checked.header.kdf) ?: return null
        return if (slow.kdf == accepted) null else OpenResult.TooSlow(slow)
    }

    private suspend fun unlockFirst(location: String, checked: Checked.Ok, attempts: List<Attempt>, backup: Backup?, access: FileAccess): OpenResult {
        var result: OpenResult = OpenResult.WrongPassword
        for (attempt in attempts) {
            result = unlock(location, checked, attempt.credentials(), attempt.origin, backup, access)
            if (result != OpenResult.WrongPassword) break
        }
        return result
    }

    private suspend fun unlock(
        location: String,
        checked: Checked.Ok,
        credentials: VaultKey,
        origin: UnlockOrigin,
        backup: Backup?,
        access: FileAccess,
    ): OpenResult {
        val kdf = checked.header.kdf
        // A lock can cancel the attempt; don't spend the key derivation on a discarded result.
        val context = currentCoroutineContext()
        context.ensureActive()
        // A cancel during the key derivation stops it ([VaultXmlCodec.Budget.cancelled]).
        val budget = VaultXmlCodec.Budget(VaultXmlCodec.Limits.forHeap(maxHeapBytes()), maxVaultBytes(maxHeapBytes()), maxHeapBytes()) { !context.isActive }
        val decoded = try {
            decode(checked.bytes, checked.header, credentials, budget)
        } catch (e: CancellationException) {
            throw e
        } catch (e: OutOfMemoryError) {
            return OpenResult.NotEnoughMemory()
        } catch (e: Throwable) {
            return OpenResult.Failed(DecodeFailure.INTERNAL)
        }
        val opened = decoded as? Decoded.Opened ?: return failure(decoded)
        val document = when {
            backup != null -> opened.document.readOnly(backup.reason)
            access == FileAccess.PROVIDER_READ_ONLY -> opened.document.readOnly(ReadOnlyReason.PROVIDER_READ_ONLY)
            access == FileAccess.SESSION_ONLY -> opened.document.readOnly(ReadOnlyReason.OPENED_FROM_APP)
            else -> opened.document
        }
        currentCoroutineContext().ensureActive()
        val baseline = OpenedVault.Baseline.Known(checked.sha256)
        val session = VaultSession.from(OpenedVault(document, baseline, checked.bytes.size.toLong(), now(), origin, access))
        if (backup != null) return OpenResult.Unlocked(session, kdf, showWeakWarning = false, backup = backup.info, bytesAfterEnd = opened.bytesAfterEnd)
        val stores = storesFor(access)
        val state = stores.state
        val showWarning = KdfPolicy.isWeak(kdf) && state.weakWarningDismissedFor(location) != kdf
        // An older file than one seen before is reported, never recorded as the newest.
        val fileNewest = NewestChange.of(document, now())
        val seen = state.newestSeen(location)
        val olderThan = seen?.takeIf { fileNewest != null && fileNewest.isBefore(it) }
        if (fileNewest != null && (seen == null || fileNewest.isAfter(seen))) state.saveNewestSeen(location, fileNewest)
        // Last, so every earlier failure leaves the baseline as it was.
        state.saveKdfBaseline(location, kdf)
        // A backup that can't be kept doesn't block reading; only a save stops on it.
        try {
            stores.backups.add(location, checked.bytes, BackupKind.OPENED)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Not reported: the unlock succeeded.
        }
        return OpenResult.Unlocked(session, kdf, showWarning, olderThan = olderThan, fileNewest = fileNewest, bytesAfterEnd = opened.bytesAfterEnd)
    }

    // Maps a decode that did not open to the result the opener reports.
    private fun failure(decoded: Decoded): OpenResult = when (decoded) {
        is Decoded.Opened -> OpenResult.Failed(DecodeFailure.INTERNAL)
        Decoded.WrongKey -> OpenResult.WrongPassword
        is Decoded.Damaged -> OpenResult.Damaged(decoded.reason)
        is Decoded.Unsupported -> OpenResult.Unsupported(decoded.reason)
        is Decoded.Refused -> OpenResult.Refused(decoded.rejection)
        is Decoded.TooLarge -> OpenResult.Unreadable(StorageFailure.TOO_LARGE)
        Decoded.NotEnoughMemory -> OpenResult.NotEnoughMemory()
        is Decoded.Failed -> OpenResult.Failed(decoded.cause)
    }

    // Adds the last good copy to a Damaged or Unreadable result (not to one that is too large),
    // and to NotEnoughMemory when the header checks of the bytes read gave it. [headerChecked] is
    // true for a result of the decryption, which runs after those checks passed. [read] is the
    // read whose bytes were checked; its sha256 is null when nothing was read.
    private suspend fun withLastCopy(location: String, read: Checked, result: OpenResult, stores: Stores, headerChecked: Boolean = false): OpenResult = when {
        result is OpenResult.Damaged -> result.copy(lastCopy = lastGoodCopy(location, read.sha256, stores))
        result is OpenResult.Unreadable && result.cause != StorageFailure.TOO_LARGE -> result.copy(lastCopy = lastGoodCopy(location, null, stores))
        result is OpenResult.NotEnoughMemory && !headerChecked && read.sha256 != null -> result.copy(lastCopy = lastGoodCopy(location, read.sha256, stores))
        else -> result
    }

    /**
     * Returns the backup to open in place of the file. Copies known to decrypt come first (an
     * unlock or a save kept them, or one of those has the same SHA-256); among them the copy a
     * cut-off save replaced (the pending marker's old bytes) leads, then newest first. A copy
     * kept only before a save holds whatever the file held and comes last. Skips a candidate
     * that holds the file's own bytes ([currentSha256]), whose bytes don't hash to its recorded
     * SHA-256, or whose header fails [checkBytes].
     */
    private suspend fun lastGoodCopy(location: String, currentSha256: String?, stores: Stores): BackupInfo? {
        val all = stores.backups.list(location)
        val decrypted = all.filter { it.kind != BackupKind.BEFORE_SAVE }.mapTo(HashSet()) { it.sha256 }
        val replaced = stores.markers.get(location)?.oldSha256
        val ordered = all.sortedBy {
            when {
                it.sha256 !in decrypted -> 2
                it.sha256 == replaced -> 0
                else -> 1
            }
        }
        return ordered.firstOrNull { it.sha256 != currentSha256 && isGood(location, it, stores.backups) }
    }

    private suspend fun isGood(location: String, backup: BackupInfo, backups: BackupStore): Boolean {
        val bytes = backups.read(location, backup.id) ?: return false
        return Sha256.hex(bytes) == backup.sha256 && checkBytes(bytes, baseline = null) is Checked.Ok
    }

    private sealed interface Checked {
        /** The hash of the bytes read, computed once on first use; null when nothing was read. */
        val sha256: String?

        class Ok(val bytes: ByteArray, val header: CheckedHeader) : Checked {
            override val sha256: String by lazy { Sha256.hex(bytes) }
        }

        class Fail(val result: OpenResult, val bytes: ByteArray? = null) : Checked {
            override val sha256: String? by lazy { bytes?.let(Sha256::hex) }
        }
    }

    // One read per call; the returned bytes are the ones checked and, in open, decrypted.
    private suspend fun readAndCheck(location: String, state: VaultStateStore): Checked {
        val read = try {
            storage.read(location, maxVaultBytes(maxHeapBytes()))
        } catch (e: CancellationException) {
            throw e
        } catch (e: OutOfMemoryError) {
            // A file near the size limit on a phone with a small heap.
            return Checked.Fail(OpenResult.NotEnoughMemory())
        } catch (e: Exception) {
            ReadResult.Failed(StorageFailure.IO_FAILURE)
        }
        val bytes = when (read) {
            is ReadResult.Bytes -> read.bytes
            is ReadResult.Failed -> return Checked.Fail(OpenResult.Unreadable(read.cause))
        }
        return when (val checked = checkBytes(bytes, state.kdfBaseline(location))) {
            is Checked.Fail -> Checked.Fail(checked.result, bytes)
            is Checked.Ok -> checked
        }
    }

    // A header whose dictionaries exceed the heap's budget, or that runs out of memory, is
    // NotEnoughMemory here, so no OutOfMemoryError from a crafted header leaves the opener.
    private fun checkBytes(bytes: ByteArray, baseline: KdfSettings?): Checked {
        val read = try {
            readHeader(bytes, maxHeapBytes())
        } catch (e: OutOfMemoryError) {
            return Checked.Fail(OpenResult.NotEnoughMemory())
        }
        val header = when (read) {
            is HeaderRead.Valid -> read.header
            is HeaderRead.Invalid -> return Checked.Fail(failure(read.result))
        }
        KdfPolicy.compare(baseline, header.kdf)?.let {
            return Checked.Fail(OpenResult.Refused(it))
        }
        return Checked.Ok(bytes, header)
    }

    companion object {
        private val KEEP_NOTHING = Stores(NoState, NoBackups, NoMarkers)

        /** Builds the production opener; key derivation and decryption run on [io]. */
        fun create(
            storage: VaultStorage,
            state: VaultStateStore,
            io: CoroutineDispatcher,
            backups: BackupStore = NoBackups,
            markers: SaveMarkerStore = NoMarkers,
        ): VaultOpening = VaultOpener(storage, state, io, backups = backups, markers = markers) { bytes, header, credentials, budget ->
            VaultXmlCodec.decode(bytes, header, credentials, budget)
        }
    }
}
