package org.onekash.kashpass.vault.save

import org.onekash.kashpass.vault.doc.VaultKey
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.open
import java.time.Duration
import java.time.Instant
import java.util.Collections
import java.util.Random
import java.util.concurrent.TimeUnit
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.backup.SaveMarker
import org.onekash.kashpass.vault.backup.SaveMarkerStore
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.doc.Encoded
import org.onekash.kashpass.vault.doc.KdfEngine
import org.onekash.kashpass.vault.doc.KeyDerivation
import org.onekash.kashpass.vault.doc.withKdf
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDelete
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.VaultIndex
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.policy.KdfSetting
import org.onekash.kashpass.vault.storage.VaultStorage
import org.onekash.kashpass.vault.storage.maxVaultBytes
import org.onekash.kashpass.vault.storage.Writability
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.HeaderDictionaries
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawEntry
import org.onekash.kashpass.vault.testing.RawField
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.u64

class SafeSaverTest {

    private val loc = "content://fake/vault.kdbx"
    private val original = TestVaults.bytes(aesRounds = 1_000UL)
    private val credentials = VaultKey.password(TestVaults.PASSWORD.toCharArray())
    private val limits = VaultXmlCodec.Limits(open = 64 * 1024 * 1024, save = 64L * 1024 * 1024)
    // The test vaults are stamped with the wall clock, and changes after now plus a slack read as
    // clock skew, so the saver's clock is the real one.
    private val now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)

    private val events = Collections.synchronizedList(mutableListOf<String>())
    private val storage = FakeVaultStorage().apply { put(loc, original) }
    private val backups = FakeBackupStore { now }
    private val markers = FakeSaveMarkerStore()
    private val state = FakeVaultStateStore()
    private val writers = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var encodes = 0
    private var encode: (VaultDocument, KeyDerivation) -> Encoded = { d, k -> VaultXmlCodec.encode(d, derive = k) }
    private var readBack: (ByteArray, VaultKey, VaultXmlCodec.Limits, KeyDerivation) -> Boolean = { b, c, l, k -> VaultXmlCodec.readBack(b, c, l, k, Long.MAX_VALUE) }

    private val readLimits = mutableListOf<Int>()
    private val derivations = java.util.concurrent.atomic.AtomicInteger()
    private val engine = KdfEngine()
    private var deriveFailure: Throwable? = null
    private val countingKdf = KeyDerivation { parameters, compositeKey ->
        derivations.incrementAndGet()
        deriveFailure?.let { throw it }
        engine.derive(parameters, compositeKey)
    }

    private fun saver(timeout: Duration = Duration.ofSeconds(10), heap: Long = Long.MAX_VALUE) = SafeSaver(
        storage = recording(storage),
        backups = recording(backups),
        markers = recording(markers),
        state = state,
        io = Dispatchers.IO,
        writers = writers,
        writeTimeout = timeout,
        maxHeapBytes = { heap },
        kdf = countingKdf,
        encode = { d, k -> events += "encode"; encodes++; encode(d, k) },
        readBack = { b, c, l, k -> events += "decode"; readBack(b, c, l, k) },
        now = { now },
    )

    @AfterEach
    fun tearDown() {
        storage.releaseWrites()
        writers.cancel()
    }

    private fun opened(bytes: ByteArray = original) =
        OpenedVault(VaultXmlCodec.open(bytes, credentials, limits), OpenedVault.Baseline.Known(Sha256.hex(bytes)), bytes.size.toLong(), now, UnlockOrigin.PASSWORD)

    /** The vault with the first entry's title changed, as an edit hands it to the saver. */
    private fun edited(vault: OpenedVault = opened(), title: String = "Edited"): OpenedVault {
        val row = VaultIndex.from(vault.document).rows(Chip.All, "").first()
        val draft = EntryEdits.draftOf(vault.document, row.id)!!
        val result = EntryEdits.edit(vault.document, row.id, EntryDraft(title, draft.userName, draft.password, draft.url, draft.notes), now)
        return vault.withDocument(assertIs<EditResult.Changed>(result).document)
    }

    private fun titles(bytes: ByteArray) = VaultIndex.from(VaultXmlCodec.open(bytes, credentials, limits)).rows(Chip.All, "").map { it.title }

    @Test
    fun `the re-read and the read-back use the heap-derived read limit`() = runBlocking<Unit> {
        assertIs<SaveResult.Saved>(saver(heap = 512L * 1024 * 1024).save(loc, edited()))
        val limit512 = org.onekash.kashpass.vault.storage.maxVaultBytes(512L * 1024 * 1024)
        assertEquals(listOf(limit512, limit512), readLimits)
        readLimits.clear()
        val limit256 = org.onekash.kashpass.vault.storage.maxVaultBytes(256L * 1024 * 1024)
        storage.put(loc, ByteArray(limit256 + 1))
        assertIs<SaveResult.Conflict>(saver(heap = 256L * 1024 * 1024).save(loc, edited()))
        assertEquals(listOf(limit256), readLimits)
    }

    @Test
    fun `a file larger than the read limit is not written, and a KDF too large for one array is not enough memory`() = runBlocking<Unit> {
        val before = storage.bytes(loc)!!.copyOf()
        // An 800-byte heap gives a 93-byte read limit, below any encoded vault.
        assertIs<SaveResult.NotEnoughMemory>(saver(heap = 800L).save(loc, edited()))
        assertTrue("write" !in events)
        assertContentEquals(before, storage.bytes(loc))
        events.clear()
        deriveFailure = org.onekash.kashpass.vault.doc.KdfTooLargeException()
        assertIs<SaveResult.NotEnoughMemory>(saver().save(loc, edited()))
        assertTrue("write" !in events)
    }

    // The largest heap whose limits from [VaultXmlCodec.Limits.forHeap] put [over] above
    // the cap [cap] reads; the limits only grow with the heap.
    private fun heapBelow(over: Long, cap: (VaultXmlCodec.Limits) -> Long): Long {
        var lo = 1L
        var hi = 1L shl 40
        while (hi - lo > 1) {
            val mid = (lo + hi) / 2
            if (cap(VaultXmlCodec.Limits.forHeap(mid)) < over) lo = mid else hi = mid
        }
        return lo
    }

    // Asserts that nothing of a save reached storage, the backups or the marker.
    private suspend fun assertNothingWritten(result: SaveResult) {
        assertContentEquals(original, storage.bytes(loc), "the file is untouched")
        assertFalse(events.any { it == "write" || it == "backup" || it == "marker set" || it == "read" }, events.toString())
        assertTrue(backups.list(loc).isEmpty())
        assertNull(markers.get(loc))
        assertIs<OpenedVault.Baseline.Known>(result.opened.baseline)
    }

    @Test
    fun `a save edited past the XML save cap stops before the backup, the marker and the write`() = runBlocking<Unit> {
        val vault = edited()
        val big = vault.document.let { d ->
            val row = VaultIndex.from(d).rows(Chip.All, "").first()
            val draft = EntryEdits.draftOf(d, row.id)!!
            val changed = EntryEdits.edit(d, row.id, EntryDraft(draft.title, draft.userName, draft.password, draft.url, "n".repeat(200_000)), now)
            vault.withDocument(assertIs<EditResult.Changed>(changed).document)
        }
        val encoded = assertIs<Encoded.Bytes>(VaultXmlCodec.encode(big.document))
        val heap = heapBelow(encoded.xmlBytes) { it.save }
        val limits = VaultXmlCodec.Limits.forHeap(heap)
        // Only the XML save cap refuses it: the open cap, the payload cap and the read limit pass.
        assertTrue(vault.document.xmlBytes <= limits.save && encoded.xmlBytes <= limits.open, "$limits")
        assertTrue(encoded.payloadBytes <= limits.payloadSave && encoded.bytes.size <= org.onekash.kashpass.vault.storage.maxVaultBytes(heap))
        events.clear()
        val result = saver(heap = heap).save(loc, big)
        assertIs<SaveResult.NotEnoughMemory>(result)
        assertEquals(listOf("writability", "encode"), events)
        assertNothingWritten(result)
        // The same edit saves on a heap one step up.
        events.clear()
        assertIs<SaveResult.Saved>(saver(heap = heapBelow(encoded.xmlBytes + 1) { it.save } + 1).save(loc, big))
    }

    @Test
    fun `a save whose decompressed payload is past the payload save cap stops before the write`() = runBlocking<Unit> {
        val attachment = Random(7).let { r -> ByteArray(300_000).also(r::nextBytes) }
        val bytes = TestVaults.rawXmlVault(TestVaults.keePassXml(entries = "<Entry><String><Key>Title</Key><Value>A</Value></String><Binary><Key>a.bin</Key><Value Ref=\"0\" /></Binary></Entry>"), attachments = listOf(attachment))
        storage.put(loc, bytes)
        val vault = OpenedVault(VaultXmlCodec.open(bytes, credentials, limits), OpenedVault.Baseline.Known(Sha256.hex(bytes)), bytes.size.toLong(), now, UnlockOrigin.PASSWORD)
        val encoded = assertIs<Encoded.Bytes>(VaultXmlCodec.encode(vault.document))
        val heap = heapBelow(encoded.payloadBytes) { it.payloadSave }
        val limits = VaultXmlCodec.Limits.forHeap(heap)
        assertTrue(encoded.xmlBytes <= limits.save && encoded.payloadBytes <= limits.decompression, "$limits")
        assertTrue(encoded.bytes.size <= org.onekash.kashpass.vault.storage.maxVaultBytes(heap))
        events.clear()
        val result = saver(heap = heap).save(loc, vault)
        assertIs<SaveResult.NotEnoughMemory>(result)
        assertEquals(listOf("writability", "encode"), events)
        assertContentEquals(bytes, storage.bytes(loc))
        assertTrue(backups.list(loc).isEmpty())
        assertNull(markers.get(loc))
        assertIs<OpenedVault.Baseline.Known>(result.opened.baseline)
    }

    @Test
    fun `a save whose file passes the read limit with XML and payload under their caps stops before the write`() = runBlocking<Unit> {
        // A save keeps the outer header's public custom data, so 64 KiB of it makes the file
        // larger than the payload by more than the gap between the payload save cap (heap / 9)
        // and the read limit (heap / 8.6).
        val attachment = Random(9).let { r -> ByteArray(300_000).also(r::nextBytes) }
        val plain = TestVaults.rawXmlVault(TestVaults.keePassXml(entries = "<Entry><String><Key>Title</Key><Value>A</Value></String><Binary><Key>a.bin</Key><Value Ref=\"0\" /></Binary></Entry>"), attachments = listOf(attachment))
        val layers = KdbxToolkit.open(plain, KdbxToolkit.Key(TestVaults.PASSWORD)).layers
        val custom = RawDictionary(0x0100, listOf(RawEntry(RawDictionary.BYTES, "Plugin_Data", ByteArray(64 * 1024) { 7 })))
        val bytes = KdbxToolkit.build(layers.copy(header = layers.header.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, custom.toBytes()))))
        storage.put(loc, bytes)
        val vault = OpenedVault(VaultXmlCodec.open(bytes, credentials, limits), OpenedVault.Baseline.Known(Sha256.hex(bytes)), bytes.size.toLong(), now, UnlockOrigin.PASSWORD)
        val encoded = assertIs<Encoded.Bytes>(VaultXmlCodec.encode(vault.document))
        // The largest heap whose read limit is below the encoded file.
        var lo = 1L
        var hi = 1L shl 40
        while (hi - lo > 1) {
            val mid = (lo + hi) / 2
            if (maxVaultBytes(mid) < encoded.bytes.size) lo = mid else hi = mid
        }
        val heap = lo
        val limits = VaultXmlCodec.Limits.forHeap(heap)
        // Only the read limit refuses it: the XML and payload save caps pass.
        assertTrue(encoded.xmlBytes <= limits.save && encoded.payloadBytes <= limits.payloadSave, "$limits, payload ${encoded.payloadBytes}")
        events.clear()
        val result = saver(heap = heap).save(loc, vault)
        assertIs<SaveResult.NotEnoughMemory>(result)
        assertEquals(listOf("writability", "encode"), events)
        assertContentEquals(bytes, storage.bytes(loc))
        assertTrue(backups.list(loc).isEmpty())
        assertNull(markers.get(loc))
        assertIs<OpenedVault.Baseline.Known>(result.opened.baseline)
        events.clear()
        assertIs<SaveResult.Saved>(saver(heap = hi + 64 * 1024).save(loc, vault))
    }

    @Test
    fun `a backup over the save caps is not saved as a new file, and nothing is written`() = runBlocking<Unit> {
        val older = TestVaults.bytes(aesRounds = 500UL)
        val backup = opened(older)
        val copy = storage.createDocument("Vault (backup).kdbx")
        val heap = heapBelow(backup.document.xmlBytes) { it.save }
        events.clear()
        assertEquals(CopyResult.Refused(copy), saver(heap = heap).saveBackupCopy(older, backup, copy))
        assertTrue(events.isEmpty(), events.toString())
        assertContentEquals(ByteArray(0), storage.bytes(copy))
        val payloadHeap = heapBelow(VaultXmlCodec.payloadBytes(backup.document)) { it.payloadSave }
        assertEquals(CopyResult.Refused(copy), saver(heap = payloadHeap).saveBackupCopy(older, backup, copy))
        assertEquals(CopyResult.Refused(copy), saver(heap = older.size * 8L - 8).saveBackupCopy(older, backup, copy))
        assertTrue(events.isEmpty(), events.toString())
        assertEquals(CopyResult.Saved("Vault (backup).kdbx"), saver(heap = 512L * 1024 * 1024).saveBackupCopy(older, backup, copy))
    }

    @Test
    fun `a copy of bytes a save prepared on this heap is written and verified`() = runBlocking<Unit> {
        val heap = 256L * 1024 * 1024
        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = false)
        val saver = saver(heap = heap)
        val failed = assertIs<SaveResult.WriteFailed>(saver.save(loc, edited()))
        val copy = storage.createDocument("Vault copy.kdbx")
        assertEquals(CopyResult.Saved("Vault copy.kdbx"), saver.saveCopy(failed.prepared, copy))
        assertTrue("Edited" in titles(storage.bytes(copy)!!))
    }

    @Test
    fun `a save runs every step in order and the file holds the edit`() = runBlocking<Unit> {
        val result = assertIs<SaveResult.Saved>(saver().save(loc, edited()))
        assertEquals(
            listOf("writability", "encode", "read", "backup", "marker set", "write", "read", "decode", "marker clear", "backup"),
            events,
        )
        val stored = storage.bytes(loc)!!
        assertEquals(OpenedVault.Baseline.Known(Sha256.hex(stored)), result.opened.baseline)
        assertTrue("Edited" in titles(stored))
        val (saved, before) = backups.list(loc)
        assertContentEquals(original, backups.read(loc, before.id))
        assertEquals(BackupKind.BEFORE_SAVE, before.kind)
        assertEquals(BackupKind.SAVED, saved.kind)
        assertContentEquals(stored, backups.read(loc, saved.id), "the newest backup is what the file now holds")
        assertNull(markers.get(loc))
    }

    @Test
    fun `a save derives the key once and the read-back decodes the stored bytes with it`() = runBlocking<Unit> {
        assertIs<SaveResult.Saved>(saver().save(loc, edited()))
        assertEquals(1, derivations.get())
        assertIs<SaveResult.Saved>(saver().save(loc, edited(opened(storage.bytes(loc)!!), title = "Again")))
        assertEquals(2, derivations.get(), "each save derives for its own fresh salt")
    }

    @ParameterizedTest
    @ValueSource(strings = ["tampered block", "tampered header HMAC", "another salt"])
    fun `a read-back that reuses the save's key fails on bytes that don't verify`(problem: String) = runBlocking<Unit> {
        readBack = { b, c, l, k ->
            val read = when (problem) {
                "tampered block" -> b.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
                "tampered header HMAC" -> {
                    val raw = RawKdbx.parse(b)
                    raw.copy(rest = raw.rest.copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() }).toBytes()
                }
                else -> RawKdbx.parse(b).withKdf { d -> d.with("S", RawDictionary.BYTES, ByteArray(32) { 7 }) }.toBytesWithHeaderHash()
            }
            VaultXmlCodec.readBack(read, c, l, k, Long.MAX_VALUE)
        }
        val result = saver().save(loc, edited())
        assertIs<SaveResult.VerifyFailed>(result, problem)
        assertEquals(OpenedVault.Baseline.Unknown, result.opened.baseline)
        assertNotNull(markers.get(loc))
        val expected = if (problem == "another salt") 2 else 1
        assertEquals(expected, derivations.get(), "only bytes with the encoded KDF settings reuse the key")
    }

    @Test
    fun `retry and save as copy derive the key again`() = runBlocking<Unit> {
        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = false)
        val saver = saver()
        val failed = assertIs<SaveResult.WriteFailed>(saver.save(loc, edited()))
        assertEquals(1, derivations.get())
        val copy = storage.createDocument("Vault copy.kdbx")
        assertEquals(CopyResult.Saved("Vault copy.kdbx"), saver.saveCopy(failed.prepared, copy))
        assertEquals(2, derivations.get())
        storage.allowWrites(loc)
        assertIs<SaveResult.Saved>(saver.retry(failed.prepared))
        assertEquals(3, derivations.get())
        val backupCopy = storage.createDocument("Vault backup.kdbx")
        assertEquals(CopyResult.Saved("Vault backup.kdbx"), saver.saveBackupCopy(original, opened(), backupCopy))
        assertEquals(4, derivations.get())
    }

    @Test
    fun `a backup of the written bytes that can't be kept doesn't fail the save`() = runBlocking<Unit> {
        backups.failingKinds = setOf(BackupKind.SAVED)
        assertIs<SaveResult.Saved>(saver().save(loc, edited()))
        assertEquals(listOf(BackupKind.BEFORE_SAVE), backups.list(loc).map { it.kind })
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "read-only", "not writable", "encode out of memory", "KDF refused", "file changed", "file emptied",
            "file shortened", "file unreadable", "backup failed", "write failed before open",
        ],
    )
    fun `a failure before the write stops the save with the file untouched`(step: String) = runBlocking<Unit> {
        var vault = edited()
        when (step) {
            "read-only" -> vault = opened(TestVaults.rawXmlVault(TestVaults.keePassXml(prolog = "<!DOCTYPE KeePassFile>\n"))).also { storage.put(loc, original) }
            "not writable" -> storage.setWritability(loc, Writability.NOT_WRITABLE)
            "encode out of memory" -> encode = { _, _ -> throw OutOfMemoryError("test") }
            "KDF refused" -> encode = { d, k ->
                val encoded = assertIs<Encoded.Bytes>(VaultXmlCodec.encode(d, derive = k))
                Encoded.Bytes(RawKdbx.parse(encoded.bytes).withKdf { d -> d.with("R", RawDictionary.UINT64, u64(0UL)) }.toBytes(), encoded.xmlBytes, encoded.payloadBytes)
            }
            "file changed" -> storage.put(loc, TestVaults.bytes(aesRounds = 1_000UL))
            "file emptied" -> storage.put(loc, ByteArray(0))
            "file shortened" -> storage.put(loc, original.copyOf(original.size / 2))
            "file unreadable" -> storage.fail(loc, StorageFailure.IO_FAILURE)
            "backup failed" -> backups.failing = true
            "write failed before open" -> storage.failWrites(loc, StorageFailure.PERMISSION_REVOKED, afterOpen = false)
        }
        val before = storage.bytes(loc)
        val result = saver().save(loc, vault)
        val expected = mapOf(
            "read-only" to SaveResult.ReadOnly::class, "not writable" to SaveResult.NotWritable::class,
            "encode out of memory" to SaveResult.NotEnoughMemory::class, "KDF refused" to SaveResult.KdfRefused::class,
            "file changed" to SaveResult.Conflict::class, "file emptied" to SaveResult.Conflict::class,
            "file shortened" to SaveResult.Conflict::class, "file unreadable" to SaveResult.Conflict::class,
            "backup failed" to SaveResult.BackupFailed::class, "write failed before open" to SaveResult.WriteFailed::class,
        )
        assertEquals(expected.getValue(step), result::class, step)
        assertContentEquals(before, storage.bytes(loc), "the file is untouched")
        assertNull(markers.get(loc), "no marker is left")
        if (step != "write failed before open") assertFalse("write" in events, events.toString())
        assertIs<OpenedVault.Baseline.Known>(result.opened.baseline)
    }

    @Test
    fun `a re-read the provider doesn't answer in time stops the save as not reachable, ready to retry`() = runBlocking<Unit> {
        storage.fail(loc, StorageFailure.TIMED_OUT)
        val result = assertIs<SaveResult.NotReachable>(saver().save(loc, edited()))
        assertNotNull(result.prepared)
        assertContentEquals(original, storage.bytes(loc))
        assertTrue(backups.list(loc).isEmpty())
        assertNull(markers.get(loc))
        storage.recover(loc)
        assertIs<SaveResult.Saved>(saver().retry(result.prepared!!))
        assertTrue("Edited" in titles(storage.bytes(loc)!!))
    }

    @Test
    fun `an Argon2 setting out of bounds in memory stops the save before any key derivation`() = runBlocking<Unit> {
        val vault = opened()
        val zeroIterations = org.onekash.kashpass.vault.kdbx.KdfParameters.Argon2(
            org.onekash.kashpass.vault.kdbx.Argon2Type.ARGON2D, ByteArray(32), 2U, 64UL shl 20, 0UL, 0x13U, null, null,
        )
        val result = assertIs<SaveResult.KdfRefused>(saver().save(loc, vault.withDocument(vault.document.withKdf(zeroIterations))))
        assertEquals(KdfRejection.OutOfBounds(KdfSetting.ARGON2_ITERATIONS, 0UL), result.rejection)
        assertContentEquals(original, storage.bytes(loc))
        assertFalse("write" in events, events.toString())
        assertEquals(0, derivations.get())
    }

    @Test
    fun `a timed-out writability check does not stop encoding, so the result can be retried`() = runBlocking<Unit> {
        storage.setWritability(loc, Writability.TIMED_OUT)
        val result = assertIs<SaveResult.NotReachable>(saver().save(loc, edited()))
        assertNotNull(result.prepared)
        assertEquals(listOf("writability", "encode"), events)
        assertContentEquals(original, storage.bytes(loc))
    }

    @Test
    fun `steps after a failure never run`() = runBlocking<Unit> {
        storage.setWritability(loc, Writability.NO_WRITE_GRANT)
        saver().save(loc, edited())
        assertEquals(listOf("writability"), events)
        events.clear()
        storage.setWritability(loc, Writability.WRITABLE)
        storage.put(loc, ByteArray(0))
        saver().save(loc, edited())
        assertEquals(listOf("writability", "encode", "read"), events)
        events.clear()
        storage.put(loc, original)
        backups.failing = true
        saver().save(loc, edited())
        assertEquals(listOf("writability", "encode", "read", "backup"), events)
    }

    @ParameterizedTest
    @ValueSource(strings = ["partial write", "ignored truncation", "different read-back", "does not decrypt", "decrypt out of memory"])
    fun `a write that doesn't verify makes the baseline unknown and keeps the marker`(problem: String) = runBlocking<Unit> {
        when (problem) {
            "partial write" -> storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = true)
            "ignored truncation" -> {
                storage.ignoreTruncation(loc)
                // A longer file to replace, so the old tail survives behind the new bytes.
                storage.put(loc, original + ByteArray(50_000))
            }
            "different read-back" -> storage.readBackDifferent(loc)
            "does not decrypt" -> readBack = { _, _, _, _ -> throw IllegalStateException("bad") }
            "decrypt out of memory" -> readBack = { _, _, _, _ -> throw OutOfMemoryError("test") }
        }
        val vault = if (problem == "ignored truncation") edited(opened().withBaseline(OpenedVault.Baseline.Known(Sha256.hex(storage.bytes(loc)!!)))) else edited()
        val result = saver().save(loc, vault)
        val expected = if (problem == "partial write") SaveResult.MaybeDamaged::class else SaveResult.VerifyFailed::class
        assertEquals(expected, result::class, problem)
        assertEquals(OpenedVault.Baseline.Unknown, result.opened.baseline)
        assertNotNull(markers.get(loc))
        assertNotNull(result.prepared)
    }

    @Test
    fun `after an unverified write the next save is a conflict`() = runBlocking<Unit> {
        storage.readBackDifferent(loc)
        val failed = saver().save(loc, edited())
        assertIs<SaveResult.VerifyFailed>(failed)
        storage.put(loc, original)
        assertIs<SaveResult.Conflict>(saver().save(loc, edited(failed.opened, title = "Edited again")))
    }

    @Test
    fun `a write that reports an error after every byte landed is classified as saved`() = runBlocking<Unit> {
        storage.failAfterFullWrite(loc)
        val result = assertIs<SaveResult.Saved>(saver().save(loc, edited()))
        assertEquals(OpenedVault.Baseline.Known(Sha256.hex(storage.bytes(loc)!!)), result.opened.baseline)
    }

    @Test
    fun `retry and save as copy write the same bytes without encoding again`() = runBlocking<Unit> {
        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = false)
        val saver = saver()
        val failed = assertIs<SaveResult.WriteFailed>(saver.save(loc, edited()))
        assertEquals(1, encodes)
        val copy = storage.createDocument("Vault (phone 2026-10-20 1200).kdbx")
        assertEquals(CopyResult.Saved("Vault (phone 2026-10-20 1200).kdbx"), saver.saveCopy(failed.prepared, copy))
        storage.allowWrites(loc)
        val retried = assertIs<SaveResult.Saved>(saver.retry(failed.prepared))
        assertEquals(1, encodes)
        assertContentEquals(storage.bytes(copy), storage.bytes(loc))
        assertEquals(OpenedVault.Baseline.Known(Sha256.hex(storage.bytes(loc)!!)), retried.opened.baseline)
    }

    @Test
    fun `a copy reports the name the provider gave, and a failed copy names the empty file`() = runBlocking<Unit> {
        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = false)
        val saver = saver()
        val prepared = assertIs<SaveResult.WriteFailed>(saver.save(loc, edited())).prepared
        storage.createDocument("Vault.kdbx")
        val clash = storage.createDocument("Vault.kdbx")
        assertEquals(CopyResult.Saved("Vault (1).kdbx"), saver.saveCopy(prepared, clash))
        val broken = storage.createDocument("Other.kdbx")
        storage.failWrites(broken, StorageFailure.IO_FAILURE, afterOpen = true)
        assertEquals(CopyResult.Failed(broken), saver.saveCopy(prepared, broken))
        assertContentEquals(original, storage.bytes(loc), "the open vault's file is untouched")
    }

    @Test
    fun `a copy is never written over a file that holds bytes`() = runBlocking<Unit> {
        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = false)
        val prepared = assertIs<SaveResult.WriteFailed>(saver().save(loc, edited())).prepared
        storage.allowWrites(loc)
        assertEquals(CopyResult.Refused(loc), saver().saveCopy(prepared, loc))
        assertContentEquals(original, storage.bytes(loc))
    }

    @Test
    fun `saves run one at a time`() = runBlocking<Unit> {
        storage.blockWrites()
        val saver = saver()
        val first = async(Dispatchers.IO) { saver.save(loc, edited(title = "First")) }
        assertTrue(storage.writeStarted.await(5, TimeUnit.SECONDS))
        assertTrue(saver.isSaving.value)
        val second = async(Dispatchers.IO) { saver.save(loc, edited(title = "Second")) }
        Thread.sleep(300)
        assertEquals(1, events.count { it == "writability" }, "the second save waits")
        storage.releaseWrites()
        assertIs<SaveResult.Saved>(first.await())
        // The second save started from the same baseline as the first, so the file changed under
        // it.
        assertIs<SaveResult.Conflict>(second.await())
        assertFalse(saver.isSaving.value)
    }

    @Test
    fun `a write past the timeout is classified by re-reading, and blocks the next write until it ends`() = runBlocking<Unit> {
        storage.blockWrites()
        val saver = saver(timeout = Duration.ofMillis(300))
        val first = assertIs<SaveResult.NotSavedUnchanged>(saver.save(loc, edited()))
        assertNotNull(markers.get(loc), "the marker stays while the write still runs")
        val marker = markers.get(loc)
        assertIs<SaveResult.WriterStillRunning>(saver.retry(first.prepared))
        assertEquals(marker, markers.get(loc), "a refused write leaves the running write's marker")
        storage.releaseWrites()
        // The stranded write finished; the file differs from the baseline, so a retry is a
        // conflict.
        Thread.sleep(300)
        assertIs<SaveResult.Conflict>(saver.retry(first.prepared))
    }

    @Test
    fun `cancelling a save during the write leaves the marker for recovery`() = runBlocking<Unit> {
        storage.blockWrites()
        val saver = saver()
        val job = async(Dispatchers.IO) { saver.save(loc, edited()) }
        assertTrue(storage.writeStarted.await(5, TimeUnit.SECONDS))
        job.cancel()
        assertThrows<CancellationException> { job.await() }
        assertEquals(SaveMarker(Sha256.hex(original), markers.get(loc)!!.newSha256), markers.get(loc))
        assertFalse(saver.isSaving.value)
    }

    @Test
    fun `cancelling a save during verify never leaves the file unaccounted for`() = runBlocking<Unit> {
        val inVerify = java.util.concurrent.CountDownLatch(1)
        val proceed = java.util.concurrent.CountDownLatch(1)
        readBack = { b, c, l, k ->
            inVerify.countDown()
            proceed.await(10, TimeUnit.SECONDS)
            VaultXmlCodec.readBack(b, c, l, k, Long.MAX_VALUE)
        }
        val saver = saver()
        val job = async(Dispatchers.IO) { saver.save(loc, edited()) }
        assertTrue(inVerify.await(10, TimeUnit.SECONDS))
        job.cancel()
        proceed.countDown()
        assertThrows<CancellationException> { job.await() }
        // Either the marker stays for the next open to check, or the check had already passed
        // and the file holds the new bytes, which decrypt.
        if (markers.get(loc) == null) assertTrue(titles(storage.bytes(loc)!!).contains("Edited"))
        assertFalse(saver.isSaving.value)
    }

    @Test
    fun `a verified save records the saved document's newest change, even when it is earlier`() = runBlocking<Unit> {
        state.saveNewestSeen(loc, Instant.parse("2020-01-01T00:00:00Z"))
        assertIs<SaveResult.Saved>(saver().save(loc, edited()))
        assertEquals(org.onekash.kashpass.vault.doc.NewestChange.of(opened(storage.bytes(loc)!!).document, now), state.newestSeen(loc))
        // An UNDO puts back an entry with its old times, so the saved file can be older than a
        // version saved before it; it is what the file holds.
        state.saveNewestSeen(loc, Instant.parse("2099-01-01T00:00:00Z"))
        assertIs<SaveResult.Saved>(saver().save(loc, edited(opened(storage.bytes(loc)!!), title = "Again")))
        assertEquals(org.onekash.kashpass.vault.doc.NewestChange.of(opened(storage.bytes(loc)!!).document, now), state.newestSeen(loc))
    }

    @Test
    fun `a delete goes through the same save and lands in the recycle bin`() = runBlocking<Unit> {
        val withBin = TestVaults.browserVault(aesRounds = 1_000UL)
        storage.put(loc, withBin)
        val vault = opened(withBin)
        val row = VaultIndex.from(vault.document).rows(Chip.All, "").first()
        val deleted = EntryDelete.delete(vault.document, row.id, now)!!
        assertIs<SaveResult.Saved>(saver().save(loc, vault.withDocument(deleted.document)))
        assertFalse(row.title in titles(storage.bytes(loc)!!))
        assertEquals(1, events.count { it == "write" })
    }

    @Test
    fun `a provider that throws while reading is a failure, never a crash`() = runBlocking<Unit> {
        storage.throwOnRead(IllegalStateException("provider bug"))
        assertIs<SaveResult.Conflict>(saver().save(loc, edited()))
        storage.throwOnRead(OutOfMemoryError("big"))
        assertIs<SaveResult.Conflict>(saver().save(loc, edited()))
    }

    @Test
    fun `a retry that fails again keeps a usable vault`() = runBlocking<Unit> {
        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = false)
        val saver = saver()
        val first = assertIs<SaveResult.WriteFailed>(saver.save(loc, edited()))
        val second = assertIs<SaveResult.WriteFailed>(saver.retry(first.prepared))
        // Each result's vault stays readable whatever happened to earlier holders.
        org.onekash.kashpass.vault.open.VaultSession.from(first.opened).release()
        assertEquals(Saveability.Saveable, second.opened.saveability)
        assertEquals(Saveability.Saveable, first.prepared.vault.saveability)
    }

    // The recorded step that throws an unexpected exception before it runs, or null.
    private var throwAt: String? = null

    private fun step(name: String) {
        if (name == throwAt) throw IllegalStateException("unexpected $name")
    }

    // Records each call into [events], in the order the saver makes them.
    private fun recording(inner: VaultStorage) = object : VaultStorage by inner {
        override suspend fun writability(location: String) = run { step("writability"); inner.writability(location) }.also { events += "writability" }
        override suspend fun read(location: String, maxBytes: Int) = inner.read(location, maxBytes).also { events += "read" }
        override suspend fun readFresh(location: String, maxBytes: Int) = inner.readFresh(location, maxBytes).also { events += "read"; readLimits += maxBytes }
        override suspend fun write(location: String, bytes: ByteArray) = run { events += "write"; step("write"); inner.write(location, bytes) }
    }

    private fun recording(inner: BackupStore) = object : BackupStore by inner {
        override suspend fun add(location: String, bytes: ByteArray, kind: BackupKind): BackupResult = run { step("backup"); inner.add(location, bytes, kind) }.also { events += "backup" }
    }

    private fun recording(inner: SaveMarkerStore) = object : SaveMarkerStore by inner {
        override fun set(location: String, oldSha256: String, newSha256: String) = run { step("marker set"); inner.set(location, oldSha256, newSha256) }.also { events += "marker set" }
        override fun clear(location: String) = run { step("marker clear"); inner.clear(location) }.also { events += "marker clear" }
    }

    @ParameterizedTest
    @ValueSource(strings = ["writability", "encode", "backup", "marker set"])
    fun `an unexpected exception before the write is a failed save with the file untouched`(at: String) = runBlocking<Unit> {
        if (at == "encode") encode = { _, _ -> throw IllegalArgumentException("unexpected encode") } else throwAt = at
        val saver = saver()
        val result = assertIs<SaveResult.UnexpectedError>(saver.save(loc, edited()), at)
        assertContentEquals(original, storage.bytes(loc), "the file is untouched")
        assertFalse("write" in events, events.toString())
        assertNull(markers.get(loc), "no marker is left")
        assertIs<OpenedVault.Baseline.Known>(result.opened.baseline)
        val encoded = at == "backup" || at == "marker set"
        assertEquals(encoded, result.prepared != null, "the bytes are kept once encoded")
        if (encoded) {
            throwAt = null
            assertIs<SaveResult.Saved>(saver.retry(result.prepared!!))
            assertTrue("Edited" in titles(storage.bytes(loc)!!))
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["write", "marker clear"])
    fun `an unexpected exception once the write started makes the baseline unknown and keeps the marker`(at: String) = runBlocking<Unit> {
        throwAt = at
        val result = assertIs<SaveResult.UnexpectedError>(saver().save(loc, edited()), at)
        assertEquals(OpenedVault.Baseline.Unknown, result.opened.baseline)
        assertNotNull(result.prepared)
        assertNotNull(markers.get(loc))
    }

    @Test
    fun `an unexpected exception during a retry is a failed save that keeps the bytes`() = runBlocking<Unit> {
        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = false)
        val saver = saver()
        val failed = assertIs<SaveResult.WriteFailed>(saver.save(loc, edited()))
        storage.allowWrites(loc)
        throwAt = "backup"
        val retried = assertIs<SaveResult.UnexpectedError>(saver.retry(failed.prepared))
        assertSame(failed.prepared, retried.prepared)
        assertIs<OpenedVault.Baseline.Known>(retried.opened.baseline)
        assertContentEquals(original, storage.bytes(loc))
    }

    @Test
    fun `an unexpected exception while writing a copy is a failed copy`() = runBlocking<Unit> {
        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = false)
        val saver = saver()
        val failed = assertIs<SaveResult.WriteFailed>(saver.save(loc, edited()))
        throwAt = "write"
        val copy = storage.createDocument("Vault (copy).kdbx")
        assertEquals(CopyResult.Failed(copy), saver.saveCopy(failed.prepared, copy))
        val backupCopy = storage.createDocument("Vault (backup).kdbx")
        assertEquals(CopyResult.Failed(backupCopy), saver.saveBackupCopy(original, opened(), backupCopy))
        assertFalse(saver.isSaving.value)
    }

    @Test
    fun `a cancellation inside a save is not turned into a result`() {
        encode = { _, _ -> throw CancellationException("cancelled") }
        assertThrows<CancellationException> { runBlocking { saver().save(loc, edited()) } }
    }

    @Test
    fun `a save or retry that fails to write keeps the earlier save's marker, so its copies stay pinned`() = runBlocking<Unit> {
        markers.set(loc, "aa", "bb")
        storage.failWrites(loc, StorageFailure.IO_FAILURE, afterOpen = false)
        val failed = assertIs<SaveResult.WriteFailed>(saver().save(loc, edited()))
        assertEquals(org.onekash.kashpass.vault.backup.SaveMarker("aa", "bb"), markers.get(loc))
        assertIs<SaveResult.WriteFailed>(saver().retry(failed.prepared))
        assertEquals(org.onekash.kashpass.vault.backup.SaveMarker("aa", "bb"), markers.get(loc))
    }

    @Test
    fun `a backup saved as a new file holds the backup's bytes, verified, and the vault file is untouched`() = runBlocking<Unit> {
        val older = TestVaults.bytes(aesRounds = 500UL)
        val copy = storage.createDocument("Vault (backup).kdbx")
        val backupCount = backups.list(loc).size
        val result = saver().saveBackupCopy(older, opened(older), copy)
        assertEquals(CopyResult.Saved("Vault (backup).kdbx"), result)
        assertContentEquals(older, storage.bytes(copy))
        assertContentEquals(original, storage.bytes(loc))
        assertEquals(backupCount, backups.list(loc).size)
        assertNull(markers.get(loc))
        assertNull(markers.get(copy))
        assertTrue("decode" in events, "the copy is read back and decrypted")
    }

    @Test
    fun `a backup is never written over a target that holds bytes or can't be read`() = runBlocking<Unit> {
        val older = TestVaults.bytes(aesRounds = 500UL)
        assertEquals(CopyResult.Refused(loc), saver().saveBackupCopy(older, opened(older), loc))
        assertContentEquals(original, storage.bytes(loc))
        for (cause in listOf(StorageFailure.IO_FAILURE, StorageFailure.TIMED_OUT)) {
            val copy = storage.createDocument("Vault ($cause).kdbx")
            storage.fail(copy, cause)
            assertEquals(CopyResult.Refused(copy), saver().saveBackupCopy(older, opened(older), copy))
        }
        assertFalse("write" in events)
    }

    @Test
    fun `a backup with settings outside the policy's bounds or no valid header is not saved as a new file`() = runBlocking<Unit> {
        val broken = RawKdbx.parse(TestVaults.bytes(aesRounds = 1_000UL)).withKdf { d -> d.with("R", RawDictionary.UINT64, u64(0UL)) }.toBytes()
        val copy = storage.createDocument("Vault (broken).kdbx")
        assertEquals(CopyResult.Refused(copy), saver().saveBackupCopy(broken, opened(), copy))
        assertEquals(CopyResult.Refused(copy), saver().saveBackupCopy(original.copyOf(40), opened(), copy))
        assertContentEquals(ByteArray(0), storage.bytes(copy))
    }

    @Test
    fun `encoded header dictionaries over the heap's budget stop the save as NotEnoughMemory before the write`() = runBlocking<Unit> {
        val heap = 32L * 1024 * 1024
        val crafted = HeaderDictionaries.manyEntries(HeaderDictionaries.PUBLIC_CUSTOM_DATA, 1 shl 20)
        encode = { _, _ -> Encoded.Bytes(crafted, 0, 0) }
        val result = saver(heap = heap).save(loc, edited())
        assertIs<SaveResult.NotEnoughMemory>(result)
        assertFalse("write" in events)
        assertNull(markers.get(loc))
        assertContentEquals(original, storage.bytes(loc))
    }

    @Test
    fun `a backup whose header dictionaries exceed the heap's budget is not saved as a new file`() = runBlocking<Unit> {
        val crafted = HeaderDictionaries.manyEntries(HeaderDictionaries.KDF, 1 shl 20)
        val copy = storage.createDocument("Vault (crafted).kdbx")
        assertEquals(CopyResult.Refused(copy), saver(heap = 32L * 1024 * 1024).saveBackupCopy(crafted, opened(), copy))
        assertContentEquals(ByteArray(0), storage.bytes(copy))
    }

    @Test
    fun `a backup copy whose write fails or reads back different is Failed`() = runBlocking<Unit> {
        val older = TestVaults.bytes(aesRounds = 500UL)
        val first = storage.createDocument("Vault (a).kdbx")
        storage.failWrites(first, StorageFailure.IO_FAILURE, afterOpen = true)
        assertEquals(CopyResult.Failed(first), saver().saveBackupCopy(older, opened(older), first))
        val second = storage.createDocument("Vault (b).kdbx")
        storage.readBackDifferent(second)
        assertEquals(CopyResult.Failed(second), saver().saveBackupCopy(older, opened(older), second))
    }

    @ParameterizedTest
    @ValueSource(strings = ["too large", "out of bounds", "salt", "algorithm unavailable", "out of memory"])
    fun `each way the key derivation fails ends the save before the write, with its own result`(failure: String) = runBlocking<Unit> {
        val rejection = KdfRejection.OutOfBounds(KdfSetting.AES_ROUNDS, 0UL)
        deriveFailure = when (failure) {
            "too large" -> org.onekash.kashpass.vault.doc.KdfTooLargeException()
            "out of bounds" -> org.onekash.kashpass.vault.doc.KdfOutOfBoundsException(rejection)
            "salt" -> org.onekash.kashpass.vault.doc.KdfSaltException()
            "algorithm unavailable" -> org.onekash.kashpass.vault.kdbx.KdbxException.AlgorithmUnavailable()
            else -> OutOfMemoryError("test")
        }
        val result = saver().save(loc, edited())
        when (failure) {
            "too large", "out of memory" -> assertIs<SaveResult.NotEnoughMemory>(result, failure)
            "out of bounds" -> assertEquals(rejection, assertIs<SaveResult.KdfRefused>(result, failure).rejection)
            "salt" -> assertNull(assertIs<SaveResult.KdfRefused>(result, failure).rejection)
            else -> assertNull(assertIs<SaveResult.UnexpectedError>(result, failure).prepared)
        }
        assertEquals(1, derivations.get())
        assertContentEquals(original, storage.bytes(loc))
        assertFalse("write" in events, events.toString())
        assertIs<OpenedVault.Baseline.Known>(result.opened.baseline)
    }

    // The minor version of the file [storage] holds at [location].
    private fun minorAt(location: String) =
        assertIs<org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.Read.Valid>(
            org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.read(storage.bytes(location)!!),
        ).header.minorVersion

    @ParameterizedTest
    @ValueSource(strings = ["4.0 with group tags", "4.1 without 4.1 content", "4.2", "4.0"])
    fun `a save writes KeePass 2's minimum version for the content and never lowers the opened one`(case: String) = runBlocking<Unit> {
        val tags = "<Tags>work</Tags>"
        val xml = TestVaults.keePassXml(
            entries = "<Entry><String><Key>Title</Key><Value>t</Value></String></Entry>",
        ).let { if (case.contains("group tags")) it.replaceFirst("<Name>", "$tags<Name>") else it }
        val minor = when (case) {
            "4.1 without 4.1 content" -> 1
            "4.2" -> 2
            else -> 0
        }
        val bytes = TestVaults.rawXmlVault(xml, minor = minor)
        storage.put(loc, bytes)
        val vault = opened(bytes)
        assertIs<SaveResult.Saved>(saver().save(loc, vault))
        val expected = if (case == "4.0") 0 else 1
        assertEquals(expected, minorAt(loc), case)
    }

    @ParameterizedTest
    @ValueSource(strings = ["Salsa20", "ArcFour variant"])
    fun `a vault with an older inner stream saves with ChaCha20 and a 64-byte key and reopens past the downgrade check`(stream: String) = runBlocking<Unit> {
        val bytes = when (stream) {
            "Salsa20" -> TestVaults.salsa20Vault()
            else -> org.onekash.kashpass.vault.corpus.Corpus.all.single { it.name == "inner-stream-arcfour-variant" }.bytes
        }
        val keys = if (stream == "Salsa20") credentials else org.onekash.kashpass.vault.fixtures.TestFiles.credentials(
            org.onekash.kashpass.vault.corpus.Corpus.all.single { it.name == "inner-stream-arcfour-variant" }.file(),
        )
        storage.put(loc, bytes)
        val vault = OpenedVault(VaultXmlCodec.open(bytes, keys, limits), OpenedVault.Baseline.Known(Sha256.hex(bytes)), bytes.size.toLong(), now, UnlockOrigin.PASSWORD)
        assertEquals(Saveability.Saveable, vault.saveability)
        assertIs<SaveResult.Saved>(saver().save(loc, vault))
        val saved = storage.bytes(loc)!!
        val header = assertIs<org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.Read.Valid>(org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.read(saved)).header
        val composite = keys.compositeKey()
        val opened = assertIs<org.onekash.kashpass.vault.kdbx.KdbxResult.Opened>(
            org.onekash.kashpass.vault.kdbx.KdbxDecoder.decode(saved, header, composite, engine::derive, 64 shl 20),
        )
        opened.plaintext.close()
        assertEquals(org.onekash.kashpass.vault.kdbx.InnerStream.CHACHA20, opened.container.inner.streamId)
        assertEquals(64, opened.container.inner.streamKey.size)
        val before = assertIs<org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.Read.Valid>(org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.read(bytes)).header
        val baseline = org.onekash.kashpass.vault.doc.CheckedHeader(before).kdf
        val now = org.onekash.kashpass.vault.doc.CheckedHeader(header).kdf
        assertNull(org.onekash.kashpass.vault.policy.KdfPolicy.compare(baseline, now), "same parameters, fresh salt")
        assertEquals(baseline, now)
        VaultXmlCodec.open(saved, keys, limits)
    }

    @Test
    fun `a lock while the encode runs lets the save finish, and nothing the document holds is zero-filled`() = runBlocking<Unit> {
        val vault = edited(opened(TestVaults.rawXmlVault(
            TestVaults.keePassXml(entries = "<Entry><String><Key>Title</Key><Value>t</Value></String><Binary><Key>f</Key><Value Ref=\"0\" /></Binary></Entry>"),
            attachments = listOf("attachment".toByteArray()),
        ).also { storage.put(loc, it) }))
        val session = org.onekash.kashpass.vault.open.VaultSession.from(vault)
        val inEncode = java.util.concurrent.CountDownLatch(1)
        val proceed = java.util.concurrent.CountDownLatch(1)
        encode = { d, k ->
            inEncode.countDown()
            proceed.await(10, TimeUnit.SECONDS)
            VaultXmlCodec.encode(d, derive = k)
        }
        val saver = saver()
        val job = async(Dispatchers.IO) { saver.save(loc, session.opened) }
        assertTrue(inEncode.await(10, TimeUnit.SECONDS))
        session.release()
        proceed.countDown()
        assertIs<SaveResult.Saved>(job.await())
        assertEquals("attachment", String(vault.document.attachments.single().data))
        assertTrue(vault.document.xml.source.bytes.any { it != 0.toByte() })
        assertTrue("Edited" in titles(storage.bytes(loc)!!))
    }
}
