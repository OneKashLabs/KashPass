package org.onekash.kashpass.vault.memory

import java.io.File
import java.lang.management.ManagementFactory
import java.lang.management.MemoryType
import java.nio.file.Files
import java.time.Instant
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.onekash.kashpass.vault.backup.BackupDeletion
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.BackupResult
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.doc.VaultKey
import org.onekash.kashpass.vault.doc.CheckedHeader
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.KeyFile
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.kdbx.KdbxDamage
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.kdbx.VariantDictionary
import org.onekash.kashpass.vault.kdbx.MemoryCause
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.storage.DeleteResult
import org.onekash.kashpass.vault.storage.FileMetadata
import org.onekash.kashpass.vault.storage.ReadResult
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.VaultStorage
import org.onekash.kashpass.vault.storage.WriteResult
import org.onekash.kashpass.vault.storage.Writability
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.HeaderDictionaries
import org.onekash.kashpass.vault.storage.maxVaultBytes
import org.onekash.kashpass.vault.xml.XmlBytes

/**
 * Child-JVM entry point of the memory tests ([MemoryRun]).
 *
 * `generate <dir> <name>...` writes each [MemoryVaults.Spec] named that is not in `<dir>` yet.
 *
 * `measure <vault> <heap bytes> [fake|disk] [edits]` opens the vault with [VaultOpener], makes
 * `edits` entry edits ([edited]; none by default) and saves it with [SafeSaver], both computing
 * their limits for a heap of `<heap bytes>`, and prints one `RESULT` line per step with its
 * outcome, time and the heap peak: the sum of the heap pools' peak usage since a reset made after
 * a full collection. The open line names the cause of a NotEnoughMemory (a limit or an
 * OutOfMemoryError) and the opened vault's saveability; the save line says whether the file was
 * written. Storage is [FakeVaultStorage] (the default), which keeps the stored file and the last
 * array it returned in the heap, or [DiskStorage], which reads as the platform adapter does:
 * 64 KiB chunks, then one array the chunks are copied into. The difference between the two is
 * the fake's own copies. Backups go to a temporary folder and are read back, as the app's file
 * store does.
 *
 * `header <field>` checks, with [VaultOpener.check] over [FakeVaultStorage] and the limits for
 * this JVM's heap, a file just under the read limit whose outer header field `<field>` (11 or 12)
 * holds a dictionary of tiny entries ([HeaderDictionaries.manyEntries]), and prints one `RESULT`
 * line for the step `check` with its outcome.
 *
 * `keyfile <root> [parsed|large]` opens a vault with a key file of tiny elements under `<root>`
 * ([keyFile]) and prints one `RESULT` line for the step `open` with its outcome and the file size.
 *
 * `entries <count> <name bytes> <value bytes>` reads a dictionary of `<count>` byte-array entries
 * with names and values of the sizes given and prints the heap the read entries keep, per entry,
 * after a full collection (`ENTRIES` line).
 */
internal object MemoryProbe {

    private const val LOCATION = "content://memory/vault.kdbx"

    @JvmStatic
    fun main(args: Array<String>) {
        when (args[0]) {
            "generate" -> generate(File(args[1]), args.drop(2))
            "measure" -> measure(File(args[1]), args[2].toLong(), disk = args.getOrNull(3) == "disk", edits = args.getOrNull(4)?.toInt() ?: 0)
            "header" -> header(args[1].toInt())
            "keyfile" -> keyFile(args[1], args.getOrNull(2) == "parsed")
            "entries" -> entries(args[1].toInt(), args[2].toInt(), args[3].toInt())
            else -> error("unknown mode ${args[0]}")
        }
    }

    private fun generate(dir: File, names: List<String>) {
        dir.mkdirs()
        for (name in names) {
            val target = File(dir, name)
            if (target.isFile) continue
            val spec = MemoryVaults.Spec.parse(name) ?: error("not a generated vault name: $name")
            val temp = File(dir, "$name.tmp")
            temp.writeBytes(MemoryVaults.build(spec))
            check(temp.renameTo(target)) { "cannot rename $temp" }
            println("GENERATED\t$name\t${target.length()}")
        }
    }

    private val pools = ManagementFactory.getMemoryPoolMXBeans().filter { it.type == MemoryType.HEAP }

    private fun collect() {
        repeat(3) {
            System.gc()
            Thread.sleep(50)
        }
    }

    private fun used(): Long = pools.sumOf { it.usage.used }

    private fun reset() = pools.forEach { it.resetPeakUsage() }

    private fun peak(): Long = pools.sumOf { it.peakUsage.used }

    private fun measure(vault: File, heapBytes: Long, disk: Boolean, edits: Int) {
        val backupDir = Files.createTempDirectory("kashpass-memory").toFile()
        val writers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            collect()
            val empty = used()
            val storage: VaultStorage = if (disk) {
                DiskStorage(File(backupDir, "vault.kdbx").also { vault.copyTo(it) })
            } else {
                FakeVaultStorage().apply { put(LOCATION, vault.readBytes()) }
            }
            val backups = DiskBackups(backupDir)
            var cause: MemoryCause? = null
            val opener = VaultOpener(storage, FakeVaultStateStore(), Dispatchers.IO, maxHeapBytes = { heapBytes }, backups = backups) { b, h, c, budget ->
                decode(b, h, c, budget) { cause = it }
            }
            collect()
            reset()
            var started = System.nanoTime()
            val opened = attempt { runBlocking { opener.open(LOCATION, TestFiles.password.toCharArray()) } }
            val saveability = (opened as? OpenResult.Unlocked)?.session?.opened?.saveability
            report("open", opened, empty, started, extra = "\tcause=${cause ?: ""}\tsaveability=${saveability ?: ""}")
            val unlocked = opened as? OpenResult.Unlocked ?: return
            val document = unlocked.session.opened.document
            val toSave = edited(unlocked.session.opened, edits)
            // Protected values written as text, not Base64: within a few bytes per value.
            val xmlAfterEdits = if (edits == 0) document.xmlBytes else XmlBytes.write(toSave.document.xml).size.toLong()
            val decompressed = document.xmlBytes + document.attachments.sumOf { it.data.size.toLong() }
            collect()
            val retained = used() - empty
            val saver = SafeSaver(storage, backups, FakeSaveMarkerStore(), FakeVaultStateStore(), Dispatchers.IO, writers, maxHeapBytes = { heapBytes })
            val writesBefore = writes(storage)
            reset()
            started = System.nanoTime()
            val saved = attempt { runBlocking { saver.save(LOCATION, toSave) } }
            val written = writes(storage) > writesBefore
            report("save", saved, empty, started, extra = "\txml=${document.xmlBytes}\tdecompressed=$decompressed\tretainedAfterOpen=$retained\twritten=$written\tedits=$edits\txmlAfterEdits=$xmlAfterEdits")
        } finally {
            writers.cancelScope()
            backupDir.deleteRecursively()
        }
    }

    /**
     * Returns [opened] after [edits] edits, as the entry editor makes them: each appends
     * [EDIT_NOTES] characters to the notes of the next entry in index order, so each adds a
     * history snapshot and the XML a save writes grows past what was read.
     */
    private fun edited(opened: OpenedVault, edits: Int): OpenedVault {
        var document = opened.document
        val ids = DocumentIds.entries(document).keys.toList()
        repeat(edits) { k ->
            val id = ids[k % ids.size]
            val draft = EntryEdits.draftOf(document, id) ?: error("no entry $id")
            val longer = EntryDraft(draft.title, draft.userName, draft.password, draft.url, draft.notes + "n".repeat(EDIT_NOTES))
            val result = EntryEdits.edit(document, id, longer, Instant.now())
            document = (result as? EditResult.Changed ?: error("edit $k: $result")).document
        }
        return opened.withDocument(document)
    }

    private const val EDIT_NOTES = 4096

    private fun CoroutineScope.cancelScope() = coroutineContext[kotlinx.coroutines.Job]?.cancel()

    private fun writes(storage: VaultStorage): Int = when (storage) {
        is FakeVaultStorage -> storage.writes
        is DiskStorage -> storage.writes
        else -> 0
    }

    // Opens as VaultXmlCodec.decode does, with the same arrays alive, and passes the cause of a
    // NotEnoughMemory container result to [cause]: a limit's refusal or an OutOfMemoryError.
    private fun decode(bytes: ByteArray, header: CheckedHeader, credentials: VaultKey, budget: VaultXmlCodec.Budget, cause: (MemoryCause) -> Unit): Decoded {
        val result = credentials.withParts { passwordHash, keyFilePart ->
            ContainerDecode.decode(bytes, header.outer, header.kdf, passwordHash, keyFilePart, budget.limits, budget.readLimitBytes, maxHeapBytes = budget.maxHeapBytes)
        }
        return when (result) {
            is ContainerDecode.Result.Opened -> try {
                Decoded.Opened(VaultXmlCodec.document(result.read, credentials, budget.limits), result.read.container.bytesAfterEnd)
            } catch (e: OutOfMemoryError) {
                result.read.zeroFill()
                cause(MemoryCause.OUT_OF_MEMORY)
                Decoded.NotEnoughMemory
            }
            is ContainerDecode.Result.Refused -> Decoded.Refused(result.rejection)
            is ContainerDecode.Result.Failed -> {
                (result.result as? KdbxResult.NotEnoughMemory)?.let { cause(it.cause) }
                Decoded.of(result.result, keyChecked = true)
            }
        }
    }

    private fun header(field: Int) {
        val storage = FakeVaultStorage().apply { put(LOCATION, HeaderDictionaries.manyEntries(field, maxVaultBytes(Runtime.getRuntime().maxMemory()) - 1)) }
        val opener = VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO)
        collect()
        val empty = used()
        reset()
        val started = System.nanoTime()
        val checked = attempt { runBlocking { opener.check(LOCATION) } }
        report("check", checked, empty, started, extra = "\tresult=${checked.takeIf { it !is Throwable } ?: ""}")
    }

    // Opens a vault with a key file of tiny elements under [root], the shape whose parse costs
    // the most heap per byte: just under the vault XML open cap ([parsed] false, which is over the
    // key-file limit), or just under the key-file limit, so it is parsed.
    private fun keyFile(root: String, parsed: Boolean) {
        val heap = Runtime.getRuntime().maxMemory()
        val size = (if (parsed) KeyFile.maxXmlBytes(heap) else VaultXmlCodec.Limits.forHeap(heap).open) - 64
        val open = "<$root>".toByteArray()
        val close = "</$root>".toByteArray()
        val element = "<a/>".toByteArray()
        val count = (size - open.size - close.size) / element.size
        val bytes = ByteArray(open.size + count * element.size + close.size)
        open.copyInto(bytes)
        for (i in 0 until count) element.copyInto(bytes, open.size + i * element.size)
        close.copyInto(bytes, open.size + count * element.size)
        val storage = FakeVaultStorage().apply { put(LOCATION, TestVaults.browserVault(aesRounds = 1_000UL)) }
        val opener = VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO)
        collect()
        val empty = used()
        reset()
        val started = System.nanoTime()
        val opened = attempt { runBlocking { opener.open(LOCATION, TestVaults.PASSWORD.toCharArray(), keyFile = bytes) } }
        report("open", opened, empty, started, extra = "\tsize=${bytes.size}")
    }

    private fun entries(count: Int, nameBytes: Int, valueBytes: Int) {
        val entry = 1 + 4 + nameBytes + 4 + valueBytes
        val bytes = ByteArray(2 + count * entry + 1)
        bytes[0] = 0
        bytes[1] = 1
        var p = 2
        for (i in 0 until count) {
            bytes[p] = 0x42
            bytes[p + 1] = nameBytes.toByte()
            for (k in 0 until minOf(4, nameBytes)) bytes[p + 5 + k] = (i ushr (8 * k)).toByte()
            bytes[p + 5 + nameBytes] = valueBytes.toByte()
            p += entry
        }
        collect()
        val before = used()
        val read = readDictionary(bytes)
        collect()
        val after = used()
        java.lang.ref.Reference.reachabilityFence(read)
        println("ENTRIES\tcount=$count\tname=$nameBytes\tvalue=$valueBytes\tretained=${after - before}\tperEntry=${(after - before).toDouble() / count}")
    }

    private fun readDictionary(bytes: ByteArray) = VariantDictionary.read(bytes, KdbxDamage.HEADER_FIELD, Long.MAX_VALUE)

    private fun attempt(block: () -> Any): Any = try {
        block()
    } catch (e: Throwable) {
        e
    }

    private fun report(step: String, result: Any, empty: Long, started: Long, extra: String) {
        val millis = (System.nanoTime() - started) / 1_000_000
        val peak = peak()
        val outcome = when (result) {
            is Throwable -> "threw ${result::class.simpleName}"
            else -> result::class.simpleName ?: result.toString()
        }
        println("RESULT\tstep=$step\toutcome=$outcome\tpeak=${peak - empty}\tmillis=$millis\tmax=${Runtime.getRuntime().maxMemory()}$extra")
    }

    /**
     * One vault file on disk read as the platform adapter reads a document: 64 KiB chunks, then
     * one array of the file's size the chunks are copied into, so both exist at the end of a read.
     */
    private class DiskStorage(private val file: File) : VaultStorage {
        override suspend fun read(location: String, maxBytes: Int): ReadResult {
            if (file.length() > maxBytes) return ReadResult.Failed(StorageFailure.TOO_LARGE)
            val chunks = ArrayList<ByteArray>()
            file.inputStream().use { input ->
                while (true) {
                    val chunk = ByteArray(CHUNK)
                    val n = input.readNBytes(chunk, 0, CHUNK)
                    if (n == 0) break
                    chunks += if (n == CHUNK) chunk else chunk.copyOf(n)
                }
            }
            val out = ByteArray(chunks.sumOf { it.size })
            var at = 0
            for (c in chunks) {
                c.copyInto(out, at)
                at += c.size
            }
            return ReadResult.Bytes(out)
        }

        override suspend fun readPrefix(location: String, count: Int): ReadResult =
            ReadResult.Bytes(file.inputStream().use { it.readNBytes(count) })

        override suspend fun writability(location: String) = Writability.WRITABLE

        var writes = 0

        override suspend fun write(location: String, bytes: ByteArray): WriteResult {
            writes++
            file.writeBytes(bytes)
            return WriteResult.Written
        }

        override suspend fun metadata(location: String) = FileMetadata(file.name, file.length(), file.lastModified())

        override suspend fun delete(location: String) = DeleteResult.UNSUPPORTED

        private companion object {
            const val CHUNK = 64 * 1024
        }
    }

    /** Keeps backups as files and reads each one back once, as the app's file store does. */
    private class DiskBackups(private val dir: File) : BackupStore {
        private var counter = 0

        override suspend fun add(location: String, bytes: ByteArray, kind: BackupKind): BackupResult {
            val sha = Sha256.hex(bytes)
            val file = File(dir, "${++counter}.kdbx")
            file.writeBytes(bytes)
            if (Sha256.hex(file.readBytes()) != sha) return BackupResult.Failed
            file.delete()
            return BackupResult.Added(BackupInfo("backup-$counter", Instant.now(), bytes.size.toLong(), kind, sha))
        }

        override suspend fun keepNewest(location: String, count: Int) = 0

        override suspend fun delete(location: String, id: String) = BackupDeletion.NotFound

        override suspend fun list(location: String) = emptyList<BackupInfo>()

        override suspend fun read(location: String, id: String): ByteArray? = null
    }
}
