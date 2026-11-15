package org.onekash.kashpass.vault.open

import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.backup.SaveMarker
import org.onekash.kashpass.vault.doc.VaultKey
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.UnlockOrigin
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.CheckedHeader
import org.onekash.kashpass.vault.doc.DecodeFailure
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.KdfEngine
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.header.KdbxHeaderParserTest.Companion.fixture
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.header.UnsupportedReason
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.policy.KdfSetting
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.maxVaultBytes
import org.onekash.kashpass.vault.fixtures.Kdbx3Vaults
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.u32
import org.onekash.kashpass.vault.testing.u64
import org.onekash.kashpass.vault.testing.uuidBytes

class VaultOpenerTest {

    private val executor = Executors.newSingleThreadExecutor { Thread(it, "vault-io-test") }
    private val io: CoroutineDispatcher = executor.asCoroutineDispatcher()
    private val storage = FakeVaultStorage()
    private val state = FakeVaultStateStore()
    private val decodes = AtomicInteger()
    private var decodedArray: ByteArray? = null
    private var decodeThread: String? = null
    private val derives = AtomicInteger()
    private val engine = KdfEngine()
    private var decode: (ByteArray, CheckedHeader, VaultKey, VaultXmlCodec.Budget) -> Decoded = { bytes, header, creds, budget ->
        decodes.incrementAndGet()
        decodedArray = bytes
        decodeThread = Thread.currentThread().name
        VaultXmlCodec.decode(bytes, header, creds, budget, derive = { p, k -> derives.incrementAndGet(); engine.derive(p, k) })
    }
    private var maxMemory = Long.MAX_VALUE
    private val opener = VaultOpener(storage, state, io, maxHeapBytes = { maxMemory }) { b, h, c, l -> decode(b, h, c, l) }

    @AfterEach
    fun tearDown() = executor.shutdown()

    private fun pw(text: String = PASSWORD) = text.toCharArray()

    private fun open(name: String, password: CharArray = pw()): OpenResult = runBlocking {
        storage.put(LOC, fixture(name))
        opener.open(LOC, password)
    }

    // A session open on a fresh test vault, then the file replaced, as another device's save does.
    private suspend fun openedThenChanged(): VaultSession {
        storage.put(LOC, TestVaults.bytes(aesRounds = 1_000UL))
        val session = assertIs<OpenResult.Unlocked>(opener.open(LOC, pw(TestVaults.PASSWORD))).session
        storage.put(LOC, TestVaults.bytes(aesRounds = 1_000UL))
        return session
    }

    @Test
    fun `a session released during the file read stops refresh before any key derivation`() = runBlocking<Unit> {
        val session = openedThenChanged()
        storage.onRead = { session.release() }
        val before = decodes.get()
        assertFailsWith<IllegalStateException> { opener.refresh(LOC, session) }
        assertEquals(before, decodes.get(), "no decode after the lock")
    }

    @Test
    fun `a session released during the file read stops reopen before any key derivation`() = runBlocking<Unit> {
        val session = openedThenChanged()
        storage.onRead = { session.release() }
        val before = decodes.get()
        assertFailsWith<IllegalStateException> { opener.reopen(LOC, session) }
        assertEquals(before, decodes.get(), "no decode after the lock")
    }

    @Test
    fun `refresh and reopen of a changed file decode it once while the session stays open`() = runBlocking<Unit> {
        val session = openedThenChanged()
        val before = decodes.get()
        assertIs<RefreshResult.Reloaded>(opener.refresh(LOC, session))
        assertEquals(before + 1, decodes.get())
        assertIs<OpenResult.Unlocked>(opener.reopen(LOC, session))
        assertEquals(before + 2, decodes.get())
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "keepass2-default-aeskdf.kdbx", "keepass2-desktop-new-database.kdbx", "keepass2-argon2id.kdbx",
            "keepass2-chacha20-argon2d.kdbx", "keepass2-kdbx41-tags.kdbx", "keepass2-weak-aeskdf-6000.kdbx",
        ],
    )
    fun `every KeePass 2 fixture unlocks with its password`(name: String) {
        val unlocked = assertIs<OpenResult.Unlocked>(open(name))
        assertTrue(unlocked.session.index.rows(Chip.All, "").isNotEmpty())
    }

    @Test
    fun `the KeePass 2 password and key file vault opens with both`() = runBlocking<Unit> {
        storage.put(LOC, fixture("keepass2-password-keyfile-v2.kdbx"))
        val unlocked = assertIs<OpenResult.Unlocked>(opener.open(LOC, pw(), keyFile = fixture("keepass2-keyfile-v2.keyx")))
        assertEquals(UnlockOrigin.PASSWORD_AND_KEY_FILE, unlocked.session.opened.origin)
        assertTrue("Example Mail" in unlocked.session.index.rows(Chip.All, "").map { it.title })
        assertEquals(OpenResult.WrongPassword, opener.open(LOC, pw()))
        assertEquals(OpenResult.WrongPassword, opener.open(LOC, pw(), keyFile = fixture("keepass2-keyfile-v1.key")))
    }

    @ParameterizedTest
    @ValueSource(strings = ["v2:keepass2-keyfile-v2.keyx", "v1:keepass2-keyfile-v1.key", "raw32:keepass2-keyfile-raw32.key", "hex64:keepass2-keyfile-hex64.key", "other:keepass2-keyfile-other.key"])
    fun `every KeePass 2 key-file-only vault opens with its key file and an empty password field`(spec: String) = runBlocking<Unit> {
        val (kind, keyFile) = spec.split(':')
        storage.put(LOC, fixture("keepass2-keyfile-only-$kind.kdbx"))
        val unlocked = assertIs<OpenResult.Unlocked>(opener.open(LOC, CharArray(0), keyFile = fixture(keyFile)))
        assertEquals(UnlockOrigin.KEY_FILE_ONLY, unlocked.session.opened.origin)
        assertEquals(1, decodes.get(), "KeePass 2 writes a key-file-only vault without a password")
        val wrong = if (kind == "other") "keepass2-keyfile-raw32.key" else "keepass2-keyfile-other.key"
        assertEquals(OpenResult.WrongPassword, opener.open(LOC, CharArray(0), keyFile = fixture(wrong)))
    }

    @Test
    fun `KDBX 3_1 key-file vaults are unsupported before any key is used`() = runBlocking<Unit> {
        for (file in Kdbx3Vaults.files) {
            storage.put(LOC, file.bytes)
            val result = assertIs<OpenResult.Unsupported>(opener.open(LOC, pw(), keyFile = file.keyFile), file.name)
            assertEquals(UnsupportedReason.FormatVersion(3, 1), result.reason, file.name)
        }
        assertEquals(0, decodes.get())
    }

    @Test
    fun `a wrong password is WrongPassword and leaves the baseline unset`() {
        assertEquals(OpenResult.WrongPassword, open("keepass2-default-aeskdf.kdbx", pw("wrong")))
        assertNull(state.kdfBaseline(LOC))
    }

    @Test
    fun `random bytes, a truncated body and a flipped content byte are damaged`() {
        val good = fixture("keepass2-default-aeskdf.kdbx")
        val cases = listOf(
            Random(1).nextBytes(500),
            good.copyOf(good.size - 40),
            // Middle of the encrypted payload.
            good.copyOf().also { it[it.size / 2] = (it[it.size / 2] + 1).toByte() },
        )
        for (bytes in cases) {
            storage.put(LOC, bytes)
            assertIs<OpenResult.Damaged>(runBlocking { opener.open(LOC, pw()) })
        }
    }

    @Test
    fun `an unsupported cipher is reported without decrypting`() {
        val twofish = RawKdbx.parse(fixture("keepass2-argon2id.kdbx"))
            .withField(RawKdbx.CIPHER_ID, uuidBytes(TWOFISH)).toBytes()
        storage.put(LOC, twofish)
        assertEquals(OpenResult.Unsupported(UnsupportedReason.Cipher(TWOFISH)), runBlocking { opener.open(LOC, pw()) })
        assertEquals(0, decodes.get())
    }

    @ParameterizedTest
    @EnumSource(StorageFailure::class)
    fun `storage failures are Unreadable and nothing is decrypted`(cause: StorageFailure) {
        storage.fail(LOC, cause)
        assertEquals(OpenResult.Unreadable(cause), runBlocking { opener.open(LOC, pw()) })
        assertEquals(0, decodes.get())
    }

    @Test
    fun `on a 256 MiB heap files over the read limit are TooLarge`() {
        maxMemory = 256L * 1024 * 1024
        val limit = maxVaultBytes(maxMemory)
        storage.put(LOC, ByteArray(limit + 1))
        assertEquals(OpenResult.Unreadable(StorageFailure.TOO_LARGE), runBlocking { opener.open(LOC, pw()) })
        storage.put(LOC, ByteArray(limit))
        assertEquals(OpenResult.Damaged(DamageReason.NOT_A_KEEPASS_FILE), runBlocking { opener.open(LOC, pw()) })
        assertEquals(0, decodes.get())
    }

    @Test
    fun `on a 512 MiB heap files over the read limit are TooLarge, the limit exactly is read`() {
        maxMemory = 512L * 1024 * 1024
        val limit = maxVaultBytes(maxMemory)
        storage.put(LOC, ByteArray(limit + 1))
        assertEquals(OpenResult.Unreadable(StorageFailure.TOO_LARGE), runBlocking { opener.open(LOC, pw()) })
        storage.put(LOC, ByteArray(limit))
        assertEquals(OpenResult.Damaged(DamageReason.NOT_A_KEEPASS_FILE), runBlocking { opener.open(LOC, pw()) })
    }

    @Test
    fun `KDBX 3 and an unknown KDF are unsupported without decrypting`() {
        val kdbx3 = RawKdbx.parse(fixture("keepass2-argon2id.kdbx")).copy(major = 3, minor = 1).toBytes()
        storage.put(LOC, kdbx3)
        assertEquals(OpenResult.Unsupported(UnsupportedReason.FormatVersion(3, 1)), runBlocking { opener.open(LOC, pw()) })
        val unknownKdf = RawKdbx.parse(fixture("keepass2-argon2id.kdbx"))
            .withKdf { it.with("\$UUID", RawDictionary.BYTES, uuidBytes(TWOFISH)) }.toBytes()
        storage.put(LOC, unknownKdf)
        assertEquals(OpenResult.Unsupported(UnsupportedReason.Kdf(TWOFISH)), runBlocking { opener.open(LOC, pw()) })
        assertEquals(0, decodes.get())
    }

    @Test
    fun `a non-ASCII password unlocks a vault written with it`() = runBlocking {
        val password = "pässwörd €→😀"
        storage.put(LOC, TestVaults.bytes(password = password))
        assertIs<OpenResult.Unlocked>(opener.open(LOC, password.toCharArray()))
        Unit
    }

    @Test
    fun `a lone surrogate in the password is a wrong password, not damage`() {
        assertEquals(OpenResult.WrongPassword, open("keepass2-default-aeskdf.kdbx", charArrayOf('a', '\uD800')))
    }

    private fun lowMemoryLanes(lanes: Long) = RawKdbx.parse(fixture("keepass2-argon2id.kdbx")).withKdf {
        it.with("M", RawDictionary.UINT64, u64(8_192UL)).with("P", RawDictionary.UINT32, u32(lanes))
    }.toBytesWithHeaderHash()

    @Test
    fun `the heap guard counts the memory Argon2 uses, 8 KiB per lane at least`() = runBlocking {
        maxMemory = 256L * 1024 * 1024
        // 8 KiB stated, 200 MiB used.
        storage.put(LOC, lowMemoryLanes(25_600))
        assertEquals(OpenResult.NotEnoughMemory(), opener.open(LOC, pw()))
        assertEquals(0, derives.get())
        // 8 KiB stated on the most lanes: 128 GiB used, past any array. On a heap that passes the
        // guard the key derivation refuses it before allocating; accepted as slow first.
        storage.put(LOC, lowMemoryLanes(0xFF_FFFF))
        val slow = assertIs<OpenResult.TooSlow>(opener.open(LOC, pw())).slow
        maxMemory = 1L shl 40
        assertEquals(OpenResult.NotEnoughMemory(), opener.open(LOC, pw(), acceptedSlow = slow.kdf))
    }

    @Test
    fun `an Argon2 salt under 8 bytes is damaged, as KeePass 2 refuses it`() = runBlocking {
        storage.put(LOC, org.onekash.kashpass.vault.corpus.Corpus.all.single { it.name == "kdf-argon2-salt-7-bytes" }.bytes)
        assertEquals(OpenResult.Damaged(DamageReason.KDF_PARAMETERS), opener.open(LOC, pw()))
    }

    @Test
    fun `the Argon2 vault with 8 KiB on 4 lanes unlocks, as in KeePass 2`() {
        assertIs<OpenResult.Unlocked>(open("keepass2-argon2-low-memory.kdbx"))
    }

    @Test
    fun `Argon2 memory above half the heap is NotEnoughMemory before key derivation`() {
        maxMemory = 100L * 1024 * 1024
        assertEquals(OpenResult.NotEnoughMemory(), open("keepass2-argon2id.kdbx"))
        assertEquals(0, derives.get())
        maxMemory = 129L * 1024 * 1024
        assertIs<OpenResult.Unlocked>(open("keepass2-argon2id.kdbx"))
    }

    @Test
    fun `StackOverflowError while decoding is an internal failure and writes no baseline`() {
        decode = { _, _, _, _ -> throw StackOverflowError() }
        assertEquals(OpenResult.Failed(DecodeFailure.INTERNAL), open("keepass2-default-aeskdf.kdbx"))
        assertNull(state.kdfBaseline(LOC))
    }

    @Test
    fun `a storage implementation that throws is Unreadable, not a crash`() = runBlocking {
        val throwing = VaultOpener(FakeVaultStorage().apply { throwOnRead(IllegalStateException("provider bug")) }, state, io) { b, h, c, l -> decode(b, h, c, l) }
        assertEquals(OpenResult.Unreadable(StorageFailure.IO_FAILURE), throwing.open(LOC, pw()))
        assertEquals(OpenResult.Unreadable(StorageFailure.IO_FAILURE), throwing.check(LOC))
    }

    @Test
    fun `running out of memory while reading is NotEnoughMemory on check and open, not a crash`() = runBlocking {
        val starved = VaultOpener(FakeVaultStorage().apply { throwOnRead(OutOfMemoryError("Java heap space")) }, state, io) { b, h, c, l -> decode(b, h, c, l) }
        assertEquals(OpenResult.NotEnoughMemory(), starved.open(LOC, pw()))
        assertEquals(OpenResult.NotEnoughMemory(), starved.check(LOC))
        assertEquals(0, decodes.get())
    }

    @Test
    fun `refused and damaged results leave the baseline as it was`() {
        state.saveKdfBaseline(LOC, KdfSettings.AesKdf(700_000UL))
        open("keepass2-default-aeskdf.kdbx")
        storage.put(LOC, ByteArray(10))
        runBlocking { opener.open(LOC, pw()) }
        assertEquals(KdfSettings.AesKdf(700_000UL), state.kdfBaseline(LOC))
    }

    @Test
    fun `Argon2 iterations 0 is refused before any key derivation`() {
        val bytes = RawKdbx.parse(fixture("keepass2-argon2id.kdbx"))
            .withKdf { it.with("I", RawDictionary.UINT64, u64(0UL)) }.toBytes()
        storage.put(LOC, bytes)
        assertEquals(
            OpenResult.Refused(KdfRejection.OutOfBounds(KdfSetting.ARGON2_ITERATIONS, 0UL)),
            runBlocking { opener.open(LOC, pw()) },
        )
        assertEquals(0, decodes.get())
    }

    @Test
    fun `fewer rounds than the last unlock is refused as a downgrade`() {
        state.saveKdfBaseline(LOC, KdfSettings.AesKdf(700_000UL))
        assertEquals(
            OpenResult.Refused(KdfRejection.Weakened(KdfSetting.AES_ROUNDS, 700_000UL, 600_000UL)),
            open("keepass2-default-aeskdf.kdbx"),
        )
        assertEquals(0, decodes.get())
    }

    @Test
    fun `a switch of KDF type with less work than the last unlock is refused as a downgrade`() {
        state.saveKdfBaseline(LOC, KdfSettings.AesKdf(60_000_000UL))
        assertEquals(
            OpenResult.Refused(KdfRejection.Weakened(KdfSetting.WORK_UNITS, 100_000UL, 1_000UL)),
            open("keepass2-argon2id.kdbx"),
        )
        assertEquals(0, decodes.get())
    }

    @Test
    fun `a switch between KeePass 2's default AES-KDF and Argon2 settings opens both ways`() {
        state.saveKdfBaseline(LOC, KdfSettings.AesKdf(600_000UL))
        assertIs<OpenResult.Unlocked>(open("keepass2-argon2id.kdbx"))
        assertIs<KdfSettings.Argon2>(state.kdfBaseline(LOC))
        assertIs<OpenResult.Unlocked>(open("keepass2-default-aeskdf.kdbx"))
        assertEquals(KdfSettings.AesKdf(600_000UL), state.kdfBaseline(LOC))
    }

    @Test
    fun `cancelling an unlock stops the key derivation, and the open ends cancelled with nothing stored`() = runBlocking {
        val rounds = (1UL shl 31) - 1UL
        // 2^31 - 1 AES-KDF rounds take minutes.
        storage.put(LOC, RawKdbx.parse(fixture("keepass2-default-aeskdf.kdbx")).withKdf { it.with("R", RawDictionary.UINT64, u64(rounds)) }.toBytesWithHeaderHash())
        val production = VaultOpener.create(storage, state, io)
        val started = System.nanoTime()
        var result: OpenResult? = null
        val attempt = launch(Dispatchers.Default) { result = production.open(LOC, pw(), acceptedSlow = KdfSettings.AesKdf(rounds)) }
        delay(500)
        attempt.cancelAndJoin()
        assertNull(result)
        assertTrue(attempt.isCancelled)
        assertTrue(System.nanoTime() - started < java.util.concurrent.TimeUnit.SECONDS.toNanos(10))
        assertTrue(Thread.getAllStackTraces().keys.none { it.name.startsWith(KdfEngine.THREAD_NAME) })
        assertNull(state.kdfBaseline(LOC))
    }

    @Test
    fun `the baseline is written only after a successful unlock`() {
        storage.put(LOC, fixture("keepass2-default-aeskdf.kdbx"))
        runBlocking { opener.check(LOC) }
        assertNull(state.kdfBaseline(LOC))
        open("keepass2-default-aeskdf.kdbx", pw("wrong"))
        assertNull(state.kdfBaseline(LOC))
        open("keepass2-default-aeskdf.kdbx")
        assertEquals(KdfSettings.AesKdf(600_000UL), state.kdfBaseline(LOC))
    }

    @Test
    fun `the decrypted bytes are the checked bytes from a single read`() {
        open("keepass2-default-aeskdf.kdbx")
        assertEquals(1, storage.reads)
        assertSame(storage.lastReturned, decodedArray)
    }

    @Test
    fun `storage reads and decryption run on the injected dispatcher`() {
        open("keepass2-default-aeskdf.kdbx")
        // Coroutine debug mode appends " @coroutine#n" to the thread name.
        assertTrue(storage.lastReadThread!!.startsWith("vault-io-test"), storage.lastReadThread)
        assertTrue(decodeThread!!.startsWith("vault-io-test"), decodeThread)
    }

    @Test
    fun `the password array is zero-filled on success and on every failure`() {
        val success = pw()
        open("keepass2-default-aeskdf.kdbx", success)
        val wrong = pw("wrong")
        open("keepass2-default-aeskdf.kdbx", wrong)
        val unreadable = pw()
        storage.fail(LOC, StorageFailure.IO_FAILURE)
        runBlocking { opener.open(LOC, unreadable) }
        val damaged = pw()
        storage.put(LOC, ByteArray(10))
        runBlocking { opener.open(LOC, damaged) }
        val refused = pw()
        state.saveKdfBaseline(LOC, KdfSettings.AesKdf(700_000UL))
        open("keepass2-default-aeskdf.kdbx", refused)
        for (array in listOf(success, wrong, unreadable, damaged, refused)) assertTrue(array.all { it == '\u0000' })
    }

    @Test
    fun `weak settings show the warning until dismissed for those exact settings`() {
        val first = assertIs<OpenResult.Unlocked>(open("keepass2-weak-aeskdf-6000.kdbx"))
        assertTrue(first.showWeakWarning)
        runBlocking { opener.dismissWeakWarning(LOC, first.kdf) }
        assertFalse(assertIs<OpenResult.Unlocked>(open("keepass2-weak-aeskdf-6000.kdbx")).showWeakWarning)

        state.saveWeakWarningDismissed(LOC, KdfSettings.AesKdf(5_000UL))
        assertTrue(assertIs<OpenResult.Unlocked>(open("keepass2-weak-aeskdf-6000.kdbx")).showWeakWarning)
        assertFalse(assertIs<OpenResult.Unlocked>(open("keepass2-default-aeskdf.kdbx")).showWeakWarning)
    }

    @Test
    fun `OutOfMemoryError during key derivation is NotEnoughMemory`() {
        decode = { _, _, _, _ -> throw OutOfMemoryError("test") }
        assertEquals(OpenResult.NotEnoughMemory(), open("keepass2-default-aeskdf.kdbx"))
    }

    @Test
    fun `any other decoding exception is an internal failure, cancellation is rethrown`() {
        decode = { _, _, _, _ -> throw IllegalStateException("test") }
        assertEquals(OpenResult.Failed(DecodeFailure.INTERNAL), open("keepass2-default-aeskdf.kdbx"))
        decode = { _, _, _, _ -> throw CancellationException("test") }
        assertThrows<CancellationException> { open("keepass2-default-aeskdf.kdbx") }
    }

    @Test
    fun `the session holds the baseline of the bytes opened, their size and time, and the saveability`() {
        val bytes = fixture("keepass2-default-aeskdf.kdbx")
        val unlocked = assertIs<OpenResult.Unlocked>(open("keepass2-default-aeskdf.kdbx"))
        val opened = unlocked.session.opened
        val sha = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals(OpenedVault.Baseline.Known(sha), opened.baseline)
        assertEquals(bytes.size.toLong(), opened.openedSize)
        assertEquals(Saveability.Saveable, unlocked.session.saveability)
        val doctype = TestVaults.rawXmlVault(TestVaults.keePassXml(prolog = "<!DOCTYPE KeePassFile>\n"))
        storage.put(LOC, doctype)
        // A different vault at the same place: forget the first one's KDF baseline.
        state.clear(LOC)
        val readOnly = assertIs<OpenResult.Unlocked>(runBlocking { opener.open(LOC, TestVaults.PASSWORD.toCharArray()) })
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.DOCTYPE), readOnly.session.saveability)
    }

    @Test
    fun `release drops the vault and the index, and a session rebuilt from the vault matches`() {
        val unlocked = assertIs<OpenResult.Unlocked>(open("keepass2-kdbx41-tags.kdbx"))
        val session = unlocked.session
        val rebuilt = VaultSession.from(session.opened.withDocument(session.opened.document))
        assertEquals(session.index.rows(Chip.All, ""), rebuilt.index.rows(Chip.All, ""))
        assertEquals(session.opened.baseline, rebuilt.opened.baseline)
        session.release()
        assertThrows<IllegalStateException> { session.opened }
        assertEquals("VaultSession(open=false)", session.toString())
        // The rebuilt session shares the document and credentials, and is unaffected.
        assertTrue(rebuilt.index.rows(Chip.All, "").isNotEmpty())
        assertEquals(Saveability.Saveable, rebuilt.saveability)
    }

    @Test
    fun `XML too large for memory is NotEnoughMemory and damaged XML is Damaged`() {
        val notes = "a".repeat(2 * 1024 * 1024)
        storage.put(LOC, TestVaults.rawXmlVault(TestVaults.keePassXml(entries = "<Entry><String><Key>Notes</Key><Value>$notes</Value></String></Entry>")))
        maxMemory = 4L * 1024 * 1024
        assertEquals(OpenResult.NotEnoughMemory(), runBlocking { opener.open(LOC, TestVaults.PASSWORD.toCharArray()) })
        maxMemory = Long.MAX_VALUE
        storage.put(LOC, TestVaults.rawXmlVault("<NotKeePass/>"))
        assertEquals(OpenResult.Damaged(DamageReason.XML), runBlocking { opener.open(LOC, TestVaults.PASSWORD.toCharArray()) })
    }

    @Test
    fun `check reports Ready, weakness, refusal and damage without a password`() = runBlocking {
        storage.put(LOC, fixture("keepass2-default-aeskdf.kdbx"))
        assertEquals(OpenResult.Ready(KdfSettings.AesKdf(600_000UL), weak = false), opener.check(LOC))
        storage.put(LOC, fixture("keepass2-weak-aeskdf-6000.kdbx"))
        assertEquals(OpenResult.Ready(KdfSettings.AesKdf(6_000UL), weak = true), opener.check(LOC))
        storage.put(LOC, ByteArray(10))
        assertEquals(OpenResult.Damaged(DamageReason.NOT_A_KEEPASS_FILE), opener.check(LOC))
        state.saveKdfBaseline(LOC, KdfSettings.AesKdf(700_000UL))
        storage.put(LOC, fixture("keepass2-default-aeskdf.kdbx"))
        assertIs<OpenResult.Refused>(opener.check(LOC))
        assertEquals(0, decodes.get())
    }

    @Test
    fun `release drops the session's index`() {
        val unlocked = assertIs<OpenResult.Unlocked>(open("keepass2-default-aeskdf.kdbx"))
        unlocked.session.release()
        assertFalse(unlocked.session.isOpen)
        assertThrows<IllegalStateException> { unlocked.session.index }
    }

    @Test
    fun `a session-only open opens read-only and stores nothing for the file`() = runBlocking {
        val rig = OpenRig()
        rig.storage.put(rig.loc, OpenRig.vault)
        rig.markers.set(rig.loc, "old", "new")
        val ready = assertIs<OpenResult.Ready>(rig.opener.check(rig.loc, FileAccess.SESSION_ONLY))
        assertFalse(ready.lostCutOffSave)
        val unlocked = assertIs<OpenResult.Unlocked>(
            rig.opener.open(rig.loc, TestVaults.PASSWORD.toCharArray(), access = FileAccess.SESSION_ONLY),
        )
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.OPENED_FROM_APP), unlocked.session.saveability)
        assertEquals(FileAccess.SESSION_ONLY, unlocked.session.opened.access)
        assertNotNull(unlocked.fileNewest)
        assertNull(unlocked.olderThan)
        assertNull(rig.state.kdfBaseline(rig.loc))
        assertNull(rig.state.newestSeen(rig.loc))
        assertTrue(rig.backups.attempts.isEmpty())
        assertEquals(SaveMarker("old", "new"), rig.markers.get(rig.loc))
    }

    @Test
    fun `a session-only open never reaches the real stores`() = runBlocking {
        val storage = FakeVaultStorage()
        val state = FakeVaultStateStore().apply { refuseAll = true }
        val backups = FakeBackupStore().apply { refuseAll = true }
        val markers = FakeSaveMarkerStore().apply { refuseAll = true }
        val opener = VaultOpener(storage, state, io, backups = backups, markers = markers) { b, h, c, l -> VaultXmlCodec.decode(b, h, c, l) }
        val session = FileAccess.SESSION_ONLY
        storage.put(LOC, OpenRig.vault)
        assertIs<OpenResult.Ready>(opener.check(LOC, session))
        val first = assertIs<OpenResult.Unlocked>(opener.open(LOC, pw(), access = session))
        val key = first.session.unlockKey()!!
        val withKey = assertIs<OpenResult.Unlocked>(opener.openWithKey(LOC, key, access = session))
        val reopened = assertIs<OpenResult.Unlocked>(opener.reopen(LOC, withKey.session))
        storage.put(LOC, OpenRig().retitled(reopened.session.opened.document, "Changed"))
        val refreshed = assertIs<RefreshResult.Reloaded>(opener.refresh(LOC, reopened.session))
        val backup = BackupInfo("id", Instant.EPOCH, 1, BackupKind.OPENED, "00")
        val notFound = OpenResult.Unreadable(StorageFailure.NOT_FOUND)
        assertEquals(notFound, opener.openBackup(LOC, backup, pw(), access = session))
        assertEquals(notFound, opener.openBackup(LOC, backup, refreshed.opened.session))
        storage.put(LOC, ByteArray(10))
        assertIs<OpenResult.Damaged>(opener.check(LOC, session))
        assertIs<OpenResult.Damaged>(opener.open(LOC, pw(), access = session))
        storage.fail(LOC, StorageFailure.IO_FAILURE)
        assertEquals(OpenResult.Unreadable(StorageFailure.IO_FAILURE), opener.open(LOC, pw(), access = session))
        // The opener ignores a failed backup, so a refused call shows only in the records.
        assertEquals(emptyList(), state.refused + backups.refused + markers.refused)
    }

    @Test
    fun `a session-only open checks against no stored settings and offers no last copy`() = runBlocking {
        val rig = OpenRig()
        rig.storage.put(rig.loc, OpenRig.vault)
        rig.unlock()
        // A stronger baseline would refuse this file as a downgrade for the remembered vault.
        rig.state.saveKdfBaseline(rig.loc, KdfSettings.AesKdf(600_000UL))
        assertIs<OpenResult.Refused>(rig.opener.check(rig.loc))
        assertIs<OpenResult.Ready>(rig.opener.check(rig.loc, FileAccess.SESSION_ONLY))
        rig.storage.put(rig.loc, ByteArray(10))
        assertEquals(OpenResult.Damaged(DamageReason.NOT_A_KEEPASS_FILE), rig.opener.check(rig.loc, FileAccess.SESSION_ONLY))
        assertEquals(
            OpenResult.Damaged(DamageReason.NOT_A_KEEPASS_FILE),
            rig.opener.open(rig.loc, TestVaults.PASSWORD.toCharArray(), access = FileAccess.SESSION_ONLY),
        )
    }

    @Test
    fun `reload and refresh of a session-only vault stay read-only and store nothing`() = runBlocking {
        val rig = OpenRig()
        rig.storage.put(rig.loc, OpenRig.vault)
        val first = rig.opener.open(rig.loc, TestVaults.PASSWORD.toCharArray(), access = FileAccess.SESSION_ONLY) as OpenResult.Unlocked
        val reopened = assertIs<OpenResult.Unlocked>(rig.opener.reopen(rig.loc, first.session))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.OPENED_FROM_APP), reopened.session.saveability)
        rig.storage.put(rig.loc, rig.retitled(first.session.opened.document, "Changed"))
        val refreshed = assertIs<RefreshResult.Reloaded>(rig.opener.refresh(rig.loc, reopened.session))
        assertEquals(FileAccess.SESSION_ONLY, refreshed.opened.session.opened.access)
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.OPENED_FROM_APP), refreshed.opened.session.saveability)
        assertNull(rig.state.kdfBaseline(rig.loc))
        assertNull(rig.state.newestSeen(rig.loc))
        assertTrue(rig.backups.attempts.isEmpty())
    }

    @Test
    fun `a provider read-only vault opens read-only and is remembered like the file`() = runBlocking {
        val rig = OpenRig()
        rig.storage.put(rig.loc, OpenRig.vault)
        val unlocked = assertIs<OpenResult.Unlocked>(
            rig.opener.open(rig.loc, TestVaults.PASSWORD.toCharArray(), access = FileAccess.PROVIDER_READ_ONLY),
        )
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.PROVIDER_READ_ONLY), unlocked.session.saveability)
        assertEquals(KdfSettings.AesKdf(1_000UL), rig.state.kdfBaseline(rig.loc))
        assertEquals(1, rig.backups.list(rig.loc).size)
        val key = unlocked.session.unlockKey()!!
        val withKey = assertIs<OpenResult.Unlocked>(rig.opener.openWithKey(rig.loc, key, access = FileAccess.PROVIDER_READ_ONLY))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.PROVIDER_READ_ONLY), withKey.session.saveability)
    }

    @Test
    fun `provider read-only access survives a reload, a refresh and a backup closed again`() = runBlocking {
        val rig = OpenRig()
        rig.storage.put(rig.loc, OpenRig.vault)
        val first = rig.opener.open(rig.loc, TestVaults.PASSWORD.toCharArray(), access = FileAccess.PROVIDER_READ_ONLY) as OpenResult.Unlocked
        val reopened = assertIs<OpenResult.Unlocked>(rig.opener.reopen(rig.loc, first.session))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.PROVIDER_READ_ONLY), reopened.session.saveability)
        rig.storage.put(rig.loc, rig.retitled(first.session.opened.document, "Changed"))
        val refreshed = assertIs<RefreshResult.Reloaded>(rig.opener.refresh(rig.loc, reopened.session))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.PROVIDER_READ_ONLY), refreshed.opened.session.saveability)
        val backup = rig.backups.list(rig.loc).last()
        val inBackup = assertIs<OpenResult.Unlocked>(rig.opener.openBackup(rig.loc, backup, refreshed.opened.session))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.BACKUP), inBackup.session.saveability)
        val closed = assertIs<OpenResult.Unlocked>(rig.opener.reopen(rig.loc, inBackup.session))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.PROVIDER_READ_ONLY), closed.session.saveability)
    }

    @Test
    fun `provider read-only access is its own field, kept when the content is read-only too`() = runBlocking {
        val rig = OpenRig()
        rig.storage.put(rig.loc, TestVaults.rawXmlVault(TestVaults.keePassXml(prolog = "<!DOCTYPE KeePassFile>\n")))
        val opened = rig.opener.open(rig.loc, TestVaults.PASSWORD.toCharArray(), access = FileAccess.PROVIDER_READ_ONLY) as OpenResult.Unlocked
        val reopened = assertIs<OpenResult.Unlocked>(rig.opener.reopen(rig.loc, opened.session))
        assertEquals(FileAccess.PROVIDER_READ_ONLY, reopened.session.opened.access)
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.PROVIDER_READ_ONLY), reopened.session.saveability)
        val plain = rig.opener.open(rig.loc, TestVaults.PASSWORD.toCharArray()) as OpenResult.Unlocked
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.DOCTYPE), plain.session.saveability)
        assertEquals(FileAccess.READ_WRITE, plain.session.opened.access)
    }

    private companion object {
        const val LOC = "content://test/vault.kdbx"
        const val PASSWORD = "kashpass-test"
        const val TWOFISH = "ad68f29f-576f-4bb9-a36a-d47af965346c"
    }
}
