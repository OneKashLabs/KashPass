package org.onekash.kashpass.vault.open

import java.security.MessageDigest
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.CorpusCase
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.doc.VaultKey
import org.onekash.kashpass.vault.doc.CheckedHeader
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.HeaderRead
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.fixtures.CredentialMode
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.header.UnsupportedReason
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.RecordingBuffers
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.kdbx.KdfParameters as KdbxKdfParameters

/**
 * Every open goes through KashPass's own container: the corpus outcome reaches the opener's result
 * unchanged, one header read feeds every check, the stored baseline and the derivation, and the
 * downgrade check compares Argon2 work with the stated memory raised to 8 KiB per lane.
 */
class OwnedOpenPathTest {

    private val loc = "content://fake/vault.kdbx"

    /**
     * An opener over fakes that records header reads and derivations, at the corpus limits, its
     * memory limits computed for a heap of [heap].
     */
    private class Probe(val state: FakeVaultStateStore = FakeVaultStateStore(), heap: Long = Long.MAX_VALUE) {
        val storage = FakeVaultStorage()
        var headerReads = 0
        val headers = mutableListOf<CheckedHeader>()
        val derived = mutableListOf<KdbxKdfParameters>()
        var buffers: org.onekash.kashpass.vault.kdbx.Buffers = org.onekash.kashpass.vault.kdbx.Buffers.Default
        val opener = VaultOpener(
            storage, state, Dispatchers.IO,
            maxHeapBytes = { heap },
            readHeader = { b, heap -> headerReads++; VaultXmlCodec.header(b, heap).also { if (it is HeaderRead.Valid) headers += it.header } },
        ) { b, h, c, budget ->
            VaultXmlCodec.decode(
                b, h, c, VaultXmlCodec.Budget(ContainerRig.LIMITS, budget.readLimitBytes, budget.maxHeapBytes),
                derive = { p, k -> derived += p; ContainerRig.derive(p, k) }, buffers = buffers,
            )
        }

        /** Opens [file] at [location] with its throwaway credentials, accepting slow settings. */
        fun open(location: String, file: VaultFile): OpenResult = runBlocking {
            storage.put(location, file.bytes)
            val password = (TestFiles.password(file.mode) ?: "")
            val first = opener.open(location, password.toCharArray(), keyFile = file.keyFile?.copyOf())
            if (first !is OpenResult.TooSlow) return@runBlocking first
            headerReads = 0
            opener.open(location, password.toCharArray(), acceptedSlow = first.slow.kdf, keyFile = file.keyFile?.copyOf())
        }
    }

    private fun outcome(r: OpenResult): String = when (r) {
        is OpenResult.Unlocked -> if (r.session.saveability == Saveability.Saveable) "OPENS" else "OPENS_READ_ONLY"
        is OpenResult.Refused -> "REFUSED_BY_POLICY"
        OpenResult.WrongPassword -> "WRONG_KEY"
        is OpenResult.Damaged -> "DAMAGED ${if (r.reason == DamageReason.NOT_A_KEEPASS_FILE) "NOT_A_KDBX_FILE" else r.reason.name}"
        is OpenResult.Unsupported -> "UNSUPPORTED"
        is OpenResult.NotEnoughMemory -> "NOT_ENOUGH_MEMORY"
        else -> r.toString()
    }

    private fun expected(c: CorpusCase): String = if (c.spec == Spec.DAMAGED) "DAMAGED ${c.damage}" else c.spec.name

    @Test
    fun `every corpus case reaches the opener with its recorded outcome and trailing-bytes flag`() {
        var trailing = 0
        val wrong = Corpus.all.mapNotNull { c ->
            val result = Probe(heap = c.heapBytes ?: Long.MAX_VALUE).open(loc, c.file())
            val got = outcome(result)
            if (got != expected(c)) return@mapNotNull "${c.name}: $got, expected ${expected(c)}"
            if (result is OpenResult.Unlocked) {
                val read = assertIs<ContainerDecode.Result.Opened>(ContainerRig.open(c)).read
                if (read.container.bytesAfterEnd) trailing++
                if (result.bytesAfterEnd != read.container.bytesAfterEnd) return@mapNotNull "${c.name}: bytesAfterEnd ${result.bytesAfterEnd}"
            }
            null
        }
        assertTrue(wrong.isEmpty(), "${wrong.size} cases:\n" + wrong.joinToString("\n"))
        assertTrue(trailing > 0, "no corpus case has bytes after the end block")
    }

    @Test
    fun `every KDBX 4 fixture opens through the opener without trailing bytes`() {
        for (file in Fixtures.kdbx4Opening.map(Fixtures::file)) {
            val unlocked = assertIs<OpenResult.Unlocked>(Probe().open(loc, file), file.name)
            assertFalse(unlocked.bytesAfterEnd, file.name)
        }
    }

    @Test
    fun `one header read feeds the KDF checks, the stored baseline and the derivation, for every fold ordering`() {
        val cases = Corpus.all.filter { it.name.startsWith("kdbx3-") || Regex("""^kdf-.*-then-""").containsMatchIn(it.name) }
        assertTrue(cases.size >= 15)
        var unlocked = 0
        for (c in cases) {
            val probe = Probe()
            val result = probe.open(loc, c.file())
            assertTrue(probe.headerReads == 1, "${c.name}: ${probe.headerReads} header reads")
            if (probe.derived.isNotEmpty()) {
                val header = probe.headers.last()
                assertTrue(probe.derived.all { it === header.outer.kdf }, "${c.name}: derived with other parameters")
                if (result is OpenResult.Unlocked) {
                    unlocked++
                    assertSame(header.kdf, result.kdf, c.name)
                    assertSame(header.kdf, probe.state.kdfBaseline(loc), c.name)
                }
            }
        }
        assertTrue(unlocked >= 10, "$unlocked unlocked")
    }

    private fun argon2Vault(lanes: UInt, iterations: ULong): ByteArray = KdbxToolkit.newVault(
        TestVaults.keePassXml().toByteArray(Charsets.UTF_8), emptyList(), KdbxToolkit.Key(TestVaults.PASSWORD),
        KdbxToolkit.Kdf.Argon2(true, ByteArray(32) { it.toByte() }, lanes, 64UL shl 20, iterations, 0x13U, null, null),
    )

    @Test
    fun `the downgrade check compares Argon2 work with the memory raised to 8 KiB per lane and no rounding`() = runBlocking<Unit> {
        val state = FakeVaultStateStore()
        val opener = VaultOpener(FakeVaultStorage().also { it.put(loc, argon2Vault(lanes = 2U, iterations = 2UL)) }, state, Dispatchers.IO) { b, h, c, budget ->
            VaultXmlCodec.decode(b, h, c, budget)
        }
        assertIs<OpenResult.Unlocked>(opener.open(loc, TestVaults.PASSWORD.toCharArray()))
        val threeLanes = VaultOpener(FakeVaultStorage().also { it.put(loc, argon2Vault(lanes = 3U, iterations = 2UL)) }, state, Dispatchers.IO) { b, h, c, budget ->
            VaultXmlCodec.decode(b, h, c, budget)
        }
        assertIs<OpenResult.Unlocked>(threeLanes.open(loc, TestVaults.PASSWORD.toCharArray()))
        var derived = false
        val fewer = VaultOpener(FakeVaultStorage().also { it.put(loc, argon2Vault(lanes = 3U, iterations = 1UL)) }, state, Dispatchers.IO) { b, h, c, budget ->
            VaultXmlCodec.decode(b, h, c, budget, derive = { _, _ -> derived = true; ByteArray(32) })
        }
        assertIs<KdfRejection.Weakened>(assertIs<OpenResult.Refused>(fewer.open(loc, TestVaults.PASSWORD.toCharArray())).rejection)
        assertFalse(derived)
        assertIs<KdfSettings.Argon2>(state.kdfBaseline(loc))
    }

    private fun sha256(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").apply { parts.forEach(::update) }.digest()

    @Test
    fun `a stored key unlocks through KashPass's decoder, alone and with a key file`() = runBlocking<Unit> {
        val key = sha256(TestVaults.PASSWORD.toByteArray())
        val rig = OpenRig()
        rig.storage.put(rig.loc, OpenRig.vault)
        assertIs<OpenResult.Unlocked>(rig.opener.openWithKey(rig.loc, key.copyOf()))
        rig.storage.put(rig.loc, OpenRig.keyFileVault)
        assertIs<OpenResult.Unlocked>(rig.opener.openWithKey(rig.loc, key.copyOf(), keyFile = TestVaults.KEY_FILE.copyOf()))
    }

    @Test
    fun `an open leaves no decrypted buffer behind but the attachments and the XML the document holds`() {
        // The document's XML array is the one exception besides attachments: a save copies the
        // unchanged nodes from it, so it lives until lock drops the document.
        fun held(unlocked: OpenResult.Unlocked): Array<ByteArray> {
            val document = unlocked.session.opened.document
            return (document.attachments.map { it.data } + document.xml.source.bytes).toTypedArray()
        }
        for (name in listOf("keepass2-shared-attachments.kdbx", "keepass2-multiblock-attachment.kdbx", "keepass2-default-aeskdf.kdbx")) {
            val file = Fixtures.file(Fixtures.named(name))
            val buffers = RecordingBuffers()
            val probe = Probe().also { it.buffers = buffers }
            val unlocked = assertIs<OpenResult.Unlocked>(probe.open(loc, file), name)
            assertTrue(buffers.byteSizes.isNotEmpty(), name)
            buffers.assertAllZeroExcept(*held(unlocked))
        }
        // A Meta/Binaries item replaces a pool slot that an entry reference read earlier.
        val replaced = Corpus.all.single { it.name == "spec-meta-binary-after-root-replaces-0" }.file()
        val buffers = RecordingBuffers()
        val unlocked = assertIs<OpenResult.Unlocked>(Probe().also { it.buffers = buffers }.open(loc, replaced))
        buffers.assertAllZeroExcept(*held(unlocked))
        val failures = mapOf(
            "spec-date-iso" to OpenResult.Damaged::class, "block-end-hmac-wrong" to OpenResult.Damaged::class,
            "xml-header-hash-wrong" to OpenResult.Damaged::class, "credentials-wrong-password" to OpenResult.WrongPassword::class,
            "inner-stream-id-4" to OpenResult.Unsupported::class, "spec-meta-binary-id-negative" to OpenResult.Damaged::class,
        )
        for ((case, kind) in failures) {
            val recording = RecordingBuffers()
            val probe = Probe().also { it.buffers = recording }
            val result = probe.open(loc, Corpus.all.single { it.name == case }.file())
            assertTrue(kind.isInstance(result), "$case: $result")
            recording.assertAllZero()
        }
    }

    @Test
    fun `each unsupported setting reaches the opener with its reason and whether the key was checked`() {
        val expected = mapOf(
            "header-stream-id-10-is-4" to UnsupportedReason.InnerStream(4, keyChecked = false),
            "inner-stream-id-4" to UnsupportedReason.InnerStream(4, keyChecked = true),
            "inner-stream-id-0" to UnsupportedReason.InnerStream(0, keyChecked = true),
            "dict-version-2-0" to UnsupportedReason.DictionaryVersion(2),
            "dict-unknown-type" to UnsupportedReason.DictionaryValueType(0x7F),
            "spec-compression-id-2" to UnsupportedReason.Compression(2),
        )
        for ((case, reason) in expected) {
            assertEquals(OpenResult.Unsupported(reason), Probe().open(loc, Corpus.all.single { it.name == case }.file()), case)
        }
    }

    @Test
    fun `a decode failure after the container opened is an internal failure, never damage`() = runBlocking<Unit> {
        val rig = OpenRig()
        rig.storage.put(rig.loc, OpenRig.vault)
        val failing = VaultOpener(rig.storage, rig.state, Dispatchers.IO) { _, _, _, _ -> Decoded.Failed(org.onekash.kashpass.vault.doc.DecodeFailure.INTERNAL) }
        assertEquals(OpenResult.Failed(org.onekash.kashpass.vault.doc.DecodeFailure.INTERNAL), failing.open(rig.loc, TestVaults.PASSWORD.toCharArray()))
    }

    @Test
    fun `a file over the read limit is too large with no last copy, content over the limit is not enough memory`() = runBlocking<Unit> {
        val rig = OpenRig()
        rig.backups.add(rig.loc, OpenRig.vault, org.onekash.kashpass.vault.backup.BackupKind.OPENED)
        rig.storage.put(rig.loc, OpenRig.weaker)
        val tooLarge = VaultOpener(rig.storage, rig.state, Dispatchers.IO, backups = rig.backups) { _, _, _, _ -> Decoded.TooLarge(10) }
        assertEquals(OpenResult.Unreadable(org.onekash.kashpass.vault.storage.StorageFailure.TOO_LARGE), tooLarge.open(rig.loc, TestVaults.PASSWORD.toCharArray()))
        val memory = VaultOpener(rig.storage, rig.state, Dispatchers.IO, backups = rig.backups) { _, _, _, _ -> Decoded.NotEnoughMemory }
        assertEquals(OpenResult.NotEnoughMemory(), memory.open(rig.loc, TestVaults.PASSWORD.toCharArray()))
    }

    @Test
    fun `a key-file-only fixture opens through the opener`() {
        val file = Fixtures.file(Fixtures.kdbx4Opening.first { it.mode == CredentialMode.KEY_FILE_ONLY })
        assertIs<OpenResult.Unlocked>(Probe().open(loc, file))
    }
}
