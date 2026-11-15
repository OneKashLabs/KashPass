package org.onekash.kashpass.vault.kdbx

import java.util.UUID
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.CorpusCase
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawEntry
import org.onekash.kashpass.vault.testing.RawField
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.le32
import org.onekash.kashpass.vault.testing.le64
import org.onekash.kashpass.vault.testing.uuidBytes

class KdbxHeaderReaderTest {

    private val weak = RawKdbx.parse(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"))

    private fun read(raw: RawKdbx) = KdbxHeaderReader.read(raw.toBytes())

    private fun valid(raw: RawKdbx): OuterHeader = assertIs<KdbxHeaderReader.Read.Valid>(read(raw)).header

    private fun invalid(raw: RawKdbx): KdbxResult = assertIs<KdbxHeaderReader.Read.Invalid>(read(raw)).result

    private fun signature(second: Int) = le32(0x9AA2D903.toInt()) + le32(second)

    @ParameterizedTest
    @MethodSource("fixtures")
    fun `every KDBX 4 fixture reads with the settings KeePass 2 folds from its fields`(name: String) {
        val bytes = Fixtures.bytes(name)
        val raw = RawKdbx.parse(bytes)
        val header = valid(raw)
        val effective = KdbxToolkit.effective(raw)
        assertEquals(raw.headerBytes().size, header.length)
        assertContentEquals(effective.seed, header.masterSeed)
        assertContentEquals(effective.iv, header.iv)
        assertEquals(if (effective.gzip) Compression.GZIP else Compression.NONE, header.compression)
        assertEquals(KdbxSignature.NORMAL, header.signature)
        assertEquals(4, header.majorVersion)
        assertSameKdf(effective.kdf, header.kdf, name)
    }

    @Test
    fun `the pre-release signature reads, KeePass 1 is unsupported and any other is not a KDBX file`() {
        assertEquals(KdbxSignature.PRE_RELEASE, valid(weak.copy(signature = signature(0xB54BFB66.toInt()))).signature)
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.FormatVersion(1, 0)), invalid(weak.copy(signature = signature(0xB54BFB65.toInt()))))
        assertEquals(KdbxResult.Damaged(KdbxDamage.NOT_A_KDBX_FILE), invalid(weak.copy(signature = signature(0xB54BFB68.toInt()))))
        assertEquals(KdbxResult.Damaged(KdbxDamage.NOT_A_KDBX_FILE), invalid(weak.copy(signature = le32(1) + le32(0xB54BFB67.toInt()))))
    }

    @Test
    fun `major 4 with any minor reads, any other major is unsupported`() {
        assertEquals(2, valid(weak.copy(minor = 2)).minorVersion)
        assertEquals(65_535, valid(weak.copy(minor = 65_535)).minorVersion)
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.FormatVersion(3, 1)), invalid(weak.copy(major = 3, minor = 1)))
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.FormatVersion(5, 0)), invalid(weak.copy(major = 5, minor = 0)))
    }

    @Test
    fun `an unknown field is skipped, a repeated field keeps its last value`() {
        valid(weak.insertBefore(RawKdbx.END_OF_HEADER, RawField(13, ByteArray(7))))
        val iv = ByteArray(16) { 9 }
        assertContentEquals(iv, valid(weak.insertBefore(RawKdbx.END_OF_HEADER, RawField(RawKdbx.ENCRYPTION_IV, iv))).iv)
    }

    @Test
    fun `field sizes and ids are checked as KeePass 2 checks them`() {
        val damaged = KdbxResult.Damaged(KdbxDamage.HEADER_FIELD)
        assertEquals(damaged, invalid(weak.withField(RawKdbx.MASTER_SEED, ByteArray(31))))
        assertEquals(damaged, invalid(weak.withoutField(RawKdbx.MASTER_SEED)))
        assertEquals(damaged, invalid(weak.withField(RawKdbx.CIPHER_ID, ByteArray(15))))
        assertEquals(damaged, invalid(weak.withField(RawKdbx.CIPHER_ID, ByteArray(17))))
        assertEquals(damaged, invalid(weak.withField(RawKdbx.COMPRESSION, ByteArray(5))))
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.Compression(2)), invalid(weak.withField(RawKdbx.COMPRESSION, le32(2))))
        val twofish = UUID.fromString("ad68f29f-576f-4bb9-a36a-d47af965346c")
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.Cipher(twofish)), invalid(weak.withField(RawKdbx.CIPHER_ID, uuidBytes(twofish.toString()))))
        val withId = { id: ByteArray -> weak.insertBefore(RawKdbx.END_OF_HEADER, RawField(RawKdbx.INNER_RANDOM_STREAM_ID, id)) }
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.InnerStream(4)), invalid(withId(le32(4))))
        assertEquals(damaged, invalid(withId(ByteArray(3))))
        assertEquals(3, valid(withId(le32(3))).innerStreamIdFallback)
        assertNull(valid(weak).innerStreamIdFallback)
        assertEquals(KdbxResult.Damaged(KdbxDamage.HEADER_FIELD), invalid(weak.withLength(1, -1)))
        assertEquals(KdbxResult.Damaged(KdbxDamage.TRUNCATED), invalid(weak.withLength(1, Int.MAX_VALUE)))
    }

    @Test
    fun `the IV is kept as read, its size is the decoder's to check`() {
        assertContentEquals(ByteArray(12), valid(weak.withField(RawKdbx.ENCRYPTION_IV, ByteArray(12))).iv)
        assertContentEquals(ByteArray(0), valid(weak.withoutField(RawKdbx.ENCRYPTION_IV)).iv)
    }

    @Test
    fun `KDF parameters are read as the KDFs read them`() {
        val d = weak.kdf()
        val damaged = KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS)
        assertEquals(damaged, invalid(weak.withKdf { it.without("S") }))
        assertEquals(damaged, invalid(weak.withKdf { it.with("R", RawDictionary.UINT32, le32(6000)) }))
        assertEquals(damaged, invalid(weak.withKdf { it.with("\$UUID", RawDictionary.BYTES, ByteArray(15)) }))
        val other = UUID.fromString("00000000-0000-0000-0000-000000000001")
        assertEquals(KdbxResult.Unsupported(KdbxUnsupported.Kdf(other)), invalid(weak.withKdf { it.with("\$UUID", RawDictionary.BYTES, uuidBytes(other.toString())) }))
        val aes = assertIs<KdfParameters.Aes>(valid(weak).kdf)
        assertEquals(6_000UL, aes.rounds)
        assertContentEquals(d.entries.single { it.key == "S" }.value, aes.seed)
    }

    @Test
    fun `Argon2 numbers that are missing or of another type read as 0, a short salt is damaged`() {
        val argon = RawKdbx.parse(Fixtures.bytes("keepass2-argon2id.kdbx"))
        val parameters = assertIs<KdfParameters.Argon2>(valid(argon.withKdf { it.without("P").with("I", RawDictionary.UINT32, le32(2)) }).kdf)
        assertEquals(0U, parameters.parallelism)
        assertEquals(0UL, parameters.iterations)
        assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), invalid(argon.withKdf { it.with("S", RawDictionary.BYTES, ByteArray(7)) }))
        assertNull(assertIs<KdfParameters.Argon2>(valid(argon.withKdf { it.with("K", RawDictionary.UINT32, le32(1)) }).kdf).secretKey)
        assertEquals(8, assertIs<KdfParameters.Argon2>(valid(argon.withKdf { it.with("S", RawDictionary.BYTES, ByteArray(8)) }).kdf).salt.size)
    }

    @Test
    fun `an Argon2 salt longer than KeePass 2's maximum is damaged, one at the maximum reads`() {
        assertEquals(0x3FFFFFFF, KdbxHeaderReader.MAX_SALT)
        // A salt that long needs a file past any read limit, so the limit is lowered to the
        // fixture's 32-byte salt to reach the same branch.
        val bytes = Fixtures.bytes("keepass2-argon2id.kdbx")
        val atMax = KdbxHeaderReader.read(bytes, maxSaltBytes = 32)
        assertEquals(32, assertIs<KdfParameters.Argon2>(assertIs<KdbxHeaderReader.Read.Valid>(atMax).header.kdf).salt.size)
        val over = KdbxHeaderReader.read(bytes, maxSaltBytes = 31)
        assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), assertIs<KdbxHeaderReader.Read.Invalid>(over).result)
    }

    @Test
    fun `fields 5 and 6 fold into the KDF in file order`() {
        val argon = RawKdbx.parse(Fixtures.bytes("keepass2-argon2id.kdbx"))
        val seed = ByteArray(32) { 4 }
        // Before field 11: no effect.
        val before = argon.insertBefore(RawKdbx.KDF_PARAMETERS, RawField(RawKdbx.TRANSFORM_ROUNDS, le64(7)))
        assertIs<KdfParameters.Argon2>(valid(before).kdf)
        // After an Argon2 field 11: rounds alone leave AES-KDF without a seed.
        val rounds = argon.insertBefore(RawKdbx.END_OF_HEADER, RawField(RawKdbx.TRANSFORM_ROUNDS, le64(7)))
        assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), invalid(rounds))
        val both = rounds.insertBefore(RawKdbx.END_OF_HEADER, RawField(RawKdbx.TRANSFORM_SEED, seed))
        val aes = assertIs<KdfParameters.Aes>(valid(both).kdf)
        assertEquals(7UL, aes.rounds)
        assertContentEquals(seed, aes.seed)
        // After an AES-KDF field 11: only the rounds change.
        val weakRounds = assertIs<KdfParameters.Aes>(valid(weak.insertBefore(RawKdbx.END_OF_HEADER, RawField(RawKdbx.TRANSFORM_ROUNDS, le64(9)))).kdf)
        assertEquals(9UL, weakRounds.rounds)
        assertContentEquals(assertIs<KdfParameters.Aes>(valid(weak).kdf).seed, weakRounds.seed)
        assertEquals(KdbxResult.Damaged(KdbxDamage.HEADER_FIELD), invalid(weak.insertBefore(RawKdbx.END_OF_HEADER, RawField(RawKdbx.TRANSFORM_ROUNDS, ByteArray(4)))))
        // No field 11 at all: the default AES-KDF, 600,000 rounds, needs field 5.
        val none = weak.withoutField(RawKdbx.KDF_PARAMETERS)
        assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), invalid(none))
        assertEquals(600_000UL, assertIs<KdfParameters.Aes>(valid(none.insertBefore(RawKdbx.END_OF_HEADER, RawField(RawKdbx.TRANSFORM_SEED, seed))).kdf).rounds)
    }

    @Test
    fun `a KDF field without a 16-byte UUID is damaged even when a valid one follows`() {
        val noUuid = RawField(RawKdbx.KDF_PARAMETERS, weak.kdf().without("\$UUID").toBytes())
        assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), invalid(weak.insertBefore(RawKdbx.KDF_PARAMETERS, noUuid)))
        val shortUuid = RawField(RawKdbx.KDF_PARAMETERS, weak.kdf().with("\$UUID", RawDictionary.BYTES, ByteArray(15)).toBytes())
        assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), invalid(weak.insertBefore(RawKdbx.KDF_PARAMETERS, shortUuid)))
    }

    @Test
    fun `the KDF dictionary is kept in the order its names first appear, after the fold`() {
        val names = { raw: RawKdbx -> valid(raw).kdfEntries!!.all().map { it.first.decodeToString() } }
        assertEquals(listOf("\$UUID", "R", "S"), names(weak))
        assertEquals(listOf("S", "R", "\$UUID"), names(weak.withKdf { it.copy(entries = it.entries.reversed()) }))
        // A repeated name keeps its first position and takes its last value; an empty name is
        // dropped.
        val repeated = valid(weak.withKdf { it.plus(RawEntry(RawDictionary.UINT32, "", le32(1))).plus(RawEntry(RawDictionary.UINT64, "R", le64(7000))) })
        assertEquals(listOf("\$UUID", "R", "S"), repeated.kdfEntries!!.all().map { it.first.decodeToString() })
        assertContentEquals(le64(7000), repeated.kdfEntries!!["R"]!!.value)
        assertEquals(7000UL, assertIs<KdfParameters.Aes>(repeated.kdf).rounds)
        // Field 5 without field 11 starts from AES-KDF's defaults: the rounds, then the seed.
        val seed = ByteArray(32) { 4 }
        val folded = weak.withoutField(RawKdbx.KDF_PARAMETERS).insertBefore(RawKdbx.END_OF_HEADER, RawField(RawKdbx.TRANSFORM_SEED, seed))
        assertEquals(listOf("R", "S"), names(folded))
        val aes = assertIs<KdfParameters.Aes>(valid(folded).kdf)
        assertContentEquals(seed, valid(folded).kdfEntries!!.bytes("S"))
        assertEquals(600_000UL, aes.rounds)
    }

    @Test
    fun `missing cipher and compression fields take KeePass 2's defaults`() {
        val header = valid(weak.withoutField(RawKdbx.CIPHER_ID).withoutField(RawKdbx.COMPRESSION))
        assertEquals(OuterCipher.AES_256, header.cipher)
        assertEquals(Compression.GZIP, header.compression)
    }

    @Test
    fun `fields 11 and 12 share one budget, a sixteenth of the heap, charged with each field's copy`() {
        val custom = RawDictionary(0x0100, listOf(RawEntry(RawDictionary.STRING, "KashPass_Plugin", "x".repeat(100).toByteArray())))
        val raw = weak.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, custom.toBytes()))
        val header = valid(raw)
        val kdfCost = raw.field(RawKdbx.KDF_PARAMETERS).size + header.kdfEntries!!.heapBytes
        val customCost = raw.field(RawKdbx.PUBLIC_CUSTOM_DATA).size + header.publicCustomData!!.heapBytes
        val needed = (kdfCost + customCost) * KdbxHeaderReader.DICTIONARY_HEAP_DIVISOR
        assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(raw.toBytes(), needed))
        val short = assertIs<KdbxHeaderReader.Read.Invalid>(KdbxHeaderReader.read(raw.toBytes(), needed - KdbxHeaderReader.DICTIONARY_HEAP_DIVISOR))
        assertEquals(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT), short.result)
        // Either field alone fits that budget.
        assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(weak.toBytes(), needed - KdbxHeaderReader.DICTIONARY_HEAP_DIVISOR))
    }

    @Test
    fun `a dictionary field longer than the budget is NotEnoughMemory before it is copied`() {
        val big = RawDictionary(0x0100, listOf(RawEntry(RawDictionary.BYTES, "KashPass_Blob", ByteArray(1 shl 20))))
        val raw = weak.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, big.toBytes()))
        val r = assertIs<KdbxHeaderReader.Read.Invalid>(KdbxHeaderReader.read(raw.toBytes(), 1L shl 20))
        assertEquals(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT), r.result)
    }

    @Test
    fun `every fixture and corpus case but the many-entry one reads the same within the budget of a 16 MiB heap`() {
        val heap = 16L * 1024 * 1024
        val files = Fixtures.kdbx4.map { it.name to Fixtures.bytes(it.name) } + Corpus.all.map { it.name to it.bytes }
        val differ = files.mapNotNull { (name, bytes) ->
            val bounded = KdbxHeaderReader.read(bytes, heap)
            val unbounded = KdbxHeaderReader.read(bytes)
            val same = when (unbounded) {
                is KdbxHeaderReader.Read.Valid -> bounded is KdbxHeaderReader.Read.Valid
                is KdbxHeaderReader.Read.Invalid -> bounded is KdbxHeaderReader.Read.Invalid && bounded.result == unbounded.result
            }
            name.takeUnless { same }
        }
        assertEquals(listOf("spec-public-custom-data-many-entries"), differ)
    }

    @Test
    fun `every header refusal of a corpus case matches the case's spec`() {
        val wrong = Corpus.all.mapNotNull { c ->
            when (val r = KdbxHeaderReader.read(c.bytes)) {
                is KdbxHeaderReader.Read.Valid -> null
                is KdbxHeaderReader.Read.Invalid -> when {
                    r.result is KdbxResult.Damaged && c.spec == Spec.DAMAGED -> null
                    r.result is KdbxResult.Unsupported && c.spec == Spec.UNSUPPORTED -> null
                    else -> "${c.name}: header ${r.result}, spec ${c.spec}"
                }
            }
        }
        assertTrue(wrong.isEmpty(), wrong.joinToString("\n"))
    }

    @Test
    fun `the header reader refuses every corpus case whose outcome the header sets`() {
        val headerLength = RawKdbx.parse(Corpus.all.single { it.name == "block-baseline-aes" }.bytes).headerBytes().size
        val decided = Corpus.all.filter { c -> headerDecided(c, headerLength) }
        assertTrue(decided.size > 200, "only ${decided.size} header cases")
        val passed = decided.filter { KdbxHeaderReader.read(it.bytes) is KdbxHeaderReader.Read.Valid }.map { it.name }
        assertEquals(emptyList(), passed)
    }

    @Test
    fun `every fold ordering in the corpus gives the KDF KeePass 2 builds`() {
        val cases = Corpus.all.filter { it.name.startsWith("kdbx3-") || Regex("""^kdf-.*-then-""").containsMatchIn(it.name) }
        assertTrue(cases.size >= 15, "${cases.size} fold cases")
        for (c in cases) {
            val effective = KdbxToolkit.effective(RawKdbx.parse(c.bytes))
            when (val r = KdbxHeaderReader.read(c.bytes)) {
                is KdbxHeaderReader.Read.Valid -> assertSameKdf(effective.kdf, r.header.kdf, c.name)
                is KdbxHeaderReader.Read.Invalid -> {
                    assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), r.result, c.name)
                    assertTrue(effective.kdf.let { it is KdbxToolkit.Kdf.Aes && it.seed == null }, c.name)
                }
            }
        }
    }

    private fun headerDecided(c: CorpusCase, headerLength: Int): Boolean {
        if (c.spec != Spec.DAMAGED && c.spec != Spec.UNSUPPORTED) return false
        val cut = Regex("""^truncated-at-(\d+)$""").find(c.name)?.groupValues?.get(1)?.toInt()
        if (cut != null) return cut < headerLength
        return c.name.startsWith("header-version") || c.name.startsWith("spec-signature") || c.name.startsWith("dict-") ||
            c.name.startsWith("spec-dict-") || c.name.startsWith("spec-public-custom-data") || c.name.startsWith("spec-compression") ||
            c.name in HEADER_DECIDED || Regex("""^header-field-\d+-id-\d+-length-(huge|negative)$""").matches(c.name)
    }

    private fun assertSameKdf(expected: KdbxToolkit.Kdf, actual: KdfParameters, name: String) {
        when (expected) {
            is KdbxToolkit.Kdf.Aes -> {
                val aes = assertIs<KdfParameters.Aes>(actual, name)
                assertEquals(expected.rounds, aes.rounds, name)
                assertContentEquals(expected.seed, aes.seed, name)
            }
            is KdbxToolkit.Kdf.Argon2 -> {
                val a = assertIs<KdfParameters.Argon2>(actual, name)
                assertEquals(if (expected.id) Argon2Type.ARGON2ID else Argon2Type.ARGON2D, a.type, name)
                assertContentEquals(expected.salt, a.salt, name)
                assertEquals(expected.parallelism, a.parallelism, name)
                assertEquals(expected.memory, a.memoryBytes, name)
                assertEquals(expected.iterations, a.iterations, name)
                assertEquals(expected.version, a.version, name)
                assertContentEquals(expected.secret, a.secretKey, name)
                assertContentEquals(expected.associated, a.associatedData, name)
            }
            KdbxToolkit.Kdf.Unreadable -> fail("$name: the toolkit reads no KDF")
        }
    }

    companion object {
        @JvmStatic
        fun fixtures(): List<String> = Fixtures.kdbx4.map { it.name }

        // Named corpus cases KeePass 2 refuses while reading the outer header.
        private val HEADER_DECIDED = setOf(
            "header-cipher-id-15-bytes", "header-cipher-id-17-bytes", "header-cipher-twofish", "header-stream-id-10-is-4",
            "kdbx3-no-kdf-at-all", "kdbx3-rounds-after-argon2", "kdf-argon2-salt-7-bytes", "spec-header-end-missing",
            "header-compression-3-bytes",
        )
    }
}
