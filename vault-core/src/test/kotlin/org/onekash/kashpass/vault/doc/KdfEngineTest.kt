package org.onekash.kashpass.vault.doc

import java.security.Security
import java.util.Collections
import java.util.HexFormat
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.kdbx.Argon2Type
import org.onekash.kashpass.vault.kdbx.KdbxException
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.OuterHeader
import org.onekash.kashpass.vault.kdbx.SaveSettings
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.policy.KdfSetting
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.u64
import org.onekash.kashpass.vault.kdbx.KdfParameters as KdbxKdfParameters

class KdfEngineTest {

    private val credentials = VaultKey.password(TestVaults.PASSWORD.toCharArray())

    private fun bytes(hex: String) = HexFormat.of().parseHex(hex.replace(" ", ""))

    private fun argon2(
        variant: Argon2Type = Argon2Type.ARGON2D,
        version: UInt = 0x13U,
        lanes: UInt = 4U,
        memory: ULong = 1024UL * 1024UL,
        iterations: ULong = 2UL,
        salt: ByteArray = ByteArray(32) { it.toByte() },
        secret: ByteArray? = null,
        associated: ByteArray? = null,
    ) = KdbxKdfParameters.Argon2(variant, salt, lanes, memory, iterations, version, secret, associated)

    private fun aes(rounds: ULong, seed: ByteArray = ByteArray(32) { (it * 7).toByte() }) = KdbxKdfParameters.Aes(rounds, seed)

    private val key = ByteArray(32) { (it + 1).toByte() }

    private fun kdfThreads() = Thread.getAllStackTraces().keys.filter { it.name.startsWith(KdfEngine.THREAD_NAME) }

    // RFC 9106 section 5 inputs; the phc-winner-argon2 KAT files use the same ones.
    private fun rfcVector(variant: Argon2Type, version: UInt) = argon2(
        variant = variant,
        version = version,
        lanes = 4U,
        memory = 32UL * 1024UL,
        iterations = 3UL,
        salt = ByteArray(16) { 2 },
        secret = ByteArray(8) { 3 },
        associated = ByteArray(12) { 4 },
    )

    private val rfcPassword = ByteArray(32) { 1 }

    // Version 0x13 tags are RFC 9106 sections 5.1 and 5.3. Version 0x10 tags are the "Tag:"
    // lines of kats/argon2d_v16 and kats/argon2id_v16 in the phc-winner-argon2 repository.
    @ParameterizedTest(name = "{0} version {1}")
    @CsvSource(
        "Argon2d, 19, 512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
        "Argon2id, 19, 0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        "Argon2d, 16, 96 a9 d4 e5 a1 73 40 92 c8 5e 29 f4 10 a4 59 14 a5 dd 1f 5c bf 08 b2 67 0d a6 8a 02 85 ab f3 2b",
        "Argon2id, 16, b6 46 15 f0 77 89 b6 6b 64 5b 67 ee 9e d3 b3 77 ae 35 0b 6b fc bb 0f c9 51 41 ea 8f 32 26 13 c0",
    )
    fun `Argon2 matches the published test vectors on one thread and on four`(variant: String, version: Int, tag: String) {
        val params = rfcVector(Argon2Type.valueOf(variant.uppercase()), version.toUInt())
        for (processors in listOf(1, 4)) {
            assertContentEquals(bytes(tag), KdfEngine(processors = { processors }).derive(params, rfcPassword), "$processors processors")
        }
    }

    /**
     * `vectors/argon2-phc-grid.tsv` holds tags from the phc-winner-argon2 reference library
     * (libargon2 release 20171227, `argon2_ctx`, which takes the secret key and associated data;
     * memory in KiB is the stated bytes / 1024): 580 cases of random passwords, salts of 8 to 33
     * bytes and optional secret key and associated data over 1 to 8 lanes, and a grid of both
     * variants and versions, 1, 2, 3, 4 and 8 lanes, 1 to 3 passes and memory at the 8 KiB per
     * lane minimum, at the minimum plus 3 KiB and 100 bytes, 1025 KiB and 3 MiB plus 512 bytes.
     */
    @Test
    fun `Argon2 matches the phc-winner-argon2 reference over 820 cases`() {
        val rows = javaClass.getResourceAsStream("/vectors/argon2-phc-grid.tsv")!!.bufferedReader().readLines().filterNot { it.startsWith("#") }
        assertEquals(820, rows.size)
        val engine = KdfEngine()
        val mismatches = rows.filter { row ->
            val c = row.split('\t')
            val parameters = KdbxKdfParameters.Argon2(
                type = if (c[0] == "d") Argon2Type.ARGON2D else Argon2Type.ARGON2ID,
                salt = bytes(c[6]), parallelism = c[3].toUInt(), memoryBytes = c[4].toULong(), iterations = c[2].toULong(), version = c[1].toUInt(),
                secretKey = c[7].takeIf { it != "-" }?.let { bytes(it) }, associatedData = c[8].takeIf { it != "-" }?.let { bytes(it) },
            )
            !engine.derive(parameters, bytes(c[5])).contentEquals(bytes(c[9]))
        }
        assertEquals(emptyList(), mismatches)
    }


    // Memory below 8 KiB per lane, which the reference library refuses: the derivation uses at
    // least 8 KiB per lane, rounded down to a multiple of 4 KiB per lane, while H0 keeps the
    // stated memory. The keys are KdfEngine's output where a second,
    // independent Argon2 implementation gave the same key; KeePass2LowMemoryArgon2Test has
    // KeePass 2 open a vault saved with each setting.
    @ParameterizedTest(name = "{0} lanes, {1} bytes")
    @CsvSource(
        "2, 8192, f53e31c7e35970accfe62f9202a7e48ec4d54fe46a34da12c3b4d290897fd8a0",
        "4, 8192, 57368d1bf881b3a820e6535aeaad823f889a69dd08b106f4ae179df1d9f0be7c",
        "8, 8192, 4e1b07dc29324cc61c0cd5c82d8f9cd83d7737d3a0fcd05fdb2947079dd52e30",
        "4, 20480, d443a14b47c9cbf893659df31dfb428602a85feb373a11fcb6b9ef0637a784ed",
        "3, 9216, e3257afd2ef7474f7616e15cff2649f1434ee809931696a98f283c3f0cda1394",
        "8, 65535, 2dc7e4b6aa147740f72763ac79b07d7276214e640ed80a86da30df8538e37323",
    )
    fun `Argon2 memory below 8 KiB per lane derives the recorded key`(lanes: Int, memory: Long, tag: String) {
        val parameters = KdbxKdfParameters.Argon2(Argon2Type.ARGON2ID, ByteArray(32) { (it * 5 + 3).toByte() }, lanes.toUInt(), memory.toULong(), 3UL, 0x13U, null, null)
        assertContentEquals(bytes(tag), KdfEngine().derive(parameters, ByteArray(32) { (it * 7 + 1).toByte() }))
    }

    @Test
    fun `twenty derivations of a four-lane setting give one key, equal to the single-thread key`() {
        val params = argon2(lanes = 4U, memory = 2UL * 1024UL * 1024UL, iterations = 2UL)
        val reference = KdfEngine(processors = { 1 }).derive(params, key)
        val engine = KdfEngine(processors = { 4 })
        repeat(20) { assertContentEquals(reference, engine.derive(params, key), "derivation $it") }
    }

    @Test
    fun `the lanes of a slice run at the same time`() {
        // A barrier for all four lanes before every segment times out unless all four run at once.
        val barrier = CyclicBarrier(4)
        val engine = KdfEngine(processors = { 4 }, beforeWork = { barrier.await(10, TimeUnit.SECONDS) })
        val params = argon2(lanes = 4U, memory = 256UL * 1024UL, iterations = 2UL)
        assertContentEquals(KdfEngine(processors = { 1 }).derive(params, key), engine.derive(params, key))
    }

    @Test
    fun `AES-KDF transforms the two halves at the same time`() {
        val barrier = CyclicBarrier(2)
        val engine = KdfEngine(processors = { 2 }, beforeWork = { barrier.await(10, TimeUnit.SECONDS) })
        assertContentEquals(KdfEngine(processors = { 1 }).derive(aes(5000UL), key), engine.derive(aes(5000UL), key))
    }

    @Test
    fun `at most min(parallelism, processors) threads run the lanes, the calling thread among them`() {
        val threads = Collections.synchronizedSet(HashSet<Thread>())
        val engine = KdfEngine(processors = { 3 }, beforeWork = { threads += Thread.currentThread() })
        engine.derive(argon2(lanes = 8U, memory = 512UL * 1024UL, iterations = 1UL), key)
        assertEquals(3, threads.size, threads.toString())
        assertTrue(Thread.currentThread() in threads)
        threads.clear()
        engine.derive(argon2(lanes = 1U, memory = 64UL * 1024UL, iterations = 1UL), key)
        assertEquals(setOf(Thread.currentThread()), threads.toSet())
        assertEquals(emptyList(), kdfThreads())
    }

    @Test
    fun `Argon2 memory is allocated once, as m' blocks shared by every lane`() {
        val sizes = Collections.synchronizedList(ArrayList<Int>())
        val engine = KdfEngine(processors = { 3 }, allocate = { n -> sizes += n; LongArray(n) })
        // 29 KiB over 3 lanes: m' is 24 blocks of 128 words.
        engine.derive(argon2(lanes = 3U, memory = 29UL * 1024UL + 1000UL, iterations = 2UL), key)
        assertEquals(listOf(24 * 128), sizes)
    }

    @Test
    fun `a failed memory allocation reaches the caller as the same OutOfMemoryError`() {
        val error = OutOfMemoryError("test")
        val thrown = assertThrows<OutOfMemoryError> { KdfEngine(allocate = { throw error }).derive(argon2(), key) }
        assertSame(error, thrown)
        assertEquals(emptyList(), kdfThreads())
    }

    @ParameterizedTest(name = "lane {0}")
    @CsvSource("0", "3")
    fun `a failure on one lane fails the derivation unwrapped and leaves no worker running`(lane: Int) {
        val oom = OutOfMemoryError("test")
        val calls = AtomicInteger()
        val failing = KdfEngine(processors = { 4 }, beforeWork = { if (it == lane && calls.incrementAndGet() == 3) throw oom })
        assertSame(oom, assertThrows<OutOfMemoryError> { failing.derive(argon2(lanes = 4U), key) })
        assertEquals(emptyList(), kdfThreads())

        val invalid = IllegalStateException("test")
        val rejecting = KdfEngine(processors = { 4 }, beforeWork = { if (it == lane) throw invalid })
        assertSame(invalid, assertThrows<IllegalStateException> { rejecting.derive(argon2(lanes = 4U), key) })
        assertEquals(emptyList(), kdfThreads())
    }

    @ParameterizedTest(name = "{0} workers")
    @CsvSource("1", "4")
    fun `cancelling Argon2 stops it before the next slice, zero-fills its memory and throws CancellationException`(processors: Int) {
        val memory = Collections.synchronizedList(ArrayList<LongArray>())
        val segments = AtomicInteger()
        val checks = AtomicInteger()
        val engine = KdfEngine(processors = { processors }, allocate = { n -> LongArray(n).also { memory += it } }, beforeWork = { segments.incrementAndGet() })
        // A million passes over 1 MiB would run for hours; the check cancels after 10 slices.
        val parameters = argon2(lanes = 4U, iterations = 1_000_000UL)
        assertThrows<java.util.concurrent.CancellationException> { engine.derive(parameters, key) { checks.incrementAndGet() > 10 } }
        assertEquals(10 * 4, segments.get(), "four lanes per slice, none after the cancel")
        assertTrue(memory.single().all { it == 0L })
        assertEquals(emptyList(), kdfThreads())
    }

    @Test
    fun `a cancelled AES-KDF derivation stops within a few thousand rounds and throws CancellationException`() {
        val checks = AtomicInteger()
        val started = System.nanoTime()
        // 2^31 - 1 rounds take minutes; each half checks every few thousand rounds.
        assertThrows<java.util.concurrent.CancellationException> {
            KdfEngine(processors = { 2 }).derive(aes((1UL shl 31) - 1UL), key) { checks.incrementAndGet() > 2 }
        }
        assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(5))
        assertTrue(checks.get() <= 4, "${checks.get()} checks")
        assertEquals(emptyList(), kdfThreads())
    }

    @Test
    fun `a derivation that is never cancelled gives the key it gives without a check`() {
        val engine = KdfEngine()
        for (parameters in listOf(rfcVector(Argon2Type.ARGON2ID, 0x13U), aes(6_000UL))) {
            val checks = AtomicInteger()
            val checked = engine.derive(parameters, key) { checks.incrementAndGet() < 0 }
            assertContentEquals(engine.derive(parameters, key), checked)
            assertTrue(checks.get() > 0)
        }
    }

    // Cipher falls back to the next provider when one refuses init, so the test removes every
    // provider of AES instead; the test JVM runs one test at a time, and a finally block puts each
    // provider back at its position.
    @Test
    fun `a platform without AES-KDF's cipher reports an unavailable algorithm and leaves no worker`() {
        val providers = Security.getProviders("Cipher.AES").orEmpty().toList()
        assertTrue(providers.isNotEmpty(), "no AES provider to remove")
        val positions = providers.associateWith { p -> Security.getProviders().indexOf(p) + 1 }
        try {
            providers.forEach { Security.removeProvider(it.name) }
            assertThrows<KdbxException.AlgorithmUnavailable> { KdfEngine().derive(aes(1_000UL), key.copyOf()) }
            assertEquals(KdfFailure.Unavailable, KdfFailure.of(KdbxException.AlgorithmUnavailable()))
        } finally {
            positions.entries.sortedBy { it.value }.forEach { (p, at) -> Security.insertProviderAt(p, at) }
        }
        assertTrue(Security.getProviders("Cipher.AES").orEmpty().isNotEmpty(), "providers restored")
        assertEquals(emptyList(), kdfThreads())
    }

    @Test
    fun `an AES-KDF seed that is not 32 bytes is hashed first, as KeePass 2 does`() {
        for (size in listOf(0, 5, 16, 33)) {
            val seed = ByteArray(size) { (it + 3).toByte() }
            val hashed = java.security.MessageDigest.getInstance("SHA-256").digest(seed)
            for (processors in listOf(1, 2)) {
                val engine = KdfEngine(processors = { processors })
                assertContentEquals(engine.derive(aes(10UL, seed = hashed), key.copyOf()), engine.derive(aes(10UL, seed = seed), key.copyOf()), "seed of $size bytes")
            }
        }
        assertEquals(emptyList(), kdfThreads())
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource("kdf-aes-seed-16-bytes", "kdf-aes-seed-empty")
    fun `the corpus vaults with a short AES-KDF seed derive KeePass 2's key and open through the codec`(name: String) {
        val case = Corpus.all.single { it.name == name }
        val file = case.file()
        val effective = KdbxToolkit.effective(RawKdbx.parse(case.bytes))
        val keepass2 = KdbxToolkit.derive(effective.kdf, KdbxToolkit.Key(TestFiles.password(file.mode)))
        val composite = KdbxToolkit.Key(TestFiles.password(file.mode)).composite()
        assertContentEquals(keepass2, KdfEngine().derive((KdbxHeaderReader.read(case.bytes) as KdbxHeaderReader.Read.Valid).header.kdf, composite))
        VaultXmlCodec.open(case.bytes, TestFiles.credentials(file), VaultXmlCodec.Limits.forHeap(512L * 1024 * 1024))
    }

    @Test
    fun `an Argon2 salt under 8 bytes is refused before any allocation`() {
        var touched = false
        val engine = KdfEngine(allocate = { touched = true; LongArray(it) }, beforeWork = { touched = true })
        assertThrows<KdfSaltException> { engine.derive(argon2(salt = ByteArray(7)), key) }
        assertTrue(!touched)
        engine.derive(argon2(salt = ByteArray(8), memory = 64UL * 1024UL), key)
    }

    @Test
    fun `Argon2 memory past one array is refused before any allocation`() {
        var touched = false
        val engine = KdfEngine(allocate = { touched = true; LongArray(it) }, beforeWork = { touched = true })
        assertThrows<KdfTooLargeException> { engine.derive(argon2(lanes = 0xFF_FFFFU, memory = 8192UL), key) }
        assertThrows<KdfTooLargeException> { engine.derive(argon2(lanes = 2_097_152U, memory = 8192UL), key) }
        assertTrue(!touched)
    }

    @ParameterizedTest(name = "{0} = {1}")
    @CsvSource(
        "ARGON2_ITERATIONS, 0", "ARGON2_ITERATIONS, 2147483648", "ARGON2_PARALLELISM, 0", "ARGON2_PARALLELISM, 16777216",
        "ARGON2_PARALLELISM, 2147483648",
        "ARGON2_MEMORY, 8191", "ARGON2_MEMORY, 0", "ARGON2_MEMORY, 2147483648", "ARGON2_VERSION, 17", "ARGON2_VERSION, 20",
        "AES_ROUNDS, 0", "AES_ROUNDS, 2147483648",
    )
    fun `settings outside the bounds are refused before any allocation or derivation`(setting: KdfSetting, value: Long) {
        val v = value.toULong()
        val kdf = when (setting) {
            KdfSetting.ARGON2_ITERATIONS -> argon2(iterations = v)
            KdfSetting.ARGON2_PARALLELISM -> argon2(lanes = v.toUInt())
            KdfSetting.ARGON2_MEMORY -> argon2(lanes = 2U, memory = v)
            KdfSetting.ARGON2_VERSION -> argon2(version = v.toUInt())
            else -> aes(v)
        }
        var touched = false
        val engine = KdfEngine(allocate = { touched = true; LongArray(it) }, beforeWork = { touched = true })
        val refused = assertThrows<KdfOutOfBoundsException> { engine.derive(kdf, key) }
        assertEquals(KdfRejection.OutOfBounds(setting, v), refused.rejection)
        assertTrue(!touched)
    }

    @Test
    fun `the codec refuses zero Argon2 iterations, which derive a password-independent key, before deriving`() {
        // Written at 1 iteration and keyed by that header; the stored header says 0.
        val written = KdbxToolkit.newVault(
            TestVaults.keePassXml().toByteArray(Charsets.UTF_8), emptyList(), KdbxToolkit.Key(TestVaults.PASSWORD),
            KdbxToolkit.Kdf.Argon2(true, ByteArray(32), 2U, 64UL * 1024UL, 1UL, 0x13U, null, null),
        )
        val layers = KdbxToolkit.open(written, KdbxToolkit.Key(TestVaults.PASSWORD)).layers
        val zero = layers.header.withKdf { it.with("I", RawDictionary.UINT64, u64(0UL)) }
        val bytes = KdbxToolkit.build(layers.copy(header = zero, kdfHeader = layers.header))
        val refused = assertIs<Decoded.Refused>(VaultXmlCodec.decode(bytes, credentials, VaultXmlCodec.Limits(open = 1 shl 20, save = 1L shl 20)))
        assertEquals(KdfSetting.ARGON2_ITERATIONS, (refused.rejection as KdfRejection.OutOfBounds).setting)
    }

    @Test
    fun `the codec checks the written settings before deriving, so an out-of-bounds setting in memory is refused`() {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL)
        val read = VaultXmlCodec.open(bytes, credentials, VaultXmlCodec.Limits(open = 1 shl 20, save = 1L shl 20))
        val h = (KdbxHeaderReader.read(bytes) as KdbxHeaderReader.Read.Valid).header
        val zeroRounds = OuterHeader(
            h.signature, h.majorVersion, h.minorVersion, h.cipher, h.compression, h.masterSeed, h.iv, aes(0UL),
            h.publicCustomData, null, null, h.length,
        )
        val document = VaultDocument(read.xml, SaveSettings.from(zeroRounds), read.attachments, read.credentials, read.protectedValues, read.xmlBytes, read.saveability)
        var derived = false
        val refused = assertIs<Encoded.Refused>(VaultXmlCodec.encode(document, derive = { p, k -> derived = true; KdfEngine().derive(p, k) }))
        assertEquals(KdfSetting.AES_ROUNDS, (refused.rejection as KdfRejection.OutOfBounds).setting)
        assertTrue(!derived)
    }

    private class Recording : KeyDerivation {
        val derived = mutableListOf<ByteArray>()
        override fun derive(parameters: KdbxKdfParameters, compositeKey: ByteArray) =
            KdfEngine().derive(parameters, compositeKey).also { derived += it }
    }

    @Test
    fun `the save cache derives once for equal settings and key and hands out fresh copies`() {
        val recording = Recording()
        val cache = SaveKeyCache(recording)
        val kdf = aes(1_000UL)
        val first = cache.derive(kdf, key.copyOf())
        val expected = first.copyOf()
        // Equal parameters in new objects, as the read-back's header parse builds them.
        val hit = cache.derive(KdbxKdfParameters.Aes(kdf.rounds, kdf.seed.copyOf()), key.copyOf())
        assertEquals(1, recording.derived.size)
        assertContentEquals(expected, hit)
        first.fill(0)
        hit.fill(0)
        val again = cache.derive(kdf, key.copyOf())
        assertEquals(1, recording.derived.size)
        assertContentEquals(expected, again, "a caller zero-filling its array leaves the kept key intact")
        val arrays = listOf(first, hit, again, recording.derived.single())
        for ((i, a) in arrays.withIndex()) for (b in arrays.drop(i + 1)) assertTrue(a !== b, "every call gets its own array")
    }

    @Test
    fun `the save cache keeps its own copy of the composite key`() {
        val recording = Recording()
        val cache = SaveKeyCache(recording)
        val composite = key.copyOf()
        cache.derive(aes(1_000UL), composite)
        composite.fill(0)
        cache.derive(aes(1_000UL), key.copyOf())
        assertEquals(1, recording.derived.size)
        cache.derive(aes(1_000UL), ByteArray(32))
        assertEquals(2, recording.derived.size, "a zero-filled key is a different key")
    }

    @Test
    fun `the save cache derives again for another salt, seed, setting or composite key`() {
        val recording = Recording()
        val cache = SaveKeyCache(recording)
        val base = argon2(memory = 64UL * 1024UL)
        val first = cache.derive(base, key.copyOf())
        val others = listOf(
            argon2(memory = 64UL * 1024UL, salt = ByteArray(32) { 1 }),
            argon2(memory = 64UL * 1024UL, iterations = 3UL),
            argon2(memory = 64UL * 1024UL, secret = ByteArray(8)),
            argon2(memory = 64UL * 1024UL, associated = ByteArray(8)),
            argon2(memory = 64UL * 1024UL, variant = Argon2Type.ARGON2ID),
        )
        for (other in others) {
            assertTrue(!first.contentEquals(cache.derive(other, key.copyOf())), other.toString())
        }
        val otherKey = key.copyOf().also { it[31] = (it[31] + 1).toByte() }
        assertTrue(!first.contentEquals(cache.derive(base, otherKey)))
        assertEquals(others.size + 2, recording.derived.size)
        assertContentEquals(first, cache.derive(base, key.copyOf()), "the first derivation stays kept")
        assertEquals(others.size + 2, recording.derived.size)
        val aesCache = SaveKeyCache(recording)
        aesCache.derive(aes(1_000UL), key.copyOf())
        aesCache.derive(aes(1_000UL, seed = ByteArray(32) { 3 }), key.copyOf())
        assertEquals(others.size + 4, recording.derived.size)
    }

    @Test
    fun `the save cache compares the whole composite key by content`() {
        // Counts derivations without deriving, so keys of any length reach the comparison.
        val derived = mutableListOf<ByteArray>()
        val cache = SaveKeyCache(object : KeyDerivation {
            override fun derive(parameters: KdbxKdfParameters, compositeKey: ByteArray) = ByteArray(32) { derived.size.toByte() }.also { derived += it }
        })
        cache.derive(aes(1_000UL), key.copyOf())
        cache.derive(aes(1_000UL), key.copyOf())
        assertEquals(1, derived.size, "an equal key in another array hits the cache")
        val differing = listOf(0, 15, 31).map { i -> key.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() } } +
            listOf(key.copyOf(31), key.copyOf(33))
        for ((n, other) in differing.withIndex()) {
            cache.derive(aes(1_000UL), other)
            assertEquals(n + 2, derived.size, "key $n derives")
        }
        cache.derive(aes(1_000UL), key.copyOf())
        assertEquals(differing.size + 1, derived.size, "the first key stays kept")
    }

    @Test
    fun `closing the save cache zero-fills the kept key and every later call derives`() {
        val recording = Recording()
        val cache = SaveKeyCache(recording)
        val handed = cache.derive(aes(1_000UL), key.copyOf())
        val kept = recording.derived.single()
        assertContentEquals(kept, handed)
        cache.close()
        assertContentEquals(ByteArray(32), kept)
        assertTrue(handed.any { it != 0.toByte() }, "the caller's copy is the caller's to clear")
        cache.derive(aes(1_000UL), key.copyOf())
        cache.derive(aes(1_000UL), key.copyOf())
        assertEquals(3, recording.derived.size)
    }

    @Test
    fun `a refused setting reaches the caller and nothing is kept`() {
        val recording = Recording()
        val cache = SaveKeyCache(recording)
        assertThrows<KdfOutOfBoundsException> { cache.derive(aes(0UL), key.copyOf()) }
        cache.derive(aes(1_000UL), key.copyOf())
        cache.derive(aes(1_000UL), key.copyOf())
        assertEquals(1, recording.derived.size)
    }
}
