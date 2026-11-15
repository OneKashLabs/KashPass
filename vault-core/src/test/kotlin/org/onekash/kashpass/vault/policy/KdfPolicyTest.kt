package org.onekash.kashpass.vault.policy

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.header.Argon2Variant
import org.onekash.kashpass.vault.header.HeaderResult
import org.onekash.kashpass.vault.header.KdbxHeaderParser
import org.onekash.kashpass.vault.header.KdbxHeaderParserTest
import org.onekash.kashpass.vault.header.KdfSettings
import kotlin.test.assertIs

class KdfPolicyTest {

    private val MIB = 1_048_576UL

    @ParameterizedTest(name = "{0}")
    @MethodSource("outOfBounds")
    fun `settings outside the accepted bounds are rejected with the setting named`(
        case: String,
        kdf: KdfSettings,
        expected: KdfRejection.OutOfBounds,
    ) {
        assertEquals(expected, KdfPolicy.checkBounds(kdf), case)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("inBounds")
    fun `settings at the edges of the bounds are accepted`(case: String, kdf: KdfSettings) {
        assertNull(KdfPolicy.checkBounds(kdf), case)
    }

    @Test
    fun `work is measured in units of KeePass 2's default settings for both KDF types`() {
        assertEquals(1.0, KdfPolicy.workUnits(KdfSettings.AesKdf(600_000UL)), 1e-9)
        assertEquals(1.0, KdfPolicy.workUnits(argon(iterations = 2UL, memory = 64UL * MIB)), 1e-9)
        assertEquals(10.0, KdfPolicy.workUnits(KdfSettings.AesKdf(6_000_000UL)), 1e-9)
    }

    @Test
    fun `a jump of more than 10x warns once the new work is at least 10 units`() {
        val base = KdfSettings.AesKdf(600_000UL)
        assertNull(KdfPolicy.slowness(base, KdfSettings.AesKdf(6_000_000UL)), "10x exactly")
        val slow = KdfPolicy.slowness(base, KdfSettings.AesKdf(6_000_001UL))
        assertEquals(KdfSettings.AesKdf(6_000_001UL), slow?.kdf)
        assertEquals(10, slow?.factor)
        assertEquals(100, KdfPolicy.slowness(base, KdfSettings.AesKdf(60_000_000UL))?.factor)
    }

    @Test
    fun `moving a weak vault up to KeePass 2's defaults never warns`() {
        assertNull(KdfPolicy.slowness(KdfSettings.AesKdf(6_000UL), KdfSettings.AesKdf(600_000UL)))
        assertNull(KdfPolicy.slowness(KdfSettings.AesKdf(6_000UL), KdfSettings.AesKdf(5_999_999UL)), "below the 10-unit floor")
    }

    @Test
    fun `a switch between AES-KDF and Argon2 compares on the same scale`() {
        assertNull(KdfPolicy.slowness(KdfSettings.AesKdf(600_000UL), argon(iterations = 2UL, memory = 64UL * MIB)))
        assertEquals(20, KdfPolicy.slowness(KdfSettings.AesKdf(600_000UL), argon(iterations = 40UL, memory = 64UL * MIB))?.factor)
    }

    @Test
    fun `work that runs in parallel counts once per lane the phone can run at once`() {
        val fourLanes = KdfSettings.Argon2(Argon2Variant.ARGON2D, 60UL, 64UL * MIB, 4U, 0x13U) // 30 units
        // Plus a few hundredths of a unit for handing 60 passes of slices to other threads.
        assertEquals(7.5, KdfPolicy.parallelUnits(fourLanes, cores = 8), 0.05)
        assertEquals(15.0, KdfPolicy.parallelUnits(fourLanes, cores = 2), 0.05)
        assertEquals(30.0, KdfPolicy.parallelUnits(fourLanes, cores = 1), 1e-9)
        // AES-KDF transforms its two halves on two threads.
        assertEquals(5.0, KdfPolicy.parallelUnits(KdfSettings.AesKdf(6_000_000UL), cores = 8), 1e-9)
    }

    @Test
    fun `with no baseline only work above 125 parallel units warns, about 1000 iterations of 64 MiB on four lanes`() {
        val sixtyPasses = KdfSettings.Argon2(Argon2Variant.ARGON2D, 60UL, 64UL * MIB, 4U, 0x13U)
        assertNull(KdfPolicy.slowness(null, sixtyPasses, cores = 8), "a few seconds on a phone")
        assertNull(KdfPolicy.slowness(null, KdfSettings.Argon2(Argon2Variant.ARGON2D, 990UL, 64UL * MIB, 4U, 0x13U), cores = 8))
        val slow = KdfPolicy.slowness(null, KdfSettings.Argon2(Argon2Variant.ARGON2D, 1002UL, 64UL * MIB, 4U, 0x13U), cores = 8)
        assertNull(slow?.factor)
        assertEquals(501, slow?.units)
        // One lane can't run in parallel, so a quarter of the iterations reaches the same time.
        assertNotNull(KdfPolicy.slowness(null, KdfSettings.Argon2(Argon2Variant.ARGON2D, 252UL, 64UL * MIB, 1U, 0x13U), cores = 8))
        assertNull(KdfPolicy.slowness(null, KdfSettings.AesKdf(150_000_000UL), cores = 8), "125 parallel units of AES-KDF")
        assertNotNull(KdfPolicy.slowness(null, KdfSettings.AesKdf(150_600_000UL), cores = 8))
    }

    @Test
    fun `many passes over little memory on several lanes warn, since every slice hands work to other threads`() {
        // 249 units on two lanes is 124.5 parallel units of compute, under the cap; the engine
        // also hands a task to another thread 8,160,000 times (4 slices per pass).
        val manyPasses = argon(iterations = 2_040_000UL, memory = 16_384UL, parallelism = 2U)
        for (cores in listOf(2, 4, 8)) assertNotNull(KdfPolicy.slowness(null, manyPasses, cores = cores), "$cores cores")
        // The same setting on more lanes hands work to more threads.
        assertNotNull(KdfPolicy.slowness(null, argon(iterations = 1_020_000UL, memory = 32_768UL, parallelism = 4U), cores = 8))
        // One worker has no other thread to hand work to; the compute alone stays under the cap.
        assertNull(KdfPolicy.slowness(null, argon(iterations = 1_020_000UL, memory = 8_192UL, parallelism = 1U), cores = 8))
        // The default Argon2 settings and a few hundred passes of them stay quiet.
        assertNull(KdfPolicy.slowness(null, argon(), cores = 8))
        assertNull(KdfPolicy.slowness(null, argon(iterations = 400UL), cores = 8))
    }

    @Test
    fun `the handoff cost moves the slowness estimate only, never the downgrade comparison`() {
        val manyPasses = argon(iterations = 2_040_000UL, memory = 16_384UL, parallelism = 2U)
        val oneLane = argon(iterations = 2_040_000UL, memory = 16_384UL, parallelism = 1U)
        assertEquals(KdfPolicy.workUnits(oneLane), KdfPolicy.workUnits(manyPasses))
        assertNull(KdfPolicy.compare(manyPasses, oneLane))
        assertNull(KdfPolicy.compare(oneLane, manyPasses))
    }

    @Test
    fun `stepping up under 10x at a time warns once past the cap`() {
        // Each unlock moves the baseline, so 30 -> 270 units would never pass the 10x test.
        val base = KdfSettings.AesKdf(18_000_000UL) // 30 units
        val slow = KdfPolicy.slowness(base, KdfSettings.AesKdf(162_000_000UL), cores = 8) // 270 units, 9x
        assertEquals(9, slow?.factor)
        assertNull(KdfPolicy.slowness(KdfSettings.AesKdf(162_000_000UL), KdfSettings.AesKdf(162_000_000UL), cores = 8), "unchanged settings")
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(
        strings = [
            "keepass2-default-aeskdf.kdbx", "keepass2-argon2id.kdbx", "keepass2-chacha20-argon2d.kdbx",
            "keepass2-kdbx41-tags.kdbx", "keepass2-weak-aeskdf-6000.kdbx", "keepass2-desktop-new-database.kdbx",
        ],
    )
    fun `no KeePass 2 fixture warns, with or without a baseline`(name: String) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/fixtures/$name")).readBytes()
        val kdf = assertIs<HeaderResult.Valid>(KdbxHeaderParser.parse(bytes)).header.kdf
        assertNull(KdfPolicy.slowness(null, kdf))
        assertNull(KdfPolicy.slowness(kdf, kdf))
    }

    private fun argon(iterations: ULong, memory: ULong) = KdfSettings.Argon2(Argon2Variant.ARGON2ID, iterations, memory, 2U, 0x13U)

    @Test
    fun `AES-KDF below 600000 rounds is weak, 600000 is not`() {
        assertTrue(KdfPolicy.isWeak(KdfSettings.AesKdf(599_999UL)))
        assertFalse(KdfPolicy.isWeak(KdfSettings.AesKdf(600_000UL)))
    }

    @Test
    fun `Argon2 below 2 iterations x 64 MiB is weak, exactly that is not`() {
        assertFalse(KdfPolicy.isWeak(argon(iterations = 2UL, memory = MIB_64)))
        assertFalse(KdfPolicy.isWeak(argon(iterations = 1UL, memory = 2UL * MIB_64)))
        assertTrue(KdfPolicy.isWeak(argon(iterations = 2UL, memory = MIB_64 - 1024UL)))
        assertTrue(KdfPolicy.isWeak(argon(iterations = 1UL, memory = MIB_64)))
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("comparisons")
    fun `comparison with the last opened settings`(
        case: String,
        baseline: KdfSettings,
        current: KdfSettings,
        expected: KdfRejection?,
    ) {
        assertEquals(expected, KdfPolicy.compare(baseline, current), case)
    }

    @Test
    fun `every KeePass 2 fixture is in bounds and only the 6000-round one is weak`() {
        val fixtures = listOf(
            "keepass2-default-aeskdf.kdbx" to false,
            "keepass2-desktop-new-database.kdbx" to false,
            "keepass2-argon2id.kdbx" to false,
            "keepass2-chacha20-argon2d.kdbx" to false,
            "keepass2-kdbx41-tags.kdbx" to false,
            "keepass2-weak-aeskdf-6000.kdbx" to true,
        )
        for ((name, weak) in fixtures) {
            val kdf = assertIs<HeaderResult.Valid>(KdbxHeaderParser.parse(KdbxHeaderParserTest.fixture(name))).header.kdf
            assertNull(KdfPolicy.checkBounds(kdf), name)
            assertEquals(weak, KdfPolicy.isWeak(kdf), name)
        }
    }

    @Test
    fun `Argon2 memory used is raised to 8 KiB per lane and rounded down to 4 KiB per lane`() {
        assertEquals(MIB_64, KdfPolicy.argon2MemoryUsedBytes(argon()))
        assertEquals(32_768UL, KdfPolicy.argon2MemoryUsedBytes(argon(memory = 8_192UL, parallelism = 4U)))
        assertEquals(24_576UL, KdfPolicy.argon2MemoryUsedBytes(argon(memory = 9_216UL, parallelism = 3U)))
        assertEquals(16_384UL, KdfPolicy.argon2MemoryUsedBytes(argon(memory = 20_480UL, parallelism = 2U)))
        assertEquals(8_192UL * 0xFF_FFFFUL, KdfPolicy.argon2MemoryUsedBytes(argon(memory = 8_192UL, parallelism = 0xFF_FFFFU)))
        assertEquals(0UL, KdfPolicy.argon2MemoryUsedBytes(argon(parallelism = 0U)))
    }

    @Test
    fun `a file stating little memory on many lanes is reported slow by the memory it uses`() {
        val replaced = argon(iterations = 16_384UL, memory = 8_192UL, parallelism = 8_192U)
        // By the stated memory this is half the baseline's work; by the memory used, 8,192
        // times it.
        assertEquals(KdfPolicy.workUnits(argon()) * 8_192, KdfPolicy.workUnits(replaced))
        val slow = assertNotNull(KdfPolicy.slowness(argon(), replaced, cores = 8))
        assertEquals(8_192, slow.factor)
        assertNull(KdfPolicy.compare(argon(), replaced))
    }

    @Test
    fun `the weak warning keeps KeePass 2's stated memory`() {
        assertTrue(KdfPolicy.isWeak(argon(memory = 8_192UL, parallelism = 8_192U)))
    }

    @Test
    fun `no baseline means nothing to compare`() {
        assertNull(KdfPolicy.compare(null, KdfSettings.AesKdf(1UL)))
    }

    companion object {
        private const val MIB_64 = 67_108_864UL
        private const val TWO_31 = 0x8000_0000UL

        fun argon(
            iterations: ULong = 2UL,
            memory: ULong = MIB_64,
            parallelism: UInt = 2U,
            version: UInt = 0x13U,
            variant: Argon2Variant = Argon2Variant.ARGON2ID,
        ) = KdfSettings.Argon2(variant, iterations, memory, parallelism, version)

        @JvmStatic
        fun outOfBounds(): List<Arguments> = listOf(
            Arguments.of("Argon2 iterations 0", argon(iterations = 0UL), KdfRejection.OutOfBounds(KdfSetting.ARGON2_ITERATIONS, 0UL)),
            Arguments.of("Argon2 iterations 2^31", argon(iterations = TWO_31), KdfRejection.OutOfBounds(KdfSetting.ARGON2_ITERATIONS, TWO_31)),
            Arguments.of("Argon2 iterations 2^32", argon(iterations = 1UL shl 32), KdfRejection.OutOfBounds(KdfSetting.ARGON2_ITERATIONS, 1UL shl 32)),
            Arguments.of("Argon2 parallelism 0", argon(parallelism = 0U), KdfRejection.OutOfBounds(KdfSetting.ARGON2_PARALLELISM, 0UL)),
            Arguments.of("Argon2 parallelism 2^24", argon(parallelism = 1U shl 24), KdfRejection.OutOfBounds(KdfSetting.ARGON2_PARALLELISM, 1UL shl 24)),
            Arguments.of("Argon2 memory below 8 KiB", argon(memory = 8_191UL, parallelism = 1U), KdfRejection.OutOfBounds(KdfSetting.ARGON2_MEMORY, 8_191UL)),
            Arguments.of("Argon2 memory 2^31", argon(memory = TWO_31), KdfRejection.OutOfBounds(KdfSetting.ARGON2_MEMORY, TWO_31)),
            Arguments.of("Argon2 version 0x12", argon(version = 0x12U), KdfRejection.OutOfBounds(KdfSetting.ARGON2_VERSION, 0x12UL)),
            Arguments.of("Argon2 version 0x14", argon(version = 0x14U), KdfRejection.OutOfBounds(KdfSetting.ARGON2_VERSION, 0x14UL)),
            Arguments.of("AES-KDF rounds 0", KdfSettings.AesKdf(0UL), KdfRejection.OutOfBounds(KdfSetting.AES_ROUNDS, 0UL)),
            Arguments.of("AES-KDF rounds 2^31", KdfSettings.AesKdf(TWO_31), KdfRejection.OutOfBounds(KdfSetting.AES_ROUNDS, TWO_31)),
        )

        @JvmStatic
        fun inBounds(): List<Arguments> = listOf(
            Arguments.of("Argon2 1 iteration, 8 KiB x p", argon(iterations = 1UL, memory = 16_384UL, parallelism = 2U)),
            // The derivation raises memory below 8 KiB per lane to 8 KiB per lane
            // (argon2MemoryUsedBytes).
            Arguments.of("Argon2 8 KiB with 4 lanes", argon(memory = 8_192UL, parallelism = 4U)),
            Arguments.of("Argon2 8 KiB at the most lanes", argon(memory = 8_192UL, parallelism = 0xFF_FFFFU)),
            Arguments.of("Argon2 iterations and memory just below 2^31", argon(iterations = TWO_31 - 1UL, memory = TWO_31 - 1UL)),
            Arguments.of("Argon2 memory just below 2^31 on 262,143 lanes", argon(memory = TWO_31 - 1UL, parallelism = 262_143U)),
            Arguments.of("Argon2 version 0x10", argon(version = 0x10U)),
            Arguments.of("AES-KDF 1 round", KdfSettings.AesKdf(1UL)),
            Arguments.of("AES-KDF 2^31 - 1 rounds", KdfSettings.AesKdf(TWO_31 - 1UL)),
        )

        @JvmStatic
        fun comparisons(): List<Arguments> = listOf(
            Arguments.of("AES fewer rounds", KdfSettings.AesKdf(600_000UL), KdfSettings.AesKdf(599_999UL),
                KdfRejection.Weakened(KdfSetting.AES_ROUNDS, 600_000UL, 599_999UL)),
            Arguments.of("AES same rounds", KdfSettings.AesKdf(600_000UL), KdfSettings.AesKdf(600_000UL), null),
            Arguments.of("AES more rounds", KdfSettings.AesKdf(600_000UL), KdfSettings.AesKdf(700_000UL), null),
            Arguments.of("Argon2id lower work", argon(), argon(memory = MIB_64 / 2UL),
                KdfRejection.Weakened(KdfSetting.ARGON2_WORK, 2UL * MIB_64, MIB_64)),
            Arguments.of("Argon2id same work, other split", argon(), argon(iterations = 4UL, memory = MIB_64 / 2UL), null),
            // 8 KiB stated on 8,192 lanes uses 64 MiB, the baseline's memory.
            Arguments.of("Argon2id low stated memory, same memory used", argon(), argon(memory = 8_192UL, parallelism = 8_192U), null),
            Arguments.of("Argon2id low stated memory, less memory used", argon(), argon(memory = 8_192UL, parallelism = 4_096U),
                KdfRejection.Weakened(KdfSetting.ARGON2_WORK, 2UL * MIB_64, MIB_64)),
            // 64 MiB is not a multiple of 4 KiB x 3 or 6 lanes; changing the lanes is no downgrade.
            Arguments.of("Argon2id 64 MiB from 2 to 3 lanes", argon(), argon(parallelism = 3U), null),
            Arguments.of("Argon2id 64 MiB from 2 to 6 lanes", argon(), argon(parallelism = 6U), null),
            Arguments.of("AES to strong Argon2id", KdfSettings.AesKdf(600_000UL), argon(), null),
            Arguments.of("AES to weak Argon2id with less work", KdfSettings.AesKdf(600_000UL), argon(iterations = 1UL),
                KdfRejection.Weakened(KdfSetting.WORK_UNITS, 1_000UL, 500UL)),
            Arguments.of("weak AES to weak Argon2id with more work", KdfSettings.AesKdf(6_000UL), argon(iterations = 1UL),
                KdfRejection.WeakAfterTypeChange(KdfSettings.AesKdf(6_000UL), argon(iterations = 1UL))),
            // The defaults for new databases are 1 unit each.
            Arguments.of("KeePass 2 default AES-KDF to default Argon2id", KdfSettings.AesKdf(600_000UL), argon(), null),
            Arguments.of("KeePass 2 default Argon2id to default AES-KDF", argon(), KdfSettings.AesKdf(600_000UL), null),
            Arguments.of("AES-KDF 60M rounds to default Argon2id", KdfSettings.AesKdf(60_000_000UL), argon(),
                KdfRejection.Weakened(KdfSetting.WORK_UNITS, 100_000UL, 1_000UL)),
            Arguments.of("Argon2id to stronger AES-KDF", argon(), KdfSettings.AesKdf(6_000_000UL), null),
            Arguments.of("Argon2d 20 x 64 MiB to AES-KDF with less work", argon(iterations = 20UL, variant = Argon2Variant.ARGON2D),
                KdfSettings.AesKdf(5_999_999UL), KdfRejection.Weakened(KdfSetting.WORK_UNITS, 10_000UL, 9_999UL)),
            // One AES-KDF round above the default is 1/600,000 unit; the display rounds the
            // remembered work up and the new work down, so the two numbers differ.
            Arguments.of("AES-KDF one round over 1 unit to default Argon2id", KdfSettings.AesKdf(600_001UL), argon(),
                KdfRejection.Weakened(KdfSetting.WORK_UNITS, 1_001UL, 1_000UL)),
            Arguments.of("Argon2id 1 KiB over 1 unit to default AES-KDF", argon(memory = MIB_64 + 1_024UL), KdfSettings.AesKdf(600_000UL),
                KdfRejection.Weakened(KdfSetting.WORK_UNITS, 1_001UL, 1_000UL)),
            Arguments.of("default Argon2id to AES-KDF one round over 1 unit", argon(), KdfSettings.AesKdf(600_001UL), null),
            // 8 KiB on 8,192 lanes counts as 64 MiB, as for the same type, so the work is no
            // less; the stated 8 KiB is weak.
            Arguments.of("AES-KDF default to Argon2id low stated memory on many lanes", KdfSettings.AesKdf(600_000UL),
                argon(memory = 8_192UL, parallelism = 8_192U),
                KdfRejection.WeakAfterTypeChange(KdfSettings.AesKdf(600_000UL), argon(memory = 8_192UL, parallelism = 8_192U))),
            Arguments.of("Argon2d to Argon2id with the same work", argon(variant = Argon2Variant.ARGON2D), argon(), null),
            Arguments.of("Argon2d to Argon2id with less work", argon(iterations = 10UL, variant = Argon2Variant.ARGON2D), argon(),
                KdfRejection.Weakened(KdfSetting.ARGON2_WORK, 10UL * MIB_64, 2UL * MIB_64)),
            Arguments.of("AES baseline, out-of-bounds AES current", KdfSettings.AesKdf(600_000UL), KdfSettings.AesKdf(1UL shl 32),
                KdfRejection.OutOfBounds(KdfSetting.AES_ROUNDS, 1UL shl 32)),
            Arguments.of("Argon2id to weak AES", argon(), KdfSettings.AesKdf(6_000UL),
                KdfRejection.Weakened(KdfSetting.WORK_UNITS, 1_000UL, 10UL)),
            Arguments.of("Argon2id at the most work to AES-KDF at the most rounds",
                argon(iterations = TWO_31 - 1UL, memory = 8_192UL, parallelism = 0xFF_FFFFU), KdfSettings.AesKdf(TWO_31 - 1UL),
                KdfRejection.Weakened(KdfSetting.WORK_UNITS, 2_199_023_123_456_001UL, 3_579_139UL)),
        )
    }
}
