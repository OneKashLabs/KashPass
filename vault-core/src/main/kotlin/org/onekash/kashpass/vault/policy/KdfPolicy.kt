package org.onekash.kashpass.vault.policy

import java.math.BigInteger
import org.onekash.kashpass.vault.header.KdfSettings

/** A key-derivation setting a rejection can name; the app turns it into a message. */
enum class KdfSetting {
    AES_ROUNDS,
    ARGON2_ITERATIONS,
    ARGON2_MEMORY,
    ARGON2_PARALLELISM,
    ARGON2_VERSION,

    /**
     * Argon2 iterations x memory in bytes. Weakness uses the stated memory; the downgrade
     * comparison raises it to 8 KiB per lane ([KdfPolicy.compare]).
     */
    ARGON2_WORK,

    /**
     * Key-derivation work in thousandths of [KdfPolicy.workUnits]' unit, for a switch between
     * AES-KDF and Argon2 ([KdfPolicy.compare]). Display only: the comparison itself is exact.
     */
    WORK_UNITS,
}

/** Why [KdfPolicy] refuses a vault's key-derivation settings. */
sealed interface KdfRejection {

    /** A value outside the bounds [KdfPolicy] accepts. */
    data class OutOfBounds(val setting: KdfSetting, val value: ULong) : KdfRejection

    /**
     * Less work than the last successful unlock: of the same KDF type, or of the other type with
     * [KdfSetting.WORK_UNITS].
     */
    data class Weakened(val setting: KdfSetting, val previous: ULong, val current: ULong) : KdfRejection

    /** A different KDF type, with no less work, whose settings are weak ([KdfPolicy.isWeak]). */
    data class WeakAfterTypeChange(val previous: KdfSettings, val current: KdfSettings) : KdfRejection
}

/**
 * Key-derivation settings that take far longer than before, reported before any derivation:
 * [factor] times the remembered settings, or null when there is nothing to compare with; [units]
 * is the work in [KdfPolicy.workUnits].
 */
data class SlowKdf(val kdf: KdfSettings, val factor: Int?, val units: Int)

/**
 * Checks whether key-derivation settings are safe to derive a key with.
 *
 * The weakness measure ([isWeak]) uses the stated Argon2 memory. The bounds: Argon2 version 0x10
 * or 0x13, parallelism 1 to 2^24 - 1, at least one iteration, memory at least 8 KiB; values of
 * 2^31 and above are refused because the derivation takes each value as a 32-bit signed integer;
 * AES-KDF needs at least one round. Memory below 8 KiB per lane is accepted and derived with 8 KiB
 * per lane ([argon2MemoryUsedBytes]); the slowness check
 * uses that memory, since it is what a derivation allocates and fills. The downgrade comparison
 * uses the stated memory raised to 8 KiB per lane, without the rounding down to 4 KiB per lane,
 * so changing only the lane count of a file that states at least 8 KiB per lane is never a
 * downgrade. The key derivation calls [checkBounds] before every derivation, since a save derives
 * before it checks the encoded header.
 */
object KdfPolicy {

    private const val LIMIT = 0x8000_0000UL // 2^31
    private const val MAX_PARALLELISM = 0xFF_FFFFUL // 2^24 - 1
    private const val MIN_MEMORY = 8_192UL // 8 KiB
    private const val WEAK_AES_ROUNDS = 600_000UL
    private const val WEAK_ARGON2_WORK = 134_217_728UL // 2 iterations x 64 MiB

    /** Returns the first setting outside the bounds, or null when every setting is inside. */
    fun checkBounds(kdf: KdfSettings): KdfRejection.OutOfBounds? = when (kdf) {
        is KdfSettings.AesKdf ->
            if (kdf.rounds < 1UL || kdf.rounds >= LIMIT) KdfRejection.OutOfBounds(KdfSetting.AES_ROUNDS, kdf.rounds) else null
        is KdfSettings.Argon2 -> {
            val lanes = kdf.parallelism.toULong()
            when {
                kdf.iterations < 1UL || kdf.iterations >= LIMIT ->
                    KdfRejection.OutOfBounds(KdfSetting.ARGON2_ITERATIONS, kdf.iterations)
                lanes < 1UL || lanes > MAX_PARALLELISM ->
                    KdfRejection.OutOfBounds(KdfSetting.ARGON2_PARALLELISM, lanes)
                kdf.memoryBytes < MIN_MEMORY || kdf.memoryBytes >= LIMIT ->
                    KdfRejection.OutOfBounds(KdfSetting.ARGON2_MEMORY, kdf.memoryBytes)
                kdf.version != 0x10U && kdf.version != 0x13U ->
                    KdfRejection.OutOfBounds(KdfSetting.ARGON2_VERSION, kdf.version.toULong())
                else -> null
            }
        }
    }

    /**
     * Returns true for weak settings: AES-KDF below 600,000 rounds, or Argon2 iterations x the
     * stated memory below 2 x 64 MiB. Call only with in-bounds settings.
     */
    fun isWeak(kdf: KdfSettings): Boolean = when (kdf) {
        is KdfSettings.AesKdf -> kdf.rounds < WEAK_AES_ROUNDS
        is KdfSettings.Argon2 -> work(kdf) < WEAK_ARGON2_WORK
    }

    /**
     * Checks [current] against the bounds, then against the settings of the last successful
     * unlock. AES-KDF to AES-KDF, or Argon2 to Argon2 (either variant), with less work is a
     * downgrade. A switch between AES-KDF and Argon2 compares both on the scale of [workUnits],
     * Argon2 by its iterations x the stated memory raised to 8 KiB per lane: less work is a
     * downgrade, and weak settings ([isWeak]) are refused even with more work. The switch is
     * compared exactly; [KdfSetting.WORK_UNITS] reports the remembered work rounded up and the new
     * work rounded down to a thousandth, so the two numbers always differ. [KdfPolicyTest] pins
     * each case.
     */
    fun compare(baseline: KdfSettings?, current: KdfSettings): KdfRejection? {
        checkBounds(current)?.let { return it }
        if (baseline == null) return null
        return when {
            baseline is KdfSettings.AesKdf && current is KdfSettings.AesKdf ->
                if (current.rounds < baseline.rounds) {
                    KdfRejection.Weakened(KdfSetting.AES_ROUNDS, baseline.rounds, current.rounds)
                } else {
                    null
                }
            baseline is KdfSettings.Argon2 && current is KdfSettings.Argon2 ->
                if (comparedWork(current) < comparedWork(baseline)) {
                    KdfRejection.Weakened(KdfSetting.ARGON2_WORK, comparedWork(baseline), comparedWork(current))
                } else {
                    null
                }
            else -> {
                val before = scaledWork(baseline)
                val now = scaledWork(current)
                when {
                    now < before -> KdfRejection.Weakened(KdfSetting.WORK_UNITS, thousandths(before, up = true), thousandths(now, up = false))
                    isWeak(current) -> KdfRejection.WeakAfterTypeChange(baseline, current)
                    else -> null
                }
            }
        }
    }

    // Work on one scale for both KDF types: [workUnits] x 600,000 x 134,217,728, so AES-KDF is
    // rounds x 134,217,728 and Argon2 is iterations x the stated memory raised to 8 KiB per lane
    // x 600,000. Exact, with no saturation.
    private fun scaledWork(kdf: KdfSettings): BigInteger = when (kdf) {
        is KdfSettings.AesKdf -> big(kdf.rounds) * big(WEAK_ARGON2_WORK)
        is KdfSettings.Argon2 -> {
            val memory = maxOf(kdf.memoryBytes, MIN_MEMORY * kdf.parallelism.toULong())
            big(kdf.iterations) * big(memory) * big(WEAK_AES_ROUNDS)
        }
    }

    // [scaled] ([scaledWork]) in thousandths of a unit, rounded [up] or down. In-bounds settings
    // give at most 2^31 iterations x 2^37 bytes x 1000 / 2^27, so it fits a ULong.
    private fun thousandths(scaled: BigInteger, up: Boolean): ULong {
        val divisor = big(WEAK_AES_ROUNDS) * big(WEAK_ARGON2_WORK)
        val (quotient, remainder) = (scaled * BigInteger.valueOf(1_000)).divideAndRemainder(divisor)
        val rounded = if (up && remainder.signum() != 0) quotient + BigInteger.ONE else quotient
        return rounded.toString().toULong()
    }

    private fun big(value: ULong): BigInteger = BigInteger(value.toString())

    /** A jump above this many times the remembered work is reported ([slowness]). */
    const val SLOW_FACTOR = 10.0

    /**
     * Work below this many units is never reported, so moving up from weak settings doesn't warn.
     */
    const val SLOW_FLOOR_UNITS = 10.0

    /**
     * Work above this many parallel units ([parallelUnits]) is reported when it is new: with no
     * remembered settings, or more than before (each unlock moves the baseline, so a file raised
     * under 10x per unlock would otherwise never warn). 1,000 iterations of 64 MiB on four lanes,
     * about a minute on a phone.
     */
    const val SLOW_CAP_PARALLEL_UNITS = 125.0

    private const val DEFAULT_AES_ROUNDS = 600_000.0
    private const val DEFAULT_ARGON2_WORK = 134_217_728.0 // 2 iterations x 64 MiB

    /**
     * Estimates derivation cost in units of the KDBX defaults for a new database (AES-KDF 600,000
     * rounds; Argon2 2 iterations x 64 MiB), so both KDF types compare on one scale. Those
     * defaults are sized for about a second on a desktop, and a phone is slower; the estimate only
     * ranks settings, it doesn't predict a time.
     */
    fun workUnits(kdf: KdfSettings): Double = when (kdf) {
        is KdfSettings.AesKdf -> kdf.rounds.toDouble() / DEFAULT_AES_ROUNDS
        is KdfSettings.Argon2 -> kdf.iterations.toDouble() * argon2MemoryUsedBytes(kdf).toDouble() / DEFAULT_ARGON2_WORK
    }

    /**
     * Estimates the time a derivation takes on [cores] processors: [workUnits] divided by the
     * lanes that run at once, plus [HANDOFF_UNITS] for each task Argon2 hands to another thread.
     * KashPass's key derivation runs Argon2's lanes in parallel and AES-KDF's two halves on two
     * threads. With w = min(parallelism, cores) workers above one, every slice (4 per pass)
     * submits w - 1 tasks and waits for them, whatever the memory, so many passes over little
     * memory cost more in handoffs than in compute ([KdfPolicyTest]). One worker hands nothing
     * over.
     */
    fun parallelUnits(kdf: KdfSettings, cores: Int = Runtime.getRuntime().availableProcessors()): Double = when (kdf) {
        is KdfSettings.AesKdf -> workUnits(kdf) / minOf(2, cores).coerceAtLeast(1)
        is KdfSettings.Argon2 -> {
            val workers = minOf(kdf.parallelism.toLong(), cores.toLong()).coerceAtLeast(1L)
            val handoffs = kdf.iterations.toDouble() * SLICES_PER_PASS * (workers - 1)
            workUnits(kdf) / workers + handoffs * HANDOFF_UNITS
        }
    }

    /**
     * Cost of handing one Argon2 slice task to another thread and waiting for it, in [workUnits].
     * Measured with KashPass's key derivation on a 16-core x86-64 host (JVM, 2026-10-29): one
     * unit (Argon2id 2 x 64 MiB on one thread) took 0.16 s, and a slice over 16 KiB cost about
     * 6.4 us more per task handed over on two workers than on one (5.3 us on four, 3.6 us on
     * eight). 6.4 us / 0.16 s is 4e-5. The ratio on a phone is not measured.
     */
    const val HANDOFF_UNITS = 4e-5

    private const val SLICES_PER_PASS = 4

    /**
     * Reports [current] when deriving with it would take far longer than with [baseline]: more than
     * [SLOW_FACTOR] times its work and at least [SLOW_FLOOR_UNITS], or more work than the baseline
     * and above [SLOW_CAP_PARALLEL_UNITS] on [cores] processors, or with no baseline above
     * [SLOW_CAP_PARALLEL_UNITS]. Someone who can replace the file can otherwise make an unlock run
     * for hours. The user can cancel a running derivation, but only this report warns before it
     * starts. Call only with in-bounds settings. [SlowKdf.units] reports
     * [workUnits], the scale of the message.
     */
    fun slowness(
        baseline: KdfSettings?,
        current: KdfSettings,
        cores: Int = Runtime.getRuntime().availableProcessors(),
    ): SlowKdf? {
        val units = workUnits(current)
        val overCap = parallelUnits(current, cores) > SLOW_CAP_PARALLEL_UNITS
        if (baseline == null) return if (overCap) SlowKdf(current, null, units.toInt()) else null
        val ratio = units / workUnits(baseline)
        val jump = units >= SLOW_FLOOR_UNITS && ratio > SLOW_FACTOR
        val newlyOverCap = overCap && ratio > 1.0
        return if (jump || newlyOverCap) SlowKdf(current, ratio.toInt(), units.toInt()) else null
    }

    /**
     * Returns the memory in bytes an Argon2 derivation with [kdf] allocates: the stated memory in
     * KiB, raised to 8 KiB per lane, rounded down to a multiple of 4 KiB per lane. The stated
     * memory itself goes into Argon2's pre-hash. The result is at most the larger of the stated
     * memory and 8 KiB x 2^32, so it never overflows.
     */
    fun argon2MemoryUsedBytes(kdf: KdfSettings.Argon2): ULong {
        val lanes = kdf.parallelism.toULong()
        if (lanes == 0UL) return 0UL
        val blocks = maxOf(kdf.memoryBytes / 1024UL, 8UL * lanes)
        return blocks / (4UL * lanes) * (4UL * lanes) * 1024UL
    }

    // Both factors are below 2^31 once checkBounds passed, so the product fits in a ULong.
    private fun work(kdf: KdfSettings.Argon2): ULong = kdf.iterations * kdf.memoryBytes

    // Iterations x the stated memory raised to 8 KiB per lane; saturates at ULong.MAX_VALUE, since
    // 2^24 lanes of 8 KiB times 2^31 iterations passes 2^64.
    private fun comparedWork(kdf: KdfSettings.Argon2): ULong {
        val memory = maxOf(kdf.memoryBytes, MIN_MEMORY * kdf.parallelism.toULong())
        return if (memory != 0UL && kdf.iterations > ULong.MAX_VALUE / memory) ULong.MAX_VALUE else kdf.iterations * memory
    }
}
