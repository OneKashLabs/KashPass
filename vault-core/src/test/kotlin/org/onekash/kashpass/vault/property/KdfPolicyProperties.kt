package org.onekash.kashpass.vault.property

import io.kotest.property.checkAll
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.KdfEngine
import org.onekash.kashpass.vault.doc.KdfOutOfBoundsException
import org.onekash.kashpass.vault.doc.KdfSaltException
import org.onekash.kashpass.vault.doc.KeyDerivation
import org.onekash.kashpass.vault.doc.VaultKey
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.decode
import org.onekash.kashpass.vault.header.Argon2Variant
import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.kdbx.Argon2Type
import org.onekash.kashpass.vault.kdbx.KdbxDamage
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.kdbx.KdfParameters
import org.onekash.kashpass.vault.policy.KdfPolicy
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.u32
import org.onekash.kashpass.vault.testing.u64

/**
 * KDF settings are checked before any key is derived ([KdfPolicy], GHSA-6c49-vgg8-vhmj): every
 * setting KdfPolicy accepts derives, a rejected one in a header stops the open with the policy's
 * refusal and no derivation, and KdfEngine refuses it again before any work. An Argon2 salt outside
 * 8 bytes to the reader's limit is damage, found while the header is read.
 */
class KdfPolicyProperties {

    private val credentials = VaultKey.password(TestVaults.PASSWORD.toCharArray())
    private val limits = VaultXmlCodec.Limits(open = 1 shl 20, save = 1L shl 20)

    // Settings small enough to derive in a unit test: memory within 1 MiB and at most 16 lanes.
    private fun cheap(s: KdfSettings) = when (s) {
        is KdfSettings.AesKdf -> s.rounds <= 10_000UL
        is KdfSettings.Argon2 -> s.iterations <= 3UL && s.memoryBytes <= 1_048_576UL && s.parallelism <= 16U
    }

    private fun countingKdf(calls: AtomicInteger) = KeyDerivation { p, k -> calls.incrementAndGet(); KdfEngine().derive(p, k) }

    // KdfEngine refuses [parameters] with [T] before it allocates or starts any work.
    private inline fun <reified T : Throwable> refusedBeforeWork(parameters: KdfParameters, what: String): T {
        var touched = false
        val engine = KdfEngine(allocate = { touched = true; LongArray(it) }, beforeWork = { touched = true })
        val refused = assertFailsWith<T>(what) { engine.derive(parameters, ByteArray(32)) }
        assertTrue(!touched, "$what: KdfEngine worked before refusing")
        return refused
    }

    private fun parameters(s: KdfSettings): KdfParameters = when (s) {
        is KdfSettings.AesKdf -> KdfParameters.Aes(s.rounds, ByteArray(32) { 1 })
        is KdfSettings.Argon2 -> KdfParameters.Argon2(
            if (s.variant == Argon2Variant.ARGON2D) Argon2Type.ARGON2D else Argon2Type.ARGON2ID,
            ByteArray(16) { 2 }, s.parallelism, s.memoryBytes, s.iterations, s.version, null, null,
        )
    }

    @Test
    fun `every setting the policy accepts derives, the same key each time`() = runBlocking<Unit> {
        var derived = 0
        checkAll(PropertyRuns.config(300), Generators.kdfSettings) { s ->
            if (KdfPolicy.checkBounds(s) != null || !cheap(s)) return@checkAll
            val key = ByteArray(32) { 3 }
            val first = KdfEngine().derive(parameters(s), key.copyOf())
            assertEquals(32, first.size, "$s")
            assertContentEquals(first, KdfEngine().derive(parameters(s), key.copyOf()), "$s")
            derived++
        }
        assertTrue(derived > 0, "no accepted setting was cheap enough to derive")
        // Argon2 from accepted values only, since a random Argon2 setting is rarely both accepted
        // and cheap: each variant, each version and memory below 8 KiB per lane.
        val seen = mutableSetOf<String>()
        checkAll(PropertyRuns.config(40), Generators.acceptedArgon2) { s ->
            assertEquals(null, KdfPolicy.checkBounds(s), "$s")
            val key = ByteArray(32) { 3 }
            assertContentEquals(KdfEngine().derive(parameters(s), key.copyOf()), KdfEngine().derive(parameters(s), key.copyOf()), "$s")
            seen += "${s.variant}"
            seen += "version ${s.version}"
            if (s.memoryBytes < 8_192UL * s.parallelism) seen += "below 8 KiB per lane"
        }
        val wanted = setOf("ARGON2D", "ARGON2ID", "version 16", "version 19", "below 8 KiB per lane")
        assertTrue(seen.containsAll(wanted), "Argon2 cases derived: $seen")
    }

    @Test
    fun `a rejected setting stops the open with the policy's refusal and no derivation, and KdfEngine refuses it too`() = runBlocking<Unit> {
        var rejected = 0
        checkAll(PropertyRuns.config(300), Generators.kdfSettings) { s ->
            val rejection = KdfPolicy.checkBounds(s) ?: return@checkAll
            rejected++
            val calls = AtomicInteger()
            val result = VaultXmlCodec.decode(withSettings(s), credentials, limits, countingKdf(calls))
            assertEquals(Decoded.Refused(rejection), result, "$s")
            assertEquals(0, calls.get(), "$s reached the KDF")
            assertEquals(rejection, refusedBeforeWork<KdfOutOfBoundsException>(parameters(s), "$s").rejection)
        }
        assertTrue(rejected > 0, "no rejected setting was generated")
    }

    @Test
    fun `an Argon2 salt outside 8 bytes to the reader's limit is damage before any derivation`() {
        // Every length from 0 to 40, so both boundaries (7 and 8, 31 and 32) are tried.
        for (length in 0..40) {
            val bytes = argon2Vault.let { layers -> KdbxToolkit.build(layers.copy(header = layers.header.withKdf { it.with("S", RawDictionary.BYTES, ByteArray(length) { 4 }) }, kdfHeader = layers.header)) }
            // The upper bound through the reader's test parameter, as a 1 GiB salt cannot be built.
            val read = KdbxHeaderReader.read(bytes, maxSaltBytes = 31)
            if (length < 8 || length > 31) assertEquals(KdbxResult.Damaged(KdbxDamage.KDF_PARAMETERS), (read as KdbxHeaderReader.Read.Invalid).result, "salt of $length")
            else assertIs<KdbxHeaderReader.Read.Valid>(read, "salt of $length")
            if (length < 8) {
                val calls = AtomicInteger()
                val result = VaultXmlCodec.decode(bytes, credentials, limits, countingKdf(calls))
                assertEquals(Decoded.Damaged(DamageReason.KDF_PARAMETERS), result, "salt of $length")
                assertEquals(0, calls.get(), "salt of $length reached the KDF")
                refusedBeforeWork<KdfSaltException>(KdfParameters.Argon2(Argon2Type.ARGON2ID, ByteArray(length), 1U, 8_192UL, 1UL, 0x13U, null, null), "salt of $length")
            }
        }
    }

    private val argon2Vault by lazy {
        KdbxToolkit.open(
            KdbxToolkit.newVault(
                TestVaults.keePassXml().toByteArray(Charsets.UTF_8), emptyList(), KdbxToolkit.Key(TestVaults.PASSWORD),
                KdbxToolkit.Kdf.Argon2(true, ByteArray(32), 2U, 64UL * 1024UL, 1UL, 0x13U, null, null),
            ),
            KdbxToolkit.Key(TestVaults.PASSWORD),
        ).layers
    }

    private val aesVault by lazy { KdbxToolkit.open(TestVaults.bytes(aesRounds = 1_000UL), KdbxToolkit.Key(TestVaults.PASSWORD)).layers }

    // A vault keyed by an accepted header whose stored KDF dictionary says [s].
    private fun withSettings(s: KdfSettings): ByteArray = when (s) {
        is KdfSettings.AesKdf -> aesVault.let { l -> KdbxToolkit.build(l.copy(header = l.header.withKdf { it.with("R", RawDictionary.UINT64, u64(s.rounds)) }, kdfHeader = l.header)) }
        is KdfSettings.Argon2 -> argon2Vault.let { l ->
            val header = l.header.withKdf {
                it.with("I", RawDictionary.UINT64, u64(s.iterations)).with("M", RawDictionary.UINT64, u64(s.memoryBytes))
                    .with("P", RawDictionary.UINT32, u32(s.parallelism.toLong())).with("V", RawDictionary.UINT32, u32(s.version.toLong()))
            }
            KdbxToolkit.build(l.copy(header = header, kdfHeader = l.header))
        }
    }
}
