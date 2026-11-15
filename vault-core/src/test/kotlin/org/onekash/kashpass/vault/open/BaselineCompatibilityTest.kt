package org.onekash.kashpass.vault.open

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.doc.HeaderRead
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.Kdbx3Vaults
import org.onekash.kashpass.vault.header.Argon2Variant
import org.onekash.kashpass.vault.header.HeaderResult
import org.onekash.kashpass.vault.header.KdbxHeaderParser
import org.onekash.kashpass.vault.header.KdbxHeaderParserTest.Companion.fixture
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.policy.KdfPolicy
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.policy.KdfSetting
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage

/**
 * KDF baselines are stored formats: app versions before KashPass's own container stored the
 * settings [KdbxHeaderParser] built. For every file it accepted, KashPass's own header reader must
 * build equal settings, so no baseline those versions stored reads as a downgrade.
 */
class BaselineCompatibilityTest {

    @Test
    fun `every file the reference header parser accepts gets equal KDF settings from KashPass's header reader`() {
        // A file the KDF bounds refuse has no baseline stored. A file the corpus marks damaged
        // does not open.
        val damaged = Corpus.all.filter { it.spec == Spec.DAMAGED }.mapTo(HashSet()) { it.name }
        val files = (Fixtures.kdbx4.map(Fixtures::file) + Kdbx3Vaults.files).map { it.name to it.bytes } + Corpus.all.map { it.name to it.bytes }
        var compared = 0
        val wrong = files.mapNotNull { (name, bytes) ->
            val before = (KdbxHeaderParser.parse(bytes) as? HeaderResult.Valid)?.header?.kdf ?: return@mapNotNull null
            if (KdfPolicy.checkBounds(before) != null) return@mapNotNull null
            compared++
            val now = (VaultXmlCodec.header(bytes, org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.NO_HEAP_LIMIT) as? HeaderRead.Valid)?.header?.kdf
            when {
                now == null -> if (name in damaged) null else "$name: the owned reader refuses it"
                now != before -> "$name: $now, earlier $before"
                KdfPolicy.compare(before, now) != null -> "$name: reads as a downgrade"
                else -> null
            }
        }
        assertTrue(compared > 100, "$compared compared")
        assertTrue(wrong.isEmpty(), wrong.joinToString("\n"))
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("storedBaselines")
    fun `a stored baseline of either KDF type is compared with a file of the other type by work`(
        case: String,
        stored: KdfSettings,
        file: String,
        expected: KdfRejection?,
    ) = runBlocking {
        val state = FakeVaultStateStore().apply { saveKdfBaseline(LOC, stored) }
        val storage = FakeVaultStorage().apply { put(LOC, fixture(file)) }
        val result = VaultOpener.create(storage, state, Dispatchers.Unconfined).check(LOC)
        if (expected == null) assertIs<OpenResult.Ready>(result, case) else assertEquals(OpenResult.Refused(expected), result, case)
    }

    companion object {
        private const val LOC = "content://test/vault.kdbx"
        private const val MIB_64 = 67_108_864UL

        // The settings as every app version stores them: AES-KDF rounds, or the Argon2 variant,
        // iterations, stated memory, lanes and version.
        @JvmStatic
        fun storedBaselines(): List<Arguments> = listOf(
            Arguments.of("AES-KDF 600,000 to Argon2id 2 x 64 MiB", KdfSettings.AesKdf(600_000UL), "keepass2-argon2id.kdbx", null),
            Arguments.of(
                "AES-KDF 60,000,000 to Argon2id 2 x 64 MiB", KdfSettings.AesKdf(60_000_000UL), "keepass2-argon2id.kdbx",
                KdfRejection.Weakened(KdfSetting.WORK_UNITS, 100_000UL, 1_000UL),
            ),
            Arguments.of(
                "Argon2d 2 x 64 MiB to AES-KDF 600,000", KdfSettings.Argon2(Argon2Variant.ARGON2D, 2UL, MIB_64, 2U, 0x13U),
                "keepass2-default-aeskdf.kdbx", null,
            ),
            Arguments.of(
                "Argon2id 20 x 64 MiB to AES-KDF 600,000", KdfSettings.Argon2(Argon2Variant.ARGON2ID, 20UL, MIB_64, 2U, 0x13U),
                "keepass2-default-aeskdf.kdbx", KdfRejection.Weakened(KdfSetting.WORK_UNITS, 10_000UL, 1_000UL),
            ),
        )
    }
}
