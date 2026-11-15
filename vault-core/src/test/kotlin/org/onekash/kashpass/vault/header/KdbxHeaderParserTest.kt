package org.onekash.kashpass.vault.header

import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawEntry
import org.onekash.kashpass.vault.testing.RawField
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.u32
import org.onekash.kashpass.vault.testing.u64
import org.onekash.kashpass.vault.testing.uuidBytes

class KdbxHeaderParserTest {

    private fun valid(bytes: ByteArray): KdbxHeader =
        assertIs<HeaderResult.Valid>(KdbxHeaderParser.parse(bytes)).header

    @Test
    fun `default KeePass 2 vault is KDBX 4_0, AES-256, AES-KDF 600000`() {
        assertEquals(
            KdbxHeader(4, 0, KdbxCipher.AES_256, KdfSettings.AesKdf(600_000UL)),
            valid(fixture("keepass2-default-aeskdf.kdbx")),
        )
    }

    @Test
    fun `desktop-saved vault matches the generated default`() {
        assertEquals(
            KdbxHeader(4, 0, KdbxCipher.AES_256, KdfSettings.AesKdf(600_000UL)),
            valid(fixture("keepass2-desktop-new-database.kdbx")),
        )
    }

    @Test
    fun `Argon2id vault has KeePass 2 defaults`() {
        assertEquals(
            KdbxHeader(4, 0, KdbxCipher.AES_256, ARGON2ID_DEFAULT),
            valid(fixture("keepass2-argon2id.kdbx")),
        )
    }

    @Test
    fun `ChaCha20 vault uses Argon2d`() {
        assertEquals(
            KdbxHeader(4, 0, KdbxCipher.CHACHA20, ARGON2ID_DEFAULT.copy(variant = Argon2Variant.ARGON2D)),
            valid(fixture("keepass2-chacha20-argon2d.kdbx")),
        )
    }

    @Test
    fun `tagged vault is KDBX 4_1`() {
        assertEquals(1, valid(fixture("keepass2-kdbx41-tags.kdbx")).minorVersion)
    }

    @Test
    fun `weak vault has 6000 AES-KDF rounds`() {
        assertEquals(KdfSettings.AesKdf(6_000UL), valid(fixture("keepass2-weak-aeskdf-6000.kdbx")).kdf)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("damagedCases")
    fun `ambiguous or broken headers are damaged`(case: String, bytes: ByteArray, expected: DamageReason) {
        val result = KdbxHeaderParser.parse(bytes)
        assertEquals(HeaderResult.Damaged(expected), result, case)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unsupportedCases")
    fun `well-formed files with other formats or algorithms are unsupported`(
        case: String,
        bytes: ByteArray,
        expected: UnsupportedReason,
    ) {
        assertEquals(HeaderResult.Unsupported(expected), KdbxHeaderParser.parse(bytes), case)
    }

    @Test
    fun `random bytes of any length never throw`() {
        val random = Random(42)
        repeat(500) {
            val bytes = random.nextBytes(random.nextInt(0, 300))
            assertIs<HeaderResult.Damaged>(KdbxHeaderParser.parse(bytes))
        }
    }

    @Test
    fun `every prefix of a valid file is damaged, never thrown`() {
        val bytes = fixture("keepass2-argon2id.kdbx")
        val headerEnd = RawKdbx.parse(bytes).let { bytes.size - it.rest.size }
        for (n in 0 until headerEnd) {
            val result = KdbxHeaderParser.parse(bytes.copyOf(n))
            if (result !is HeaderResult.Damaged) fail("prefix of $n bytes gave $result")
        }
    }

    companion object {
        val ARGON2ID_DEFAULT = KdfSettings.Argon2(
            variant = Argon2Variant.ARGON2ID,
            iterations = 2UL,
            memoryBytes = 64UL * 1024UL * 1024UL,
            parallelism = 2U,
            version = 0x13U,
        )

        fun fixture(name: String): ByteArray =
            requireNotNull(KdbxHeaderParserTest::class.java.getResourceAsStream("/fixtures/$name")) { name }
                .use { it.readBytes() }

        private fun argon(): RawKdbx = RawKdbx.parse(fixture("keepass2-argon2id.kdbx"))

        private fun aes(): RawKdbx = RawKdbx.parse(fixture("keepass2-default-aeskdf.kdbx"))

        @JvmStatic
        fun damagedCases(): List<Arguments> = listOf(
            Arguments.of("empty", ByteArray(0), DamageReason.NOT_A_KEEPASS_FILE),
            Arguments.of("not a KeePass signature", ByteArray(64) { 7 }, DamageReason.NOT_A_KEEPASS_FILE),
            Arguments.of("signature only", fixture("keepass2-argon2id.kdbx").copyOf(8), DamageReason.TRUNCATED),
            Arguments.of(
                "repeated cipher field",
                argon().plusField(RawField(RawKdbx.CIPHER_ID, uuidBytes(CHACHA20))).toBytes(),
                DamageReason.DUPLICATE_FIELD,
            ),
            Arguments.of(
                "second KDF field with iterations 0",
                argon().let { it.plusField(RawField(RawKdbx.KDF_PARAMETERS, it.kdf().with("I", RawDictionary.UINT64, u64(0UL)).toBytes())) }.toBytes(),
                DamageReason.DUPLICATE_FIELD,
            ),
            Arguments.of(
                "repeated dictionary key, later I = 0",
                argon().withKdf { it.plus(RawEntry(RawDictionary.UINT64, "I", u64(0UL))) }.toBytes(),
                DamageReason.DUPLICATE_KEY,
            ),
            Arguments.of(
                "unknown variant type hiding a value",
                argon().withKdf { it.plus(RawEntry(0x99, "X", u64(0UL))) }.toBytes(),
                DamageReason.UNKNOWN_VALUE_TYPE,
            ),
            Arguments.of(
                "trailing bytes after the dictionary terminator",
                argon().withKdf { it.copy(trailing = byteArrayOf(RawDictionary.UINT64.toByte(), 1, 0, 0, 0)) }.toBytes(),
                DamageReason.TRAILING_BYTES,
            ),
            Arguments.of(
                "iterations stored as UInt32",
                argon().withKdf { it.with("I", RawDictionary.UINT32, u32(2)) }.toBytes(),
                DamageReason.WRONG_VALUE_TYPE,
            ),
            Arguments.of(
                "parallelism stored as UInt64",
                argon().withKdf { it.with("P", RawDictionary.UINT64, u64(2UL)) }.toBytes(),
                DamageReason.WRONG_VALUE_TYPE,
            ),
            Arguments.of(
                "AES rounds stored as Int32",
                aes().withKdf { it.with("R", RawDictionary.INT32, u32(600_000)) }.toBytes(),
                DamageReason.WRONG_VALUE_TYPE,
            ),
            Arguments.of(
                "UInt64 value with a 4-byte length",
                argon().withKdf { it.without("I").plus(RawEntry(RawDictionary.UINT64, "I", u32(2))) }.toBytes(),
                DamageReason.INVALID_LENGTH,
            ),
            Arguments.of(
                "negative field length",
                argon().plusField(RawField(1, ByteArray(0), declaredLength = -1)).toBytes(),
                DamageReason.INVALID_LENGTH,
            ),
            Arguments.of(
                "negative dictionary value length",
                argon().withKdf { it.plus(RawEntry(RawDictionary.BYTES, "Z", ByteArray(0), declaredLength = -4)) }.toBytes(),
                DamageReason.INVALID_LENGTH,
            ),
            Arguments.of(
                "compression value 2",
                argon().withField(RawKdbx.COMPRESSION, u32(2)).toBytes(),
                DamageReason.INVALID_COMPRESSION,
            ),
            Arguments.of(
                "unknown header field id 13",
                argon().plusField(RawField(13, ByteArray(4))).toBytes(),
                DamageReason.UNKNOWN_FIELD,
            ),
            Arguments.of(
                "no KDF field",
                argon().withoutField(RawKdbx.KDF_PARAMETERS).toBytes(),
                DamageReason.MISSING_FIELD,
            ),
            Arguments.of(
                "Argon2 without iterations",
                argon().withKdf { it.without("I") }.toBytes(),
                DamageReason.MISSING_FIELD,
            ),
            Arguments.of(
                "dictionary version 2.0",
                argon().withKdf { it.copy(version = 0x0200) }.toBytes(),
                DamageReason.INVALID_DICTIONARY,
            ),
            Arguments.of(
                "field length 2^31 - 1 on a short file",
                argon().plusField(RawField(RawKdbx.CIPHER_ID, ByteArray(16), declaredLength = Int.MAX_VALUE)).toBytes(),
                DamageReason.TRUNCATED,
            ),
            Arguments.of(
                "dictionary value length 2^31 - 1",
                argon().withKdf { it.plus(RawEntry(RawDictionary.BYTES, "Z", ByteArray(0), declaredLength = Int.MAX_VALUE)) }.toBytes(),
                DamageReason.TRUNCATED,
            ),
            Arguments.of(
                "KDBX 3 transform rounds field in a KDBX 4 header",
                argon().plusField(RawField(6, ByteArray(0))).toBytes(),
                DamageReason.UNKNOWN_FIELD,
            ),
            Arguments.of(
                "KDBX 3 inner stream id field in a KDBX 4 header",
                argon().plusField(RawField(10, ByteArray(0))).toBytes(),
                DamageReason.UNKNOWN_FIELD,
            ),
            Arguments.of(
                "cipher id of 15 bytes",
                argon().withField(RawKdbx.CIPHER_ID, ByteArray(15)).toBytes(),
                DamageReason.INVALID_LENGTH,
            ),
        )

        @JvmStatic
        fun unsupportedCases(): List<Arguments> = listOf(
            Arguments.of("KDBX 3.1", argon().copy(major = 3, minor = 1).toBytes(), UnsupportedReason.FormatVersion(3, 1)),
            Arguments.of("KDBX 5.0", argon().copy(major = 5, minor = 0).toBytes(), UnsupportedReason.FormatVersion(5, 0)),
            Arguments.of(
                "KeePass 1.x signature",
                byteArrayOf(0x03, 0xD9.toByte(), 0xA2.toByte(), 0x9A.toByte(), 0x65, 0xFB.toByte(), 0x4B, 0xB5.toByte()) + ByteArray(64),
                UnsupportedReason.FormatVersion(1, 0),
            ),
            Arguments.of(
                "Twofish cipher",
                argon().withField(RawKdbx.CIPHER_ID, uuidBytes(TWOFISH)).toBytes(),
                UnsupportedReason.Cipher(TWOFISH),
            ),
            Arguments.of(
                "the AES-KDF id other KDBX 4 writers use",
                aes().withKdf { it.with("\$UUID", RawDictionary.BYTES, uuidBytes(AES_KDF_OTHER_WRITERS)) }.toBytes(),
                UnsupportedReason.Kdf(AES_KDF_OTHER_WRITERS),
            ),
        )

        const val CHACHA20 = "d6038a2b-8b6f-4cb5-a524-339a31dbb59a"
        const val TWOFISH = "ad68f29f-576f-4bb9-a36a-d47af965346c"
        const val AES_KDF_OTHER_WRITERS = "7c02bb82-79a7-4ac0-927d-114a00648238"
    }
}
