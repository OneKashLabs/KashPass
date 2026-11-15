package org.onekash.kashpass.vault.kdbx

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.fail
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawEntry
import org.onekash.kashpass.vault.testing.RawField
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.le32
import org.onekash.kashpass.vault.testing.le64

/**
 * The KDF parameters [KdbxHeaderWriter] returns are the ones its header bytes hold: the reader
 * builds the same from the bytes, and so does the test toolkit's own fold of the written fields.
 * Every setting but the fresh salt or seed is the opened file's.
 */
class HeaderWriterFoldTest {

    @ParameterizedTest
    @MethodSource("cases")
    fun `the returned KDF parameters are the ones the written header holds`(name: String) {
        val raw = CASES.getValue(name)
        val opened = openedHeader(raw)
        val written = writtenHeader(raw)

        val reread = assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(written.bytes), name).header
        assertKdfEquals(reread.kdf, written.kdf, withSalt = true, name)
        assertContentEquals(reread.masterSeed, written.header.masterSeed, name)
        assertContentEquals(reread.iv, written.header.iv, name)

        val fields = RawKdbx.parse(written.bytes)
        assertToolkitReads(KdbxToolkit.effective(fields).kdf, written.kdf, name)
        assertContentEquals(fields.field(RawKdbx.MASTER_SEED), written.header.masterSeed, name)
        assertContentEquals(fields.field(RawKdbx.ENCRYPTION_IV), written.header.iv, name)

        assertKdfEquals(opened.kdf, written.kdf, withSalt = false, name)
        assertEquals(32, saltOf(written.kdf).size, name)
    }

    // Compares the test toolkit's reading of the written fields with the writer's parameters.
    private fun assertToolkitReads(expected: KdbxToolkit.Kdf, actual: KdfParameters, name: String) {
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
        private val weak = RawKdbx.parse(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"))
        private val argon2id = RawKdbx.parse(Fixtures.bytes("keepass2-argon2id.kdbx"))
        private val seed = weak.kdf().entries.single { it.key == "S" }.value

        private val CASES: Map<String, RawKdbx> = mapOf(
            "uuid-last" to weak.withKdf { it.copy(entries = it.entries.reversed()) },
            "unknown-entries" to weak.withKdf {
                it.plus(RawEntry(RawDictionary.UINT32, "X", le32(7))).plus(RawEntry(RawDictionary.STRING, "note", "text".encodeToByteArray()))
            },
            "argon2-k-and-a" to RawKdbx.parse(Fixtures.bytes("keepass2-argon2-secret-and-data.kdbx")),
            "argon2-k-not-bytes" to argon2id.withKdf { it.plus(RawEntry(RawDictionary.UINT32, "K", le32(5))) },
            "argon2id" to argon2id,
            "argon2d-chacha20" to RawKdbx.parse(Fixtures.bytes("keepass2-chacha20-argon2d.kdbx")),
            "argon2id-uuid-last" to argon2id.withKdf { it.copy(entries = it.entries.drop(1) + it.entries.first()) },
            "kdbx3-fold-no-kdf" to weak.withoutField(RawKdbx.KDF_PARAMETERS)
                .plusField(RawField(RawKdbx.TRANSFORM_SEED, seed)).plusField(RawField(RawKdbx.TRANSFORM_ROUNDS, le64(6000))),
            "kdbx3-fold-after-argon2" to argon2id.plusField(RawField(RawKdbx.TRANSFORM_SEED, seed)).plusField(RawField(RawKdbx.TRANSFORM_ROUNDS, le64(6000))),
            "kdbx3-rounds-after-aes-kdf" to weak.plusField(RawField(RawKdbx.TRANSFORM_ROUNDS, le64(7000))),
            "kdbx3-rounds-before-kdf" to weak.insertBefore(RawKdbx.KDF_PARAMETERS, RawField(RawKdbx.TRANSFORM_ROUNDS, le64(7000))),
            "aes-kdf-seed-16-bytes" to weak.withKdf { it.with("S", RawDictionary.BYTES, seed.copyOf(16)) },
        )

        @JvmStatic
        fun cases(): List<String> = CASES.keys.toList()
    }
}
