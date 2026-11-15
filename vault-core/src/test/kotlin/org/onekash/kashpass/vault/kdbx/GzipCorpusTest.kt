package org.onekash.kashpass.vault.kdbx

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.kdbx.GzipReader.Ending
import org.onekash.kashpass.vault.testing.Gzip
import org.onekash.kashpass.vault.testing.KdbxToolkit

/**
 * The corrupted corpus's gzip cases and the gzip fixtures through [GzipReader], with the result
 * KeePass 2 on Windows reads at this layer (the inner header and XML parse check the rest).
 */
class GzipCorpusTest {

    private val key = KdbxToolkit.Key(TestFiles.password)

    // Every corpus case builds on this vault's payload.
    private val base by lazy { KdbxToolkit.open(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"), key).contentBytes }

    @Test
    fun `every gzip case of the corpus has an expected result here`() {
        val names = Corpus.all.map { it.name }.filter { it.startsWith("gzip-") || it.startsWith("compression-gzip-") }
        assertEquals(names.sorted(), expected.keys.sorted())
    }

    @ParameterizedTest
    @MethodSource("cases")
    fun `a corpus gzip case reads as KeePass 2 reads it`(name: String) {
        val payload = KdbxToolkit.payload(Corpus.all.single { it.name == name }.bytes, key)
        val limit = 16 shl 20
        when (val e = expected.getValue(name)) {
            is Expect.Content -> {
                val r = GzipReader.inflate(payload, 0, payload.size, limit)
                assertEquals(e.ending, r.ending)
                assertContentEquals(e.content(base), r.bytes.copyOf(r.size))
            }
            Expect.Prefix -> {
                val r = GzipReader.inflate(payload, 0, payload.size, limit)
                assertEquals(Ending.INPUT_ENDED, r.ending)
                assertTrue(r.size < base.size)
                assertContentEquals(base.copyOf(r.size), r.bytes.copyOf(r.size))
            }
            is Expect.Fault -> assertEquals(e.fault, assertIs<KdbxException.CompressedData>(runCatching { GzipReader.inflate(payload, 0, payload.size, limit) }.exceptionOrNull()).fault)
            Expect.TooLarge -> assertEquals(limit, assertIs<KdbxException.InflatedTooLarge>(runCatching { GzipReader.inflate(payload, 0, payload.size, limit) }.exceptionOrNull()).limit)
        }
    }

    @ParameterizedTest
    @MethodSource("gzipFixtures")
    fun `each gzip fixture's payload inflates to its content`(name: String) {
        val fixture = Fixtures.named(name)
        val file = Fixtures.file(fixture)
        val key = KdbxToolkit.Key(TestFiles.password(fixture.mode), TestFiles.keyFilePart(file))
        val kdf = KdbxToolkit.effective(KdbxToolkit.split(file.bytes).header).kdf
        val payload = KdbxToolkit.payload(file.bytes, KdbxToolkit.derive(kdf, key))
        val r = GzipReader.inflate(payload, 0, payload.size, 64 shl 20)
        assertEquals(Ending.TRAILER_CHECKED, r.ending)
        assertContentEquals(Gzip.decompress(payload), r.bytes.copyOf(r.size))
    }

    companion object {
        private sealed interface Expect {
            data class Content(val ending: Ending, val content: (ByteArray) -> ByteArray = { it }) : Expect
            data object Prefix : Expect
            data class Fault(val fault: KdbxException.Fault) : Expect
            data object TooLarge : Expect
        }

        private val expected: Map<String, Expect> = mapOf(
            "gzip-two-members-content-split" to Expect.Content(Ending.TRAILER_CHECKED) { it.copyOf(it.size / 2) },
            "gzip-second-member-non-empty" to Expect.Content(Ending.TRAILER_CHECKED),
            "gzip-second-member-empty" to Expect.Content(Ending.TRAILER_CHECKED),
            "gzip-data-after-member" to Expect.Content(Ending.TRAILER_CHECKED),
            "gzip-crc-wrong" to Expect.Fault(KdbxException.Fault.CRC),
            "gzip-isize-wrong" to Expect.Fault(KdbxException.Fault.ISIZE),
            "gzip-trailer-missing" to Expect.Content(Ending.TRAILER_INCOMPLETE),
            "gzip-trailer-half" to Expect.Content(Ending.TRAILER_INCOMPLETE),
            "gzip-cut-inside-member" to Expect.Prefix,
            "compression-gzip-with-plain-content" to Expect.Fault(KdbxException.Fault.ZLIB_HEADER),
            "gzip-bomb-512mib" to Expect.TooLarge,
            // A zlib stream, which .NET's GZipStream on Windows accepts (window bits 47).
            "gzip-flag-zlib-content" to Expect.Content(Ending.TRAILER_CHECKED),
        )

        @JvmStatic
        fun cases(): List<String> = expected.keys.toList()

        /**
         * Every KDBX 4 fixture with gzip compression except the Argon2 version 0x12 one, whose key
         * no KDF here derives the way its writer did.
         */
        @JvmStatic
        fun gzipFixtures(): List<String> = Fixtures.kdbx4.map { it.name }
            .filter { it != "keepass2-compression-none.kdbx" && it != "keepass2-argon2-version-0x12.kdbx" }
    }
}
