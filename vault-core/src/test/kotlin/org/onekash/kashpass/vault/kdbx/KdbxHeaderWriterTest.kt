package org.onekash.kashpass.vault.kdbx

import java.security.SecureRandom
import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawEntry
import org.onekash.kashpass.vault.testing.RawField
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.le32
import org.onekash.kashpass.vault.testing.le64
import org.onekash.kashpass.vault.testing.uuidBytes

class KdbxHeaderWriterTest {

    private val weak = RawKdbx.parse(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"))
    private val secretAndData = RawKdbx.parse(Fixtures.bytes("keepass2-argon2-secret-and-data.kdbx"))
    private val signature = le32(0x9AA2D903.toInt()) + le32(0xB54BFB67.toInt())
    private val keepass2Fields = listOf(2, 3, 4, 11, 7, 0)
    private val endValue = byteArrayOf(0x0D, 0x0A, 0x0D, 0x0A)
    private val uuid = "\$UUID"

    private fun parsed(w: KdbxHeaderWriter.Write.Written) = RawKdbx.parse(w.bytes)

    private fun salt(raw: RawKdbx): ByteArray = raw.kdf().entries.single { it.key == "S" }.value

    private fun names(raw: RawKdbx): List<String> = raw.kdf().entries.map { it.key }

    private fun value(raw: RawKdbx, name: String): ByteArray = raw.kdf().entries.single { it.key == name }.value

    // The KDF dictionary's entry names as stored, read without decoding them.
    private fun nameBytes(header: OuterHeader): List<List<Byte>> = header.kdfEntries!!.all().map { it.first.toList() }

    @ParameterizedTest
    @MethodSource("fixtures")
    fun `each fixture's header is written as KeePass 2 wrote it, with fresh random values`(name: String) {
        val raw = RawKdbx.parse(Fixtures.bytes(name))
        val opened = openedHeader(raw)
        val written = writtenHeader(raw, raw.minor)
        val out = parsed(written)
        val expected = raw.withField(RawKdbx.MASTER_SEED, out.field(RawKdbx.MASTER_SEED))
            .withField(RawKdbx.ENCRYPTION_IV, out.field(RawKdbx.ENCRYPTION_IV))
            .withKdf { it.with("S", RawDictionary.BYTES, salt(out)) }
        assertContentEquals(expected.headerBytes(), written.bytes, name)
        assertContentEquals(signature, out.signature, name)
        // Public custom data (field 12) follows the encryption IV, only when there is some.
        val withPublic = raw.fields.any { it.id == RawKdbx.PUBLIC_CUSTOM_DATA }
        assertEquals(if (withPublic) keepass2Fields.dropLast(1) + RawKdbx.PUBLIC_CUSTOM_DATA + 0 else keepass2Fields, out.fields.map { it.id }, name)
        assertContentEquals(endValue, out.field(RawKdbx.END_OF_HEADER), name)
        assertEquals(32, out.field(RawKdbx.MASTER_SEED).size, name)
        assertEquals(if (opened.cipher == OuterCipher.CHACHA20) 12 else 16, out.field(RawKdbx.ENCRYPTION_IV).size, name)
        assertEquals(32, salt(out).size, name)
        assertFalse(salt(out).contentEquals(salt(raw)), name)

        val back = written.header
        assertEquals(written.bytes.size, back.length, name)
        assertEquals(KdbxSignature.NORMAL, back.signature, name)
        assertEquals(opened.cipher, back.cipher, name)
        assertEquals(opened.compression, back.compression, name)
        if (withPublic) {
            assertEquals(
                opened.publicCustomData!!.all().map { (k, e) -> k.decodeToString() to (e.type to e.value.toList()) },
                back.publicCustomData!!.all().map { (k, e) -> k.decodeToString() to (e.type to e.value.toList()) },
                name,
            )
        } else {
            assertNull(back.publicCustomData, name)
        }
        assertKdfEquals(opened.kdf, back.kdf, withSalt = false, name)
        assertContentEquals(salt(out), saltOf(back.kdf), name)
        assertContentEquals(out.field(RawKdbx.MASTER_SEED), back.masterSeed, name)
        assertContentEquals(out.field(RawKdbx.ENCRYPTION_IV), back.iv, name)
    }

    @Test
    fun `a file opened with the pre-release signature is written with the normal one`() {
        val preRelease = weak.copy(signature = le32(0x9AA2D903.toInt()) + le32(0xB54BFB66.toInt()))
        assertEquals(KdbxSignature.PRE_RELEASE, openedHeader(preRelease).signature)
        val written = writtenHeader(preRelease)
        assertContentEquals(signature, written.bytes.copyOf(8))
        assertEquals(KdbxSignature.NORMAL, written.header.signature)
    }

    @Test
    fun `the version is 4 and the minor the caller gives`() {
        for (minor in listOf(0, 1, 2, 0xFFFF)) {
            val out = parsed(writtenHeader(weak, minor))
            assertEquals(4, out.major)
            assertEquals(minor, out.minor)
        }
        val settings = SaveSettings.from(openedHeader(weak))
        for (minor in listOf(-1, 0x10000)) {
            val e = assertThrows<KdbxException.InvalidLength> { KdbxHeaderWriter.write(settings, minor, SecureRandom()) }
            assertEquals(KdbxException.Field.RANGE, e.field)
        }
    }

    @Test
    fun `fields KeePass 2 does not write at KDBX 4 are dropped and missing ones written`() {
        val legacy = weak.insertBefore(RawKdbx.KDF_PARAMETERS, RawField(RawKdbx.TRANSFORM_ROUNDS, le64(7000)))
            .plusField(RawField(RawKdbx.COMMENT, "comment".encodeToByteArray()))
            .plusField(RawField(RawKdbx.PROTECTED_STREAM_KEY, ByteArray(32) { 1 }))
            .plusField(RawField(RawKdbx.STREAM_START_BYTES, ByteArray(32) { 2 }))
            .plusField(RawField(RawKdbx.INNER_RANDOM_STREAM_ID, le32(3)))
            .plusField(RawField(13, le32(7)))
            .plusField(RawField(RawKdbx.ENCRYPTION_IV, weak.field(RawKdbx.ENCRYPTION_IV)))
            .withField(RawKdbx.END_OF_HEADER, Random(1).nextBytes(100))
        val written = writtenHeader(legacy)
        val out = parsed(written)
        assertEquals(keepass2Fields, out.fields.map { it.id })
        assertContentEquals(endValue, out.field(RawKdbx.END_OF_HEADER))
        assertNull(written.header.innerStreamKeyFallback)
        assertNull(written.header.innerStreamIdFallback)

        // The defaults for a missing cipher or compression field are written out.
        val bare = parsed(writtenHeader(weak.withoutField(RawKdbx.CIPHER_ID).withoutField(RawKdbx.COMPRESSION)))
        assertEquals(keepass2Fields, bare.fields.map { it.id })
        assertContentEquals(uuidBytes("31c1f2e6-bf71-4350-be58-05216afc5aff"), bare.field(RawKdbx.CIPHER_ID))
        assertContentEquals(le32(1), bare.field(RawKdbx.COMPRESSION))
    }

    @Test
    fun `the KDF dictionary is UUID first, then the file's other entries in file order`() {
        val reordered = weak.withKdf { it.copy(entries = it.entries.reversed()) }
        assertEquals(listOf("S", "R", uuid), names(reordered))
        val out = parsed(writtenHeader(reordered))
        assertEquals(listOf(uuid, "S", "R"), names(out))
        assertContentEquals(value(weak, "R"), value(out, "R"))
        assertContentEquals(value(weak, uuid), value(out, uuid))
    }

    @Test
    fun `unknown entries and K and A are kept in place, only the salt changes`() {
        val extra = listOf(
            RawEntry(RawDictionary.UINT32, "X", le32(7)),
            RawEntry(RawDictionary.STRING, "note", "Grüße".encodeToByteArray()),
            RawEntry(RawDictionary.INT64, "i64", le64(-7)),
        )
        val raw = secretAndData.withKdf { it.copy(entries = it.entries + extra) }
        val out = parsed(writtenHeader(raw))
        assertEquals(listOf(uuid, "V", "I", "M", "P", "K", "A", "S", "X", "note", "i64"), names(out))
        val before = raw.kdf().entries
        val after = out.kdf().entries
        for ((b, a) in before.zip(after)) {
            assertEquals(b.type, a.type, b.key)
            if (b.key == "S") assertFalse(b.value.contentEquals(a.value)) else assertContentEquals(b.value, a.value, b.key)
        }
    }

    @Test
    fun `the KDF dictionary is re-serialized as KeePass 2 does`() {
        val seed = salt(weak)
        val nonUtf8Name = byteArrayOf(0xC3.toByte(), 0x28)
        val dictionary = RawDictionary(
            0x01FF,
            listOf(
                RawEntry(RawDictionary.UINT64, "R", le64(7000)),
                RawEntry(RawDictionary.BOOL, "B", byteArrayOf(2)),
                RawEntry(RawDictionary.UINT32, "", le32(1)),
                RawEntry(RawDictionary.BYTES, uuid, value(weak, uuid)),
                RawEntry(RawDictionary.BYTES, "S", seed),
                RawEntry(RawDictionary.UINT32, "", le32(1), rawName = nonUtf8Name),
                RawEntry(RawDictionary.STRING, "T", byteArrayOf(0x61, 0xFF.toByte())),
                RawEntry(RawDictionary.UINT64, "R", le64(6000)),
            ),
            trailing = byteArrayOf(1, 2, 3),
        )
        val written = writtenHeader(weak.withKdf { dictionary })
        val out = parsed(written)
        val replacement = byteArrayOf(0xEF.toByte(), 0xBF.toByte(), 0xBD.toByte())
        val expected = RawDictionary(
            0x0100,
            listOf(
                RawEntry(RawDictionary.BYTES, uuid, value(weak, uuid)),
                RawEntry(RawDictionary.UINT64, "R", le64(6000)),
                RawEntry(RawDictionary.BOOL, "B", byteArrayOf(1)),
                RawEntry(RawDictionary.BYTES, "S", salt(out)),
                RawEntry(RawDictionary.UINT32, "", le32(1), rawName = replacement + byteArrayOf(0x28)),
                RawEntry(RawDictionary.STRING, "T", byteArrayOf(0x61) + replacement),
            ),
        )
        assertContentEquals(expected.toBytes(), out.field(RawKdbx.KDF_PARAMETERS))
        assertEquals(6000UL, assertIs<KdfParameters.Aes>(written.kdf).rounds)
    }

    @Test
    fun `fields 5 and 6 fold into AES-KDF and are written as UUID, R, S`() {
        val seed = salt(weak)
        val aes = uuidBytes("c9d9f39a-628a-4460-bf74-0d08c18a4fea")
        val noKdf = weak.withoutField(RawKdbx.KDF_PARAMETERS)
        val argon = RawKdbx.parse(Fixtures.bytes("keepass2-argon2id.kdbx"))
        val cases = mapOf(
            "seed then rounds" to (noKdf.plusField(RawField(RawKdbx.TRANSFORM_SEED, seed)).plusField(RawField(RawKdbx.TRANSFORM_ROUNDS, le64(6000))) to 6000L),
            "rounds then seed" to (noKdf.plusField(RawField(RawKdbx.TRANSFORM_ROUNDS, le64(6000))).plusField(RawField(RawKdbx.TRANSFORM_SEED, seed)) to 6000L),
            "seed alone" to (noKdf.plusField(RawField(RawKdbx.TRANSFORM_SEED, seed)) to 600_000L),
            "after Argon2" to (argon.plusField(RawField(RawKdbx.TRANSFORM_SEED, seed)).plusField(RawField(RawKdbx.TRANSFORM_ROUNDS, le64(6000))) to 6000L),
            "rounds after AES-KDF" to (weak.plusField(RawField(RawKdbx.TRANSFORM_ROUNDS, le64(9))) to 9L),
        )
        for ((label, case) in cases) {
            val (raw, rounds) = case
            val out = parsed(writtenHeader(raw))
            assertEquals(keepass2Fields, out.fields.map { it.id }, label)
            assertEquals(listOf(uuid, "R", "S"), names(out), label)
            assertContentEquals(aes, value(out, uuid), label)
            assertContentEquals(le64(rounds), value(out, "R"), label)
            assertFalse(salt(out).contentEquals(seed), label)
        }
    }

    @Test
    fun `public custom data is written only with at least one item, re-serialized as KeePass 2 does`() {
        val everyType = listOf(
            RawEntry(RawDictionary.UINT32, "KashPass_UInt32", le32(7)),
            RawEntry(RawDictionary.UINT64, "KashPass_UInt64", le64(7L)),
            RawEntry(RawDictionary.BOOL, "KashPass_Bool", byteArrayOf(1)),
            RawEntry(RawDictionary.INT32, "KashPass_Int32", le32(-7)),
            RawEntry(RawDictionary.INT64, "KashPass_Int64", le64(-7L)),
            RawEntry(RawDictionary.STRING, "KashPass_String", "text".encodeToByteArray()),
            RawEntry(RawDictionary.BYTES, "KashPass_Bytes", byteArrayOf(1, 2, 3)),
        )
        val custom = RawDictionary(0x0100, everyType).toBytes()
        val written = writtenHeader(weak.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, custom)))
        val out = parsed(written)
        assertEquals(listOf(2, 3, 4, 11, 7, 12, 0), out.fields.map { it.id })
        assertContentEquals(custom, out.field(RawKdbx.PUBLIC_CUSTOM_DATA))
        assertEquals(everyType.map { it.key }, written.header.publicCustomData!!.all().map { it.first.decodeToString() })

        val messy = RawDictionary(
            0x0105,
            listOf(
                RawEntry(RawDictionary.STRING, "a", "first".encodeToByteArray()),
                RawEntry(RawDictionary.BOOL, "flag", byteArrayOf(5)),
                RawEntry(RawDictionary.UINT32, "", le32(1)),
                RawEntry(RawDictionary.INT32, "a", le32(3)),
            ),
            trailing = byteArrayOf(9, 9),
        )
        val tidy = RawDictionary(0x0100, listOf(RawEntry(RawDictionary.INT32, "a", le32(3)), RawEntry(RawDictionary.BOOL, "flag", byteArrayOf(1))))
        val messyOut = parsed(writtenHeader(weak.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, messy.toBytes()))))
        assertContentEquals(tidy.toBytes(), messyOut.field(RawKdbx.PUBLIC_CUSTOM_DATA))

        val noItems = RawDictionary(0x0100, listOf(RawEntry(RawDictionary.UINT32, "", le32(1)))).toBytes()
        val none = writtenHeader(weak.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, noItems)))
        assertEquals(keepass2Fields, parsed(none).fields.map { it.id })
        assertNull(none.header.publicCustomData)
    }

    @Test
    fun `a header not read from a file gets the dictionary KeePass 2 builds for its KDF`() {
        fun header(kdf: KdfParameters) = OuterHeader(
            KdbxSignature.NORMAL, 4, 0, OuterCipher.CHACHA20, Compression.NONE, ByteArray(32), ByteArray(12), kdf, null, null, null, 0,
        )
        val aes = KdfParameters.Aes(6000UL, ByteArray(32) { 3 })
        val argon = KdfParameters.Argon2(Argon2Type.ARGON2ID, ByteArray(16) { 4 }, 2U, 1UL shl 20, 2UL, 0x13U, ByteArray(8) { 5 }, ByteArray(4) { 6 })
        for ((kdf, expected) in listOf(aes to listOf(uuid, "R", "S"), argon to listOf(uuid, "V", "I", "M", "P", "S", "K", "A"))) {
            val written = assertIs<KdbxHeaderWriter.Write.Written>(KdbxHeaderWriter.write(SaveSettings.from(header(kdf)), 0, SecureRandom()))
            val out = parsed(written)
            assertEquals(expected, names(out))
            assertKdfEquals(kdf, written.kdf, withSalt = false)
            assertEquals(32, saltOf(written.kdf).size)
            assertEquals(OuterCipher.CHACHA20, written.header.cipher)
            assertEquals(Compression.NONE, written.header.compression)
            assertEquals(12, written.header.iv.size)
        }
    }

    @Test
    fun `the settings keep no salt or seed of the opened file`() {
        for (raw in listOf(weak, secretAndData)) {
            val settings = SaveSettings.from(openedHeader(raw))
            val s = settings.kdfEntries.single { it.name.contentEquals("S".encodeToByteArray()) }
            assertEquals(0, s.value.size)
            assertContentEquals("\$UUID".encodeToByteArray(), settings.kdfEntries.first().name)
            assertEquals(raw.minor, settings.openedMinor)
        }
    }

    @Test
    fun `a dictionary entry whose name is not UTF-8 is written with KeePass 2's replacement character`() {
        val raw = weak.withKdf { it.plus(RawEntry(RawDictionary.UINT32, "", le32(1), rawName = byteArrayOf(0xC3.toByte(), 0x28))) }
        val opened = nameBytes(openedHeader(raw))
        assertTrue(listOf(0xC3.toByte(), 0x28.toByte()) in opened)
        val written = nameBytes(writtenHeader(raw).header)
        assertEquals(listOf(0xEF.toByte(), 0xBF.toByte(), 0xBD.toByte(), 0x28.toByte()), written.last())
    }

    companion object {
        @JvmStatic
        fun fixtures(): List<String> = Fixtures.kdbx4.map { it.name }
    }
}
