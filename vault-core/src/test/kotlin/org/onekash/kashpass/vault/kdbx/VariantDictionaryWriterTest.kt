package org.onekash.kashpass.vault.kdbx

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.header.HeaderResult
import org.onekash.kashpass.vault.header.KdbxHeaderParser
import org.onekash.kashpass.vault.kdbx.VariantDictionaryWriter.Entry
import org.onekash.kashpass.vault.kdbx.VariantDictionaryWriter.Value
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawEntry
import org.onekash.kashpass.vault.testing.RawKdbx

class VariantDictionaryWriterTest {

    private fun entry(raw: RawEntry): Entry = Entry(
        raw.key,
        when (raw.type) {
            RawDictionary.UINT32 -> Value.UInt32(Bytes.readLe32(raw.value, 0).toUInt())
            RawDictionary.UINT64 -> Value.UInt64(Bytes.readLe64(raw.value, 0).toULong())
            RawDictionary.BOOL -> Value.Bool(raw.value[0].toInt() != 0)
            RawDictionary.INT32 -> Value.Int32(Bytes.readLe32(raw.value, 0))
            RawDictionary.INT64 -> Value.Int64(Bytes.readLe64(raw.value, 0))
            RawDictionary.STRING -> Value.Text(raw.value.decodeToString())
            RawDictionary.BYTES -> Value.Binary(raw.value)
            else -> error("type ${raw.type}")
        },
    )

    @ParameterizedTest
    @MethodSource("fixtures")
    fun `each fixture's KDF dictionary is written byte for byte and read back by the header parser`(name: String) {
        val header = RawKdbx.parse(Fixtures.bytes(name))
        val stored = header.field(RawKdbx.KDF_PARAMETERS)
        val written = VariantDictionaryWriter.write(RawDictionary.parse(stored).entries.map(::entry))
        assertContentEquals(stored, written, name)

        val original = assertIs<HeaderResult.Valid>(KdbxHeaderParser.parse(header.toBytes()))
        val reread = assertIs<HeaderResult.Valid>(KdbxHeaderParser.parse(header.withField(RawKdbx.KDF_PARAMETERS, written).toBytes()))
        assertEquals(original.header.kdf, reread.header.kdf)
    }

    @Test
    fun `KeePass 2's entry order is the fixtures' order`() {
        val names = { file: String -> RawDictionary.parse(RawKdbx.parse(Fixtures.bytes(file)).field(RawKdbx.KDF_PARAMETERS)).entries.map { it.key } }
        assertEquals(listOf("\$UUID", "R", "S"), names("keepass2-default-aeskdf.kdbx"))
        assertEquals(listOf("\$UUID", "V", "I", "M", "P", "S"), names("keepass2-argon2id.kdbx"))
    }

    @Test
    fun `every value type is written as the test toolkit's RawDictionary writes it`() {
        val raw = listOf(
            RawEntry(RawDictionary.UINT32, "u32", byteArrayOf(1, 0, 0, -128)),
            RawEntry(RawDictionary.UINT64, "u64", byteArrayOf(-1, -1, -1, -1, -1, -1, -1, -1)),
            RawEntry(RawDictionary.BOOL, "bool", byteArrayOf(1)),
            RawEntry(RawDictionary.INT32, "i32", byteArrayOf(-2, -1, -1, -1)),
            RawEntry(RawDictionary.INT64, "i64", byteArrayOf(5, 0, 0, 0, 0, 0, 0, -128)),
            RawEntry(RawDictionary.STRING, "text", "Grüße".encodeToByteArray()),
            RawEntry(RawDictionary.BYTES, "bytes", byteArrayOf(9, 8, 7)),
            RawEntry(RawDictionary.BYTES, "empty", ByteArray(0)),
            RawEntry(RawDictionary.STRING, "naïve name", "x".encodeToByteArray()),
        )
        assertContentEquals(RawDictionary(0x0100, raw).toBytes(), VariantDictionaryWriter.write(raw.map(::entry)))
    }

    @Test
    fun `an entry with an empty name is skipped and an empty dictionary is version and terminator`() {
        val written = VariantDictionaryWriter.write(listOf(Entry("", Value.Bool(true)), Entry("a", Value.Bool(false))))
        assertContentEquals(RawDictionary(0x0100, listOf(RawEntry(RawDictionary.BOOL, "a", byteArrayOf(0)))).toBytes(), written)
        assertContentEquals(byteArrayOf(0, 1, 0), VariantDictionaryWriter.write(emptyList()))
    }

    @Test
    fun `raw entries are written as given, with the bytes write gives for typed ones`() {
        val notUtf8 = byteArrayOf(0xC3.toByte(), 0x28)
        val raw = listOf(
            VariantDictionaryWriter.RawEntry(RawDictionary.UINT32, notUtf8, byteArrayOf(1, 0, 0, 0)),
            VariantDictionaryWriter.RawEntry(RawDictionary.STRING, "s".encodeToByteArray(), byteArrayOf(0x61, 0xFF.toByte())),
            VariantDictionaryWriter.RawEntry(RawDictionary.BOOL, ByteArray(0), byteArrayOf(1)),
            VariantDictionaryWriter.RawEntry(RawDictionary.BYTES, "b".encodeToByteArray(), ByteArray(0)),
        )
        val expected = RawDictionary(
            0x0100,
            listOf(
                RawEntry(RawDictionary.UINT32, "", byteArrayOf(1, 0, 0, 0), rawName = notUtf8),
                RawEntry(RawDictionary.STRING, "s", byteArrayOf(0x61, 0xFF.toByte())),
                RawEntry(RawDictionary.BYTES, "b", ByteArray(0)),
            ),
        )
        assertContentEquals(expected.toBytes(), VariantDictionaryWriter.writeRaw(raw))

        val typed = listOf(Entry("u", Value.UInt64(7UL)), Entry("t", Value.Text("Grüße")))
        val same = listOf(
            VariantDictionaryWriter.RawEntry(RawDictionary.UINT64, "u".encodeToByteArray(), ByteArray(8).also { Bytes.writeLe64(it, 0, 7L) }),
            VariantDictionaryWriter.RawEntry(RawDictionary.STRING, "t".encodeToByteArray(), "Grüße".encodeToByteArray()),
        )
        assertContentEquals(VariantDictionaryWriter.write(typed), VariantDictionaryWriter.writeRaw(same))
    }

    @Test
    fun `a dictionary too large for an array is refused before the output is allocated`() {
        // Eight entries share one 256 MiB array: 2 GiB of values in total.
        val big = ByteArray(1 shl 28)
        val result = runCatching { VariantDictionaryWriter.write(List(8) { Entry("e$it", Value.Binary(big)) }) }
        assertTrue(result.exceptionOrNull() is KdbxException.DictionaryTooLarge, result.toString())
    }

    companion object {
        @JvmStatic
        fun fixtures(): List<String> = Fixtures.kdbx4.map { it.name }
    }
}
