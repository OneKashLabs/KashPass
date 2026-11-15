package org.onekash.kashpass.vault.header

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/**
 * The strict outer-header parser whose KDF settings app versions before KashPass's own container
 * stored as KDF baselines. It is the reference for
 * [org.onekash.kashpass.vault.open.BaselineCompatibilityTest]: every baseline it produced must
 * compare equal to the settings KashPass's own header reader builds. It refuses a repeated field
 * or dictionary key, a negative field length, KDBX 3 fields and unknown dictionary types as
 * damaged. [KdbxHeaderParserTest] pins each rule.
 */
object KdbxHeaderParser {

    private const val SIGNATURE_BASE = 0x9AA2D903.toInt()
    private const val SIGNATURE_KDBX = 0xB54BFB67.toInt()
    private const val SIGNATURE_KEEPASS_1 = 0xB54BFB65.toInt()
    private const val SIGNATURE_KDBX_PRE_RELEASE = 0xB54BFB66.toInt()

    private const val FIELD_END = 0
    private const val FIELD_CIPHER = 2
    private const val FIELD_COMPRESSION = 3
    private const val FIELD_MASTER_SEED = 4
    private const val FIELD_IV = 7
    private const val FIELD_KDF = 11
    private const val FIELD_PUBLIC_CUSTOM_DATA = 12

    // Fields KDBX 4 defines. The KDBX 3 ones (5, 6, 8, 9, 10) are refused: a KDBX 4 writer never
    // writes them.
    private val KDBX4_FIELDS = setOf(0, 1, 2, 3, 4, 7, 11, 12)

    private const val TYPE_END = 0x00
    private const val TYPE_UINT32 = 0x04
    private const val TYPE_UINT64 = 0x05
    private const val TYPE_BOOL = 0x08
    private const val TYPE_INT32 = 0x0C
    private const val TYPE_INT64 = 0x0D
    private const val TYPE_STRING = 0x18
    private const val TYPE_BYTES = 0x42
    private val FIXED_SIZE = mapOf(TYPE_UINT32 to 4, TYPE_UINT64 to 8, TYPE_BOOL to 1, TYPE_INT32 to 4, TYPE_INT64 to 8)
    private val KNOWN_TYPES = FIXED_SIZE.keys + setOf(TYPE_STRING, TYPE_BYTES)

    private const val CIPHER_AES_256 = "31c1f2e6-bf71-4350-be58-05216afc5aff"
    private const val CIPHER_CHACHA20 = "d6038a2b-8b6f-4cb5-a524-339a31dbb59a"
    private const val KDF_AES = "c9d9f39a-628a-4460-bf74-0d08c18a4fea"
    private const val KDF_ARGON2D = "ef636ddf-8c29-444b-91f7-a9a403e30a0c"
    private const val KDF_ARGON2ID = "9e298b19-56db-4773-b23d-fc3ec6f0a1e6"

    /** Parses [bytes] (the whole file or at least its header); never throws. */
    fun parse(bytes: ByteArray): HeaderResult = try {
        parseOrThrow(bytes)
    } catch (e: DamagedException) {
        HeaderResult.Damaged(e.reason)
    }

    private fun parseOrThrow(bytes: ByteArray): HeaderResult {
        val r = Reader(ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN))
        if (bytes.size < 4 || r.int() != SIGNATURE_BASE) damaged(DamageReason.NOT_A_KEEPASS_FILE)
        when (r.int()) {
            SIGNATURE_KDBX -> Unit
            SIGNATURE_KEEPASS_1 -> return HeaderResult.Unsupported(UnsupportedReason.FormatVersion(1, 0))
            SIGNATURE_KDBX_PRE_RELEASE -> return HeaderResult.Unsupported(UnsupportedReason.FormatVersion(2, 0))
            else -> damaged(DamageReason.NOT_A_KEEPASS_FILE)
        }
        val minor = r.u16()
        val major = r.u16()
        // KDBX 3 uses 2-byte field lengths, so nothing past the version is read for other majors.
        if (major != 4) return HeaderResult.Unsupported(UnsupportedReason.FormatVersion(major, minor))

        val fields = mutableMapOf<Int, ByteArray>()
        while (true) {
            val id = r.u8()
            val length = r.int()
            if (length < 0) damaged(DamageReason.INVALID_LENGTH)
            val data = r.bytes(length)
            if (id !in KDBX4_FIELDS) damaged(DamageReason.UNKNOWN_FIELD)
            if (fields.put(id, data) != null) damaged(DamageReason.DUPLICATE_FIELD)
            if (id == FIELD_END) break
        }

        val cipherBytes = fields[FIELD_CIPHER] ?: damaged(DamageReason.MISSING_FIELD)
        val compression = fields[FIELD_COMPRESSION] ?: damaged(DamageReason.MISSING_FIELD)
        val kdfBytes = fields[FIELD_KDF] ?: damaged(DamageReason.MISSING_FIELD)
        if (FIELD_MASTER_SEED !in fields || FIELD_IV !in fields) damaged(DamageReason.MISSING_FIELD)

        if (cipherBytes.size != 16 || compression.size != 4) damaged(DamageReason.INVALID_LENGTH)
        val compressionId = ByteBuffer.wrap(compression).order(ByteOrder.LITTLE_ENDIAN).int
        if (compressionId != 0 && compressionId != 1) damaged(DamageReason.INVALID_COMPRESSION)
        fields[FIELD_PUBLIC_CUSTOM_DATA]?.let { readDictionary(it) }
        val kdfEntries = readDictionary(kdfBytes)

        val cipher = when (val id = uuid(cipherBytes)) {
            CIPHER_AES_256 -> KdbxCipher.AES_256
            CIPHER_CHACHA20 -> KdbxCipher.CHACHA20
            else -> return HeaderResult.Unsupported(UnsupportedReason.Cipher(id))
        }
        val kdf = when (val result = kdf(kdfEntries)) {
            is KdfOrUnsupported.Settings -> result.settings
            is KdfOrUnsupported.Unsupported -> return HeaderResult.Unsupported(UnsupportedReason.Kdf(result.uuid))
        }
        return HeaderResult.Valid(KdbxHeader(major, minor, cipher, kdf))
    }

    private sealed interface KdfOrUnsupported {
        data class Settings(val settings: KdfSettings) : KdfOrUnsupported
        data class Unsupported(val uuid: String) : KdfOrUnsupported
    }

    private fun kdf(entries: Map<String, Value>): KdfOrUnsupported {
        val uuidBytes = entries.bytes("\$UUID")
        if (uuidBytes.size != 16) damaged(DamageReason.WRONG_VALUE_TYPE)
        val settings = when (val uuid = uuid(uuidBytes)) {
            KDF_AES -> {
                entries.bytes("S")
                KdfSettings.AesKdf(entries.uint64("R"))
            }
            KDF_ARGON2D, KDF_ARGON2ID -> {
                entries.bytes("S")
                entries.optionalBytes("K")
                entries.optionalBytes("A")
                KdfSettings.Argon2(
                    variant = if (uuid == KDF_ARGON2D) Argon2Variant.ARGON2D else Argon2Variant.ARGON2ID,
                    iterations = entries.uint64("I"),
                    memoryBytes = entries.uint64("M"),
                    parallelism = entries.uint32("P"),
                    version = entries.uint32("V"),
                )
            }
            else -> return KdfOrUnsupported.Unsupported(uuid)
        }
        return KdfOrUnsupported.Settings(settings)
    }

    private class Value(val type: Int, val data: ByteArray)

    /**
     * Reads a VariantDictionary, rejecting repeated keys (compared after UTF-8 decoding), unknown
     * types, wrong fixed sizes, negative lengths and bytes after the terminator.
     */
    private fun readDictionary(bytes: ByteArray): Map<String, Value> {
        val r = Reader(ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN))
        if (r.u16() and 0xFF00 != 0x0100) damaged(DamageReason.INVALID_DICTIONARY)
        val entries = mutableMapOf<String, Value>()
        while (true) {
            val type = r.u8()
            if (type == TYPE_END) break
            if (type !in KNOWN_TYPES) damaged(DamageReason.UNKNOWN_VALUE_TYPE)
            val keyLength = r.int()
            if (keyLength <= 0) damaged(DamageReason.INVALID_LENGTH)
            val key = r.bytes(keyLength).toString(Charsets.UTF_8)
            val valueLength = r.int()
            if (valueLength < 0) damaged(DamageReason.INVALID_LENGTH)
            FIXED_SIZE[type]?.let { if (valueLength != it) damaged(DamageReason.INVALID_LENGTH) }
            val value = r.bytes(valueLength)
            if (entries.put(key, Value(type, value)) != null) damaged(DamageReason.DUPLICATE_KEY)
        }
        if (r.remaining() != 0) damaged(DamageReason.TRAILING_BYTES)
        return entries
    }

    private fun Map<String, Value>.typed(key: String, type: Int): ByteArray {
        val value = this[key] ?: damaged(DamageReason.MISSING_FIELD)
        if (value.type != type) damaged(DamageReason.WRONG_VALUE_TYPE)
        return value.data
    }

    private fun Map<String, Value>.bytes(key: String) = typed(key, TYPE_BYTES)

    private fun Map<String, Value>.optionalBytes(key: String) {
        if (containsKey(key)) typed(key, TYPE_BYTES)
    }

    private fun Map<String, Value>.uint64(key: String): ULong =
        ByteBuffer.wrap(typed(key, TYPE_UINT64)).order(ByteOrder.LITTLE_ENDIAN).long.toULong()

    private fun Map<String, Value>.uint32(key: String): UInt =
        ByteBuffer.wrap(typed(key, TYPE_UINT32)).order(ByteOrder.LITTLE_ENDIAN).int.toUInt()

    private fun uuid(bytes: ByteArray): String {
        val buf = ByteBuffer.wrap(bytes)
        return UUID(buf.long, buf.long).toString()
    }

    private class Reader(private val buf: ByteBuffer) {
        fun remaining() = buf.remaining()
        fun u8(): Int = need(1).get().toInt() and 0xFF
        fun u16(): Int = need(2).short.toInt() and 0xFFFF
        fun int(): Int = need(4).int
        // Checks the length before allocating, so a lying length can't exhaust memory.
        fun bytes(n: Int): ByteArray {
            need(n)
            return ByteArray(n).also { buf.get(it) }
        }
        private fun need(n: Int): ByteBuffer {
            if (buf.remaining() < n) damaged(DamageReason.TRUNCATED)
            return buf
        }
    }

    private class DamagedException(val reason: DamageReason) : Exception(null, null, false, false)

    private fun damaged(reason: DamageReason): Nothing = throw DamagedException(reason)
}

/** Outer ciphers [KdbxHeaderParser] accepts. */
enum class KdbxCipher { AES_256, CHACHA20 }

/** The parts of a KDBX 4 outer header [KdbxHeaderParser] returns. */
data class KdbxHeader(
    val majorVersion: Int,
    val minorVersion: Int,
    val cipher: KdbxCipher,
    val kdf: KdfSettings,
)

/** Outcome of [KdbxHeaderParser.parse]. */
sealed interface HeaderResult {

    /** A KDBX 4 header that passed every check. */
    data class Valid(val header: KdbxHeader) : HeaderResult

    /** A well-formed file using a format or algorithm the parser does not accept. */
    data class Unsupported(val reason: UnsupportedReason) : HeaderResult

    /** Bytes that are not a KDBX file, are cut short, or are ambiguous to read. */
    data class Damaged(val reason: DamageReason) : HeaderResult
}
