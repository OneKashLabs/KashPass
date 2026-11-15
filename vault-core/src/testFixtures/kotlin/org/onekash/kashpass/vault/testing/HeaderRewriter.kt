package org.onekash.kashpass.vault.testing

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Rebuilds the outer header of a real KDBX 4 file with test-chosen changes, including ones a
 * well-formed writer never produces: repeated fields, repeated dictionary keys, unknown value
 * types, wrong lengths and trailing bytes.
 *
 * The header hash and HMAC are not recomputed, so a rewritten file never decrypts; the header
 * checks under test run before any key derivation and need neither. [KdbxToolkit] recomputes both
 * for tests that need a file that decrypts.
 */
data class RawKdbx(
    val signature: ByteArray,
    val minor: Int,
    val major: Int,
    val fields: List<RawField>,
    val rest: ByteArray,
) {
    /** Serializes the header fields followed by the untouched remainder of the file. */
    fun toBytes(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(signature)
        out.write(le16(minor))
        out.write(le16(major))
        for (field in fields) {
            out.write(field.id)
            out.write(le32(field.declaredLength))
            out.write(field.data)
        }
        out.write(rest)
        return out.toByteArray()
    }

    /**
     * Serializes as [toBytes] does with the header's SHA-256 (the first 32 bytes of [rest])
     * recomputed, so the file passes the unkeyed header check and fails at the header HMAC.
     */
    fun toBytesWithHeaderHash(): ByteArray {
        val header = headerBytes()
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest(header)
        return header + hash + rest.copyOfRange(32, rest.size)
    }

    /** Serializes the signature, version and header fields, without the remainder. */
    fun headerBytes(): ByteArray = copy(rest = ByteArray(0)).toBytes()

    /** Returns the data of the first field with [id]. */
    fun field(id: Int): ByteArray = fields.first { it.id == id }.data

    /** Replaces the data of the first field with [id]. */
    fun withField(id: Int, data: ByteArray): RawKdbx {
        val index = fields.indexOfFirst { it.id == id }
        return copy(fields = fields.toMutableList().also { it[index] = RawField(id, data) })
    }

    /** Inserts [field] before the end-of-header field. */
    fun plusField(field: RawField): RawKdbx {
        val end = fields.indexOfLast { it.id == END_OF_HEADER }
        return copy(fields = fields.take(end) + field + fields.drop(end))
    }

    /** Removes every field with [id]. */
    fun withoutField(id: Int): RawKdbx = copy(fields = fields.filterNot { it.id == id })

    /** Inserts [field] before the first field with [id]. */
    fun insertBefore(id: Int, field: RawField): RawKdbx {
        val at = fields.indexOfFirst { it.id == id }
        return copy(fields = fields.take(at) + field + fields.drop(at))
    }

    /** Gives the field at [index] the declared length [length], keeping its data. */
    fun withLength(index: Int, length: Int): RawKdbx =
        copy(fields = fields.mapIndexed { i, f -> if (i == index) f.copy(declaredLength = length) else f })

    /** Parses the KDF parameters dictionary. */
    fun kdf(): RawDictionary = RawDictionary.parse(field(KDF_PARAMETERS))

    /** Replaces the KDF parameters dictionary. */
    fun withKdf(transform: (RawDictionary) -> RawDictionary): RawKdbx =
        withField(KDF_PARAMETERS, transform(kdf()).toBytes())

    companion object {
        const val END_OF_HEADER = 0
        const val COMMENT = 1
        const val CIPHER_ID = 2
        const val COMPRESSION = 3
        const val MASTER_SEED = 4
        const val TRANSFORM_SEED = 5
        const val TRANSFORM_ROUNDS = 6
        const val ENCRYPTION_IV = 7
        const val PROTECTED_STREAM_KEY = 8
        const val STREAM_START_BYTES = 9
        const val INNER_RANDOM_STREAM_ID = 10
        const val KDF_PARAMETERS = 11
        const val PUBLIC_CUSTOM_DATA = 12

        /** Splits a well-formed KDBX 4 file into header fields and the rest. */
        fun parse(bytes: ByteArray): RawKdbx {
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val signature = ByteArray(8).also { buf.get(it) }
            val minor = buf.short.toInt() and 0xFFFF
            val major = buf.short.toInt() and 0xFFFF
            val fields = mutableListOf<RawField>()
            while (true) {
                val id = buf.get().toInt() and 0xFF
                val length = buf.int
                val data = ByteArray(length).also { buf.get(it) }
                fields += RawField(id, data)
                if (id == END_OF_HEADER) break
            }
            val rest = ByteArray(buf.remaining()).also { buf.get(it) }
            return RawKdbx(signature, minor, major, fields, rest)
        }
    }
}

/** One header field; a [declaredLength] unlike the data size models a lying length. */
data class RawField(val id: Int, val data: ByteArray, val declaredLength: Int = data.size)

/**
 * One VariantDictionary entry; [declaredLength] can differ from the size of [value]. [rawName]
 * replaces the UTF-8 bytes of [key] (for names that are not valid UTF-8), and [declaredNameLength]
 * can differ from the name's size.
 */
data class RawEntry(
    val type: Int,
    val key: String,
    val value: ByteArray,
    val declaredLength: Int = value.size,
    val rawName: ByteArray? = null,
    val declaredNameLength: Int? = null,
) {
    /** The name bytes as stored. */
    val nameBytes: ByteArray get() = rawName ?: key.toByteArray(Charsets.UTF_8)
}

/**
 * A KDBX VariantDictionary that keeps entry order, duplicates and trailing bytes as written;
 * [terminated] false leaves out the null terminator.
 */
data class RawDictionary(
    val version: Int,
    val entries: List<RawEntry>,
    val trailing: ByteArray = ByteArray(0),
    val terminated: Boolean = true,
) {
    /**
     * Serializes the version, the entries, the terminator (unless left out) and the trailing bytes.
     */
    fun toBytes(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(le16(version))
        for (entry in entries) {
            val name = entry.nameBytes
            out.write(entry.type)
            out.write(le32(entry.declaredNameLength ?: name.size))
            out.write(name)
            out.write(le32(entry.declaredLength))
            out.write(entry.value)
        }
        if (terminated) out.write(0)
        out.write(trailing)
        return out.toByteArray()
    }

    /** Replaces the first entry named [key], or appends it when absent. */
    fun with(key: String, type: Int, value: ByteArray): RawDictionary {
        val index = entries.indexOfFirst { it.key == key }
        val entry = RawEntry(type, key, value)
        return copy(entries = if (index < 0) entries + entry else entries.toMutableList().also { it[index] = entry })
    }

    /** Appends [entry] even when an entry with the same key exists. */
    fun plus(entry: RawEntry): RawDictionary = copy(entries = entries + entry)

    /** Removes every entry named [key]. */
    fun without(key: String): RawDictionary = copy(entries = entries.filterNot { it.key == key })

    companion object {
        const val UINT32 = 0x04
        const val UINT64 = 0x05
        const val BOOL = 0x08
        const val INT32 = 0x0C
        const val INT64 = 0x0D
        const val STRING = 0x18
        const val BYTES = 0x42

        /** Parses a well-formed dictionary (test helper; no validation). */
        fun parse(bytes: ByteArray): RawDictionary {
            val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val version = buf.short.toInt() and 0xFFFF
            val entries = mutableListOf<RawEntry>()
            while (true) {
                val type = buf.get().toInt() and 0xFF
                if (type == 0) break
                val key = ByteArray(buf.int).also { buf.get(it) }.toString(Charsets.UTF_8)
                val value = ByteArray(buf.int).also { buf.get(it) }
                entries += RawEntry(type, key, value)
            }
            val trailing = ByteArray(buf.remaining()).also { buf.get(it) }
            return RawDictionary(version, entries, trailing)
        }
    }
}

/** Little-endian UInt32 bytes. */
fun u32(value: Long): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value.toInt()).array()

/** Little-endian UInt64 bytes. */
fun u64(value: ULong): ByteArray = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value.toLong()).array()

/** Big-endian bytes of a UUID string, as KDBX stores cipher and KDF ids. */
fun uuidBytes(uuid: String): ByteArray {
    val u = java.util.UUID.fromString(uuid)
    return ByteBuffer.allocate(16).putLong(u.mostSignificantBits).putLong(u.leastSignificantBits).array()
}

private fun le16(v: Int) = byteArrayOf(v.toByte(), (v shr 8).toByte())

/** Little-endian Int32 bytes. */
fun le32(v: Int): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()

/** Little-endian Int64 bytes. */
fun le64(v: Long): ByteArray = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array()
