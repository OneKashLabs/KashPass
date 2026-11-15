package org.onekash.kashpass.vault.kdbx

import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.CIPHER
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.COMPRESSION
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.END
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.IV
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.KDF
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.MASTER_SEED
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.PUBLIC_CUSTOM_DATA
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.SIGNATURE_1
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.SIGNATURE_2
import java.security.SecureRandom
import org.onekash.kashpass.vault.kdbx.VariantDictionaryWriter.RawEntry

/**
 * Writes a KDBX 4 outer header: the signature 0x9AA2D903 0xB54BFB67 (never the pre-release
 * 0xB54BFB66, which a reader opens too), the version, then the fields 2 (cipher), 3 (compression),
 * 4 (master seed), 11 (KDF parameters), 7 (IV), 12 (public custom data, only with at least one
 * item) and 0 with 0D 0A 0D 0A. No other field is written: fields 5, 6, 8, 9 and 10 belong to
 * KDBX versions below 4.
 *
 * Each write draws a fresh 32-byte master seed, an IV of the cipher's size (16 bytes for AES-256,
 * 12 for ChaCha20) and a 32-byte KDF salt or seed, in that order, from the caller's random
 * source; the salt takes the place of the `S` entry. The header's SHA-256 and HMAC are the
 * encoder's to write. [KdbxHeaderWriterTest] pins the layout.
 */
internal object KdbxHeaderWriter {

    /** The outcome of [write]. */
    sealed interface Write {
        /**
         * The header [bytes] and the [header] [KdbxHeaderReader] reads from them. The encoder
         * derives the key with [kdf] and takes the master seed and the IV from [header], so the
         * key and the cipher use what the bytes say.
         */
        class Written(val bytes: ByteArray, val header: OuterHeader) : Write {
            val kdf: KdfParameters get() = header.kdf
        }

        /**
         * [KdbxHeaderReader] refused the written bytes with [result]. Settings from
         * [SaveSettings.from] give this only as NotEnoughMemory, when the re-read runs out of
         * memory; the caller reports any other result as an internal failure.
         */
        class Invalid(val result: KdbxResult) : Write
    }

    private const val MAJOR = 4

    private const val SEED_SIZE = 32
    private const val SALT_SIZE = 32
    private val END_VALUE = byteArrayOf(0x0D, 0x0A, 0x0D, 0x0A)

    /**
     * Writes the header of a save with [settings] as KDBX 4.[minorVersion], with every random
     * value drawn from [random]. Throws [KdbxException.DictionaryTooLarge] when the header would
     * not fit in an array, and [KdbxException.InvalidLength] with [KdbxException.Field.RANGE] for
     * a [minorVersion] outside 0..65535, which the 16-bit version field cannot hold.
     */
    fun write(settings: SaveSettings, minorVersion: Int, random: SecureRandom): Write {
        if (minorVersion !in 0..0xFFFF) throw KdbxException.InvalidLength(KdbxException.Field.RANGE)
        // The seed, IV, salt and dictionary are written in the clear, so none is zero-filled.
        val seed = ByteArray(SEED_SIZE).also(random::nextBytes)
        val iv = ByteArray(settings.cipher.ivSize).also(random::nextBytes)
        val salt = ByteArray(SALT_SIZE).also(random::nextBytes)
        val dictionary = VariantDictionaryWriter.writeRaw(withSalt(settings.kdfEntries, salt))
        val fields = ArrayList<Pair<Int, ByteArray>>(7)
        fields += CIPHER to SaveSettings.uuidBytes(settings.cipher.uuid)
        fields += COMPRESSION to ByteArray(4).also { Bytes.writeLe32(it, 0, compressionId(settings.compression)) }
        fields += MASTER_SEED to seed
        fields += KDF to dictionary
        fields += IV to iv
        // Field 12 is written only with at least one item.
        if (settings.publicCustomData.isNotEmpty()) fields += PUBLIC_CUSTOM_DATA to VariantDictionaryWriter.writeRaw(settings.publicCustomData)
        fields += END to END_VALUE
        val bytes = assemble(minorVersion, fields)
        // The settings come from a header read within the heap's budget or are built in memory,
        // so the re-read needs no budget.
        return when (val read = KdbxHeaderReader.read(bytes, KdbxHeaderReader.NO_HEAP_LIMIT)) {
            is KdbxHeaderReader.Read.Valid -> Write.Written(bytes, read.header)
            is KdbxHeaderReader.Read.Invalid -> Write.Invalid(read.result)
        }
    }

    // The entries with the `S` value replaced in place, or appended when absent.
    private fun withSalt(entries: List<RawEntry>, salt: ByteArray): List<RawEntry> {
        val fresh = RawEntry(VariantDictionary.BYTE_ARRAY, SaveSettings.SALT_NAME, salt)
        var replaced = false
        val out = entries.map { e ->
            if (SaveSettings.sameName(e.name, SaveSettings.SALT_NAME)) fresh.also { replaced = true } else e
        }
        return if (replaced) out else out + fresh
    }

    private fun assemble(minorVersion: Int, fields: List<Pair<Int, ByteArray>>): ByteArray {
        var size = 12L
        for ((_, data) in fields) size += 5L + data.size
        if (size > Int.MAX_VALUE) throw KdbxException.DictionaryTooLarge()
        val out = ByteArray(size.toInt())
        Bytes.writeLe32(out, 0, SIGNATURE_1)
        Bytes.writeLe32(out, 4, SIGNATURE_2)
        Bytes.writeLe16(out, 8, minorVersion)
        Bytes.writeLe16(out, 10, MAJOR)
        var p = 12
        for ((id, data) in fields) {
            out[p] = id.toByte()
            Bytes.writeLe32(out, p + 1, data.size)
            data.copyInto(out, p + 5)
            p += 5 + data.size
        }
        return out
    }

    // PwCompressionAlgorithm: None 0, GZip 1.
    private fun compressionId(compression: Compression): Int = when (compression) {
        Compression.NONE -> 0
        Compression.GZIP -> 1
    }
}
