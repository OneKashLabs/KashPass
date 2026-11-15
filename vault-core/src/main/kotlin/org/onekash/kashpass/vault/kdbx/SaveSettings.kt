package org.onekash.kashpass.vault.kdbx

import java.nio.ByteBuffer
import java.util.UUID
import org.onekash.kashpass.vault.kdbx.VariantDictionaryWriter.RawEntry
import org.onekash.kashpass.vault.kdbx.VariantDictionaryWriter.Value

/**
 * The outer header settings a save takes from the opened file: the [cipher], the [compression], the
 * KDF as [kdf] (the parameters the KDF policy checks) and as [kdfEntries] (the dictionary
 * [KdbxHeaderWriter] writes), [publicCustomData] and [openedMinor], the file's minor version. The
 * master seed and the IV are not kept and [kdfEntries] holds no salt or seed: every save draws
 * fresh ones. [kdf] is the opened file's, salt or seed included.
 *
 * Both dictionaries are the file's after a read and a write: an entry with an empty name dropped,
 * the last value of a repeated name at the name's first position, names and string values decoded
 * as UTF-8 and encoded again (an invalid sequence becomes U+FFFD), a Bool written as 0 or 1, and
 * any other value as read.
 */
internal class SaveSettings private constructor(
    val cipher: OuterCipher,
    val compression: Compression,
    val kdf: KdfParameters,
    /**
     * The KDF dictionary in the order a save writes it: `$UUID` first, then the other entries in
     * the order of [OuterHeader.kdfEntries]. The `S` entry holds no bytes here; [KdbxHeaderWriter]
     * writes 32 fresh ones in its place.
     */
    val kdfEntries: List<RawEntry>,
    /** The public custom data items in file order; empty when the file has none. */
    val publicCustomData: List<RawEntry>,
    val openedMinor: Int,
) {
    companion object {
        /** The `$UUID` entry name. */
        internal val UUID_NAME = "\$UUID".encodeToByteArray()

        /** The salt (Argon2) or seed (AES-KDF) entry name, which every save replaces. */
        internal val SALT_NAME = "S".encodeToByteArray()

        /**
         * Returns the settings of [header]. A header without [OuterHeader.kdfEntries] gets the
         * dictionary built from [OuterHeader.kdf]: `$UUID, R, S` for AES-KDF and
         * `$UUID, V, I, M, P, S` for Argon2, then `K` and `A` when present.
         */
        fun from(header: OuterHeader): SaveSettings {
            val read = header.kdfEntries?.let { keePassRoundTrip(it.all()) } ?: typed(header.kdf)
            val kdfEntries = ArrayList<RawEntry>(read.size + 1)
            kdfEntries += RawEntry(VariantDictionary.BYTE_ARRAY, UUID_NAME, uuidBytes(KdfUuid.of(header.kdf)))
            for (e in read) when {
                sameName(e.name, UUID_NAME) -> Unit
                sameName(e.name, SALT_NAME) -> kdfEntries += salt()
                else -> kdfEntries += e
            }
            val custom = header.publicCustomData?.let { keePassRoundTrip(it.all()) }
            return SaveSettings(header.cipher, header.compression, header.kdf, kdfEntries, custom ?: emptyList(), header.minorVersion)
        }

        /** Returns true when [a] and [b] hold the same bytes. */
        // allowed: dictionary names are header bytes written in the clear, never a secret
        internal fun sameName(a: ByteArray, b: ByteArray): Boolean = a.contentEquals(b)

        // Entries as a read and a write leave them. Names that differ as bytes but decode to the
        // same string become one entry, at the position of the first of them.
        private fun keePassRoundTrip(entries: List<Pair<ByteArray, VariantDictionary.Entry>>): List<RawEntry> {
            val byName = LinkedHashMap<ByteBuffer, RawEntry>()
            for ((name, entry) in entries) {
                val decoded = utf8RoundTrip(name)
                val value = when (entry.type) {
                    VariantDictionary.STRING -> utf8RoundTrip(entry.value)
                    VariantDictionary.BOOL -> byteArrayOf(if (entry.value[0].toInt() != 0) 1 else 0)
                    else -> entry.value.copyOf()
                }
                byName[ByteBuffer.wrap(decoded)] = RawEntry(entry.type, decoded, value)
            }
            return byName.values.toList()
        }

        // An invalid UTF-8 sequence decodes to U+FFFD and does not throw. Header names and string
        // values hold no key or plaintext bytes.
        // allowed: header dictionary names and string values, which hold no secret
        private fun utf8RoundTrip(bytes: ByteArray): ByteArray = bytes.decodeToString().encodeToByteArray()

        private fun typed(kdf: KdfParameters): List<RawEntry> = when (kdf) {
            is KdfParameters.Aes -> listOf(raw("R", Value.UInt64(kdf.rounds)), salt())
            is KdfParameters.Argon2 -> listOfNotNull(
                raw("V", Value.UInt32(kdf.version)), raw("I", Value.UInt64(kdf.iterations)), raw("M", Value.UInt64(kdf.memoryBytes)),
                raw("P", Value.UInt32(kdf.parallelism)), salt(),
                kdf.secretKey?.let { raw("K", Value.Binary(it.copyOf())) },
                kdf.associatedData?.let { raw("A", Value.Binary(it.copyOf())) },
            )
        }

        private fun raw(name: String, value: Value) = VariantDictionaryWriter.raw(VariantDictionaryWriter.Entry(name, value))

        private fun salt() = RawEntry(VariantDictionary.BYTE_ARRAY, SALT_NAME, ByteArray(0))

        // KDBX stores a UUID as its 16 bytes in big-endian order.
        internal fun uuidBytes(uuid: UUID): ByteArray =
            ByteBuffer.allocate(16).putLong(uuid.mostSignificantBits).putLong(uuid.leastSignificantBits).array()
    }
}
