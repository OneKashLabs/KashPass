package org.onekash.kashpass.vault.testing

import kotlinx.coroutines.CoroutineDispatcher
import org.onekash.kashpass.vault.backup.BackupStore
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.open.VaultOpening
import org.onekash.kashpass.vault.storage.VaultStateStore
import org.onekash.kashpass.vault.storage.VaultStorage

/**
 * Builds KDBX 4 files whose outer header holds one VariantDictionary field (11, the KDF
 * parameters, or 12, the public custom data) of many tiny entries, as a file writer that controls
 * every byte before the header HMAC can write them. The format sets no count or size limit on
 * such a dictionary.
 */
object HeaderDictionaries {

    /** Outer header field ids of the two dictionaries. */
    const val KDF = 11
    const val PUBLIC_CUSTOM_DATA = 12

    // Type 0x42 (byte array), a 4-byte name length, a 3-byte name, a 4-byte value length of 0.
    private const val ENTRY_BYTES = 12

    // Signature, version, field 2 (AES-256), field 4 (32-byte seed), the dictionary field's id and
    // length, the dictionary version, its end byte and field 0 with no data.
    private const val FIXED_BYTES = 12 + (5 + 16) + (5 + 32) + 5 + 2 + 1 + 5

    /** The number of entries [manyEntries] writes for a file of at most [maxFileBytes]. */
    fun entriesFor(maxFileBytes: Int): Int = (maxFileBytes - FIXED_BYTES) / ENTRY_BYTES

    /**
     * Returns a file of at most [maxFileBytes]: signature, KDBX 4.0, AES-256, a 32-byte master
     * seed, then field [field] holding [entriesFor] entries of type 0x42 with distinct 3-byte names
     * and empty values, then the end field. Nothing follows the header: a reader that gets past
     * the header finds the file cut short.
     */
    fun manyEntries(field: Int, maxFileBytes: Int): ByteArray {
        val n = entriesFor(maxFileBytes)
        val dictionary = 2 + n * ENTRY_BYTES + 1
        val out = ByteArray(FIXED_BYTES - 2 - 1 - 5 + dictionary + 5)
        var p = 0
        fun le32(v: Int) {
            for (i in 0 until 4) out[p++] = (v ushr (8 * i)).toByte()
        }
        fun le16(v: Int) {
            out[p++] = v.toByte()
            out[p++] = (v ushr 8).toByte()
        }
        fun field(id: Int, length: Int) {
            out[p++] = id.toByte()
            le32(length)
        }
        le32(0x9AA2D903.toInt())
        le32(0xB54BFB67.toInt())
        le16(0)
        le16(4)
        field(2, 16)
        for (b in AES_256) out[p++] = b
        field(4, 32)
        p += 32
        field(field, dictionary)
        le16(0x0100)
        for (i in 0 until n) {
            out[p++] = 0x42
            le32(3)
            out[p++] = i.toByte()
            out[p++] = (i ushr 8).toByte()
            out[p++] = (i ushr 16).toByte()
            le32(0)
        }
        out[p++] = 0
        field(0, 0)
        check(p == out.size) { "wrote $p of ${out.size} bytes" }
        return out
    }

    /**
     * Returns the production opener over [storage], [state] and [backups], computing its limits
     * for a heap of [maxHeapBytes] instead of this JVM's.
     */
    fun opener(storage: VaultStorage, state: VaultStateStore, io: CoroutineDispatcher, maxHeapBytes: Long, backups: BackupStore): VaultOpening =
        VaultOpener(storage, state, io, maxHeapBytes = { maxHeapBytes }, backups = backups) { bytes, header, credentials, budget ->
            VaultXmlCodec.decode(bytes, header, credentials, budget)
        }

    // The AES-256 cipher UUID as KDBX stores it.
    private val AES_256 = byteArrayOf(
        0x31, 0xC1.toByte(), 0xF2.toByte(), 0xE6.toByte(), 0xBF.toByte(), 0x71, 0x43, 0x50,
        0xBE.toByte(), 0x58, 0x05, 0x21, 0x6A, 0xFC.toByte(), 0x5A, 0xFF.toByte(),
    )
}
