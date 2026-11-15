package org.onekash.kashpass.vault.kdbx

import java.util.UUID

/**
 * Reads a KDBX 4 outer header.
 *
 * Fields are applied in file order to the defaults (AES-256, gzip, AES-KDF 600,000 rounds without
 * a seed): the last value of a repeated field wins, an unknown id is skipped, field 11 replaces
 * the whole KDF parameter set, and the KDBX 3 fields 5 (transform seed) and 6 (transform rounds)
 * first turn a KDF other than AES-KDF into AES-KDF with its defaults, then set the seed or the
 * rounds. Fields 8 and 10 are kept as fallbacks for the inner header; field 9 is read and not
 * used. The one [KdfParameters] this builds is what the KDF policy checks and the KDF derives
 * with. After the fields, the checks run in this order: the cipher id, the master seed's size,
 * then the KDF parameters. The IV is kept as read; the decoder checks its size after the header
 * HMAC. The KDF dictionary is kept beside the parameters ([OuterHeader.kdfEntries]) for a save to
 * write back, and the public custom data as read ([OuterHeader.publicCustomData]).
 * [KdbxHeaderReaderTest] pins each rule.
 *
 * The format puts no limit on a dictionary's size, so a header of millions of tiny entries fills
 * the heap before the header HMAC can be checked. The copies of fields 11 and 12 and the entries
 * read from them are charged against one budget, the heap divided by [DICTIONARY_HEAP_DIVISOR]:
 * each field's length before it is copied, then each entry ([VariantDictionary.read]). Past the
 * budget the header is NotEnoughMemory([MemoryCause.LIMIT]), not damage. [HeaderMemoryTest] pins
 * it.
 */
internal object KdbxHeaderReader {

    /** The outcome of [read]: a header, or a damaged or unsupported file. */
    sealed interface Read {
        class Valid(val header: OuterHeader) : Read
        class Invalid(val result: KdbxResult) : Read
    }

    // Signatures and field ids; the ones a KDBX 4 save writes are shared with [KdbxHeaderWriter].
    internal const val SIGNATURE_1 = 0x9AA2D903.toInt()
    internal const val SIGNATURE_2 = 0xB54BFB67.toInt()
    private const val SIGNATURE_2_PRE_RELEASE = 0xB54BFB66.toInt()
    private const val SIGNATURE_2_KEEPASS_1 = 0xB54BFB65.toInt()

    internal const val END = 0
    internal const val CIPHER = 2
    internal const val COMPRESSION = 3
    internal const val MASTER_SEED = 4
    private const val TRANSFORM_SEED = 5
    private const val TRANSFORM_ROUNDS = 6
    internal const val IV = 7
    private const val STREAM_KEY = 8
    private const val STREAM_ID = 10
    internal const val KDF = 11
    internal const val PUBLIC_CUSTOM_DATA = 12

    private const val DEFAULT_AES_ROUNDS = 600_000L
    private const val MIN_SALT = 8

    /** The longest Argon2 salt a KDBX reader accepts; a longer one is damage. */
    const val MAX_SALT = 0x3FFFFFFF

    /**
     * The header dictionaries take at most the heap divided by this. The header is read
     * while the file's bytes (up to the heap divided by 8.6) and, on a refresh or a reopen, the
     * open document are alive. A KDF dictionary holds 3 to 8 entries and plugins write a few
     * public custom data items; a 256 MiB heap admits about 55,000 entries.
     */
    const val DICTIONARY_HEAP_DIVISOR = 16L

    /**
     * The heap to pass to [read] for header bytes that do not come from storage: the header
     * [KdbxHeaderWriter] writes from settings an earlier read admitted, and tests. Its
     * budget never runs out.
     */
    const val NO_HEAP_LIMIT = Long.MAX_VALUE

    /**
     * Reads the header at the start of [bytes]; a damaged or unsupported one is [Read.Invalid]. The
     * dictionary budget is [maxHeapBytes] divided by [DICTIONARY_HEAP_DIVISOR]; past it, or on an
     * OutOfMemoryError, the result is Invalid(NotEnoughMemory). An Argon2 salt longer than
     * [maxSaltBytes] ([MAX_SALT] outside tests) is damage.
     */
    fun read(bytes: ByteArray, maxHeapBytes: Long = NO_HEAP_LIMIT, maxSaltBytes: Int = MAX_SALT): Read = try {
        Read.Valid(parse(bytes, maxHeapBytes / DICTIONARY_HEAP_DIVISOR, maxSaltBytes))
    } catch (e: KdbxFailure) {
        Read.Invalid(e.result)
    } catch (e: OutOfMemoryError) {
        Read.Invalid(KdbxResult.NotEnoughMemory(MemoryCause.OUT_OF_MEMORY))
    }

    private fun unsupported(what: KdbxUnsupported): Nothing = throw KdbxFailure(KdbxResult.Unsupported(what))

    // The KDF parameter set while the fields are read: its UUID and its dictionary entries.
    private class KdfState(val uuid: UUID, val entries: VariantDictionary.Entries)

    private fun aesDefaults(): KdfState {
        val entries = VariantDictionary.Entries.empty()
        entries.set("R", VariantDictionary.Entry(VariantDictionary.UINT64, le64(DEFAULT_AES_ROUNDS)))
        return KdfState(KdfUuid.AES_KDF, entries)
    }

    private fun parse(bytes: ByteArray, budgetBytes: Long, maxSaltBytes: Int): OuterHeader {
        if (bytes.size < 4) damaged(KdbxDamage.TRUNCATED)
        if (Bytes.readLe32(bytes, 0) != SIGNATURE_1) damaged(KdbxDamage.NOT_A_KDBX_FILE)
        if (bytes.size < 8) damaged(KdbxDamage.TRUNCATED)
        val signature = when (Bytes.readLe32(bytes, 4)) {
            SIGNATURE_2 -> KdbxSignature.NORMAL
            SIGNATURE_2_PRE_RELEASE -> KdbxSignature.PRE_RELEASE
            SIGNATURE_2_KEEPASS_1 -> unsupported(KdbxUnsupported.FormatVersion(1, 0))
            else -> damaged(KdbxDamage.NOT_A_KDBX_FILE)
        }
        if (bytes.size < 12) damaged(KdbxDamage.TRUNCATED)
        val minor = Bytes.readLe16(bytes, 8)
        val major = Bytes.readLe16(bytes, 10)
        // KDBX 3 fields have 2-byte lengths, so nothing past the version is read for other majors.
        if (major != 4) unsupported(KdbxUnsupported.FormatVersion(major, minor))

        var cipher = OuterCipher.AES_256.uuid
        var compression = Compression.GZIP
        var masterSeed: ByteArray? = null
        var iv: ByteArray? = null
        var kdf = aesDefaults()
        var streamKey: ByteArray? = null
        var streamId: Int? = null
        var publicCustomData: VariantDictionary.Entries? = null
        var budget = budgetBytes
        // Charges a dictionary field's copy before it is made, then reads its entries.
        fun dictionary(at: Int, length: Int, damage: KdbxDamage): VariantDictionary.Entries {
            if (length > budget) throw KdbxFailure(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT))
            budget -= length
            val entries = VariantDictionary.read(bytes.copyOfRange(at, at + length), damage, budget)
            budget -= entries.heapBytes
            return entries
        }
        var p = 12
        while (true) {
            if (bytes.size - p < 5) damaged(KdbxDamage.TRUNCATED)
            val id = bytes[p].toInt() and 0xFF
            val length = Bytes.readLe32(bytes, p + 1)
            p += 5
            if (length < 0) damaged(KdbxDamage.HEADER_FIELD)
            if (length > bytes.size - p) damaged(KdbxDamage.TRUNCATED)
            val at = p
            p += length
            // Fields 11 and 12 are copied against the dictionary budget, below.
            val data = if (id == KDF || id == PUBLIC_CUSTOM_DATA) NO_DATA else bytes.copyOfRange(at, p)
            when (id) {
                END -> break
                CIPHER -> {
                    if (data.size != 16) damaged(KdbxDamage.HEADER_FIELD)
                    cipher = uuid(data)
                }
                COMPRESSION -> {
                    if (data.size != 4) damaged(KdbxDamage.HEADER_FIELD)
                    val compressionId = Bytes.readLe32(data, 0).toUInt().toLong()
                    compression = when (compressionId) {
                        0L -> Compression.NONE
                        1L -> Compression.GZIP
                        else -> unsupported(KdbxUnsupported.Compression(compressionId.toInt()))
                    }
                }
                MASTER_SEED -> masterSeed = data
                TRANSFORM_SEED -> kdf = asAesKdf(kdf).also { it.entries.set("S", VariantDictionary.Entry(VariantDictionary.BYTE_ARRAY, data)) }
                TRANSFORM_ROUNDS -> {
                    val aes = asAesKdf(kdf)
                    if (data.size != 8) damaged(KdbxDamage.HEADER_FIELD)
                    aes.entries.set("R", VariantDictionary.Entry(VariantDictionary.UINT64, data))
                    kdf = aes
                }
                IV -> iv = data
                STREAM_KEY -> streamKey = data
                STREAM_ID -> {
                    if (data.size != 4) damaged(KdbxDamage.HEADER_FIELD)
                    val streamIdValue = Bytes.readLe32(data, 0).toUInt().toLong()
                    if (streamIdValue >= InnerStream.COUNT) unsupported(KdbxUnsupported.InnerStream(streamIdValue.toInt()))
                    streamId = streamIdValue.toInt()
                }
                KDF -> {
                    // A KDF dictionary without a 16-byte $UUID is damage.
                    val entries = dictionary(at, length, KdbxDamage.KDF_PARAMETERS)
                    val id = entries.bytes("\$UUID")?.takeIf { it.size == 16 } ?: damaged(KdbxDamage.KDF_PARAMETERS)
                    kdf = KdfState(uuid(id), entries)
                }
                PUBLIC_CUSTOM_DATA -> publicCustomData = dictionary(at, length, KdbxDamage.HEADER_FIELD)
            }
        }

        val outerCipher = OuterCipher.entries.firstOrNull { it.uuid == cipher } ?: unsupported(KdbxUnsupported.Cipher(cipher))
        val seed = masterSeed ?: damaged(KdbxDamage.HEADER_FIELD)
        if (seed.size != 32) damaged(KdbxDamage.HEADER_FIELD)
        return OuterHeader(
            signature = signature,
            majorVersion = major,
            minorVersion = minor,
            cipher = outerCipher,
            compression = compression,
            masterSeed = seed,
            iv = iv ?: ByteArray(0),
            kdf = kdfParameters(kdf, maxSaltBytes),
            publicCustomData = publicCustomData,
            innerStreamKeyFallback = streamKey,
            innerStreamIdFallback = streamId,
            length = p,
            kdfEntries = kdf.entries,
        )
    }

    // Field 5 or 6 on a KDF other than AES-KDF starts from AES-KDF's defaults.
    private fun asAesKdf(kdf: KdfState): KdfState = if (kdf.uuid == KdfUuid.AES_KDF) kdf else aesDefaults()

    // An Argon2 number that is missing or of another type reads as 0, which the KDF policy
    // refuses; AES-KDF rounds that are missing or not a UInt64, a missing AES-KDF seed, and a
    // missing Argon2 salt or one under 8 bytes or over [maxSaltBytes] are damage.
    private fun kdfParameters(kdf: KdfState, maxSaltBytes: Int): KdfParameters {
        val e = kdf.entries
        return when (kdf.uuid) {
            KdfUuid.AES_KDF -> {
                val rounds = e["R"]?.takeIf { it.type == VariantDictionary.UINT64 } ?: damaged(KdbxDamage.KDF_PARAMETERS)
                val seed = e.bytes("S") ?: damaged(KdbxDamage.KDF_PARAMETERS)
                KdfParameters.Aes(Bytes.readLe64(rounds.value, 0).toULong(), seed)
            }
            KdfUuid.ARGON2D, KdfUuid.ARGON2ID -> {
                val salt = e.bytes("S") ?: damaged(KdbxDamage.KDF_PARAMETERS)
                if (salt.size < MIN_SALT || salt.size > maxSaltBytes) damaged(KdbxDamage.KDF_PARAMETERS)
                KdfParameters.Argon2(
                    type = if (kdf.uuid == KdfUuid.ARGON2D) Argon2Type.ARGON2D else Argon2Type.ARGON2ID,
                    salt = salt,
                    parallelism = u32(e, "P"),
                    memoryBytes = u64(e, "M"),
                    iterations = u64(e, "I"),
                    version = u32(e, "V"),
                    secretKey = e.bytes("K"),
                    associatedData = e.bytes("A"),
                )
            }
            else -> unsupported(KdbxUnsupported.Kdf(kdf.uuid))
        }
    }

    private fun u32(e: VariantDictionary.Entries, name: String): UInt =
        e[name]?.takeIf { it.type == VariantDictionary.UINT32 }?.let { Bytes.readLe32(it.value, 0).toUInt() } ?: 0U

    private fun u64(e: VariantDictionary.Entries, name: String): ULong =
        e[name]?.takeIf { it.type == VariantDictionary.UINT64 }?.let { Bytes.readLe64(it.value, 0).toULong() } ?: 0UL

    private fun uuid(b: ByteArray): UUID {
        var msb = 0L
        var lsb = 0L
        for (i in 0 until 8) msb = (msb shl 8) or (b[i].toLong() and 0xFF)
        for (i in 8 until 16) lsb = (lsb shl 8) or (b[i].toLong() and 0xFF)
        return UUID(msb, lsb)
    }

    private fun le64(v: Long) = ByteArray(8).also { Bytes.writeLe64(it, 0, v) }

    private val NO_DATA = ByteArray(0)
}
