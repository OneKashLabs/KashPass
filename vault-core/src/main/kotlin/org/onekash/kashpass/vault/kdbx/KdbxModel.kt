package org.onekash.kashpass.vault.kdbx

import java.util.UUID

/** The second signature word: the KDBX value, or the KDBX pre-release value, which opens too. */
internal enum class KdbxSignature { NORMAL, PRE_RELEASE }

/**
 * Outer ciphers KDBX 4 files use that KashPass opens, by the UUID of header field 2, with the
 * size of the IV each takes (header field 7).
 */
internal enum class OuterCipher(val uuid: UUID, val ivSize: Int) {
    AES_256(UUID.fromString("31c1f2e6-bf71-4350-be58-05216afc5aff"), 16),
    CHACHA20(UUID.fromString("d6038a2b-8b6f-4cb5-a524-339a31dbb59a"), 12),
}

/** Payload compression (outer header field 3). */
internal enum class Compression { NONE, GZIP }

/** Argon2 variants KDBX 4 defines. */
internal enum class Argon2Type { ARGON2D, ARGON2ID }

/** The `$UUID` values of the KDFs KashPass opens. */
internal object KdfUuid {
    val AES_KDF: UUID = UUID.fromString("c9d9f39a-628a-4460-bf74-0d08c18a4fea")
    val ARGON2D: UUID = UUID.fromString("ef636ddf-8c29-444b-91f7-a9a403e30a0c")
    val ARGON2ID: UUID = UUID.fromString("9e298b19-56db-4773-b23d-fc3ec6f0a1e6")

    /** Returns the `$UUID` of the KDF [kdf] belongs to. */
    fun of(kdf: KdfParameters): UUID = when (kdf) {
        is KdfParameters.Aes -> AES_KDF
        is KdfParameters.Argon2 -> if (kdf.type == Argon2Type.ARGON2D) ARGON2D else ARGON2ID
    }
}

/**
 * The KDF parameters a file's key is derived with, after the KDBX header rules.
 * [KdbxHeaderReader] builds the one instance that the KDF policy checks and the KDF derives with.
 * The arrays are the caller's to zero-fill; none of them is secret.
 */
internal sealed class KdfParameters {

    /**
     * AES-KDF: [rounds] AES-256 encryptions keyed by [seed]; a seed that is not 32 bytes is
     * hashed first.
     */
    class Aes(val rounds: ULong, val seed: ByteArray) : KdfParameters()

    /**
     * Argon2 with [memoryBytes] as stated in the header's `M` entry; [secretKey] (`K`) and
     * [associatedData] (`A`) are null when absent or not byte arrays.
     */
    class Argon2(
        val type: Argon2Type,
        val salt: ByteArray,
        val parallelism: UInt,
        val memoryBytes: ULong,
        val iterations: ULong,
        val version: UInt,
        val secretKey: ByteArray?,
        val associatedData: ByteArray?,
    ) : KdfParameters()
}

/**
 * A KDBX 4 outer header as read. [length] is the header's size in bytes (the
 * signature to the end of the end field), which its SHA-256 and HMAC cover. [iv] is kept as read;
 * the decoder checks its size for the cipher after the header HMAC. [innerStreamKeyFallback] and
 * [innerStreamIdFallback] are the legacy outer fields 8 and 10, which the inner header's own
 * fields replace; each is null when absent. [publicCustomData] is the public custom data
 * dictionary as read, null when field 12 is absent. [kdfEntries] is the KDF dictionary [kdf] was
 * built from, after the fold of fields 5 and 6, in the order the names first appeared;
 * [SaveSettings] writes both back. [kdfEntries] is null for a header that [KdbxHeaderReader] did
 * not read.
 */
internal class OuterHeader(
    val signature: KdbxSignature,
    val majorVersion: Int,
    val minorVersion: Int,
    val cipher: OuterCipher,
    val compression: Compression,
    val masterSeed: ByteArray,
    val iv: ByteArray,
    val kdf: KdfParameters,
    val publicCustomData: VariantDictionary.Entries?,
    val innerStreamKeyFallback: ByteArray?,
    val innerStreamIdFallback: Int?,
    val length: Int,
    val kdfEntries: VariantDictionary.Entries? = null,
)

/** An inner-header attachment: its bytes and whether its flag marks it protected in memory. */
internal class Attachment(val protected: Boolean, val data: ByteArray)

/**
 * The inner header after the outer fallbacks: the inner stream [streamId] and [streamKey], and the
 * attachments in file order, never merged. [streamKey] is the caller's to zero-fill.
 */
internal class InnerHeader(val streamId: Int, val streamKey: ByteArray, val attachments: List<Attachment>)

/**
 * An opened KDBX 4 container. [bytesAfterEnd] is true when the file has bytes after its end
 * block, which the reader ignores and a save drops.
 */
internal class KdbxContainer(val header: OuterHeader, val inner: InnerHeader, val bytesAfterEnd: Boolean)
