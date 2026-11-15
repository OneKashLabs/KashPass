package org.onekash.kashpass.vault.header

/** Argon2 variants KDBX 4 defines. */
enum class Argon2Variant { ARGON2D, ARGON2ID }

/** Key-derivation settings from the KDBX 4 outer header, as the key derivation uses them. */
sealed interface KdfSettings {

    /** AES-KDF with [rounds] transformation rounds. */
    data class AesKdf(val rounds: ULong) : KdfSettings

    /** Argon2 with memory in bytes, as stored in the header's `M` entry. */
    data class Argon2(
        val variant: Argon2Variant,
        val iterations: ULong,
        val memoryBytes: ULong,
        val parallelism: UInt,
        val version: UInt,
    ) : KdfSettings
}

/** Which setting made a file unsupported; the app turns it into a message. */
sealed interface UnsupportedReason {

    /** Any format version other than KDBX 4.x, including KDBX 3.x and KeePass 1.x. */
    data class FormatVersion(val major: Int, val minor: Int) : UnsupportedReason

    /** An outer cipher other than AES-256 or ChaCha20 (for example Twofish). */
    data class Cipher(val uuid: String) : UnsupportedReason

    /** A key derivation function other than AES-KDF, Argon2d or Argon2id. */
    data class Kdf(val uuid: String) : UnsupportedReason

    /** A KDF parameter dictionary with a major version above 1. */
    data class DictionaryVersion(val major: Int) : UnsupportedReason

    /** A KDF parameter dictionary value of a type KDBX 4 does not define. */
    data class DictionaryValueType(val type: Int) : UnsupportedReason

    /** A compression id other than none (0) or gzip (1). */
    data class Compression(val id: Int) : UnsupportedReason

    /**
     * An inner stream id other than ArcFour variant (1), Salsa20 (2) or ChaCha20 (3).
     * [keyChecked] is true when the id came from the inner header, which is read after the key was
     * derived and the header HMAC verified it; false when it came from the outer header, before
     * any derivation.
     */
    data class InnerStream(val id: Int, val keyChecked: Boolean) : UnsupportedReason
}

/**
 * Why a file was refused as damaged. [afterHeaderHmac] is true for damage found after the header
 * HMAC verified the key: KeePass 2's Repair Mode import, which the app points the user to,
 * checks the header and its HMAC as usual and reads past such damage. Values are only appended;
 * KashPass's own reader gives NOT_A_KEEPASS_FILE, TRUNCATED and the values from HEADER_FIELD on.
 */
enum class DamageReason(val afterHeaderHmac: Boolean = false) {
    NOT_A_KEEPASS_FILE,
    TRUNCATED,
    INVALID_LENGTH,
    UNKNOWN_FIELD,
    DUPLICATE_FIELD,
    MISSING_FIELD,
    INVALID_COMPRESSION,
    INVALID_DICTIONARY,
    DUPLICATE_KEY,
    UNKNOWN_VALUE_TYPE,
    WRONG_VALUE_TYPE,
    TRAILING_BYTES,

    /** An outer header field has a negative or overlong length or a wrong size. */
    HEADER_FIELD,

    /** The KDF parameters are malformed (an AES-KDF without a seed, a short Argon2 salt). */
    KDF_PARAMETERS,

    /** The SHA-256 stored after the header differs from the header's. */
    HEADER_HASH,

    /** A block length is negative or longer than the bytes left. */
    BLOCK_LENGTH(afterHeaderHmac = true),

    /** A block HMAC differs: the block was changed, moved, repeated or left out. */
    BLOCK_HMAC(afterHeaderHmac = true),

    /** The file ends before the end block. */
    END_BLOCK_MISSING(afterHeaderHmac = true),

    /** The ciphertext is not a whole number of cipher blocks. */
    CIPHERTEXT_LENGTH(afterHeaderHmac = true),

    /** The AES padding is not valid. */
    PADDING(afterHeaderHmac = true),

    /** The compressed content is not valid gzip data. */
    COMPRESSED_DATA(afterHeaderHmac = true),

    /** The inner header is cut or malformed. */
    INNER_HEADER(afterHeaderHmac = true),

    /** The inner stream id or key is missing or malformed. */
    INNER_STREAM(afterHeaderHmac = true),

    /** The XML is malformed or holds a value or structure the KDBX format does not allow. */
    XML(afterHeaderHmac = true),

    /** A protected value is not Base64. */
    PROTECTED_VALUE(afterHeaderHmac = true),

    /** A date is malformed. */
    DATE(afterHeaderHmac = true),

    /** The XML Meta/HeaderHash differs from the header's SHA-256. */
    XML_HEADER_HASH(afterHeaderHmac = true),

    /** A Meta/Binaries item is malformed. */
    META_BINARY(afterHeaderHmac = true),
}
