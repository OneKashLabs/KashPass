package org.onekash.kashpass.vault.kdbx

import java.util.UUID

/**
 * The outcome of opening a KDBX 4 file with [KdbxDecoder]: one value for every way an open
 * ends, so no exception but a CancellationException reaches the caller. No result has a string
 * form that shows key, plaintext or file bytes.
 */
internal sealed interface KdbxResult {

    /**
     * The file opened. [plaintext] holds the decrypted payload with the XML; the caller closes it,
     * which zero-fills it. The attachments in [container] are separate copies the caller owns.
     */
    class Opened(val container: KdbxContainer, val plaintext: Plaintext) : KdbxResult

    /** The password or key file did not verify: the header HMAC differs. */
    data object WrongKey : KdbxResult

    /** The file is damaged at the layer [reason] names. */
    data class Damaged(val reason: KdbxDamage) : KdbxResult

    /** The file uses a format or algorithm KashPass does not open; [what] names it. */
    data class Unsupported(val what: KdbxUnsupported) : KdbxResult

    /** The file is larger than [limitBytes], the read limit for this device's heap. */
    data class TooLarge(val limitBytes: Int) : KdbxResult

    /** Opening needs more memory than this device has; [cause] says how that was found. */
    data class NotEnoughMemory(val cause: MemoryCause) : KdbxResult

    /** Opening failed for a reason that is not the file's ([FailureCause]). */
    data class Failed(val cause: FailureCause) : KdbxResult
}

/** How [KdbxResult.NotEnoughMemory] was found. */
internal enum class MemoryCause {
    /**
     * Decompressed content, the KDF's memory or the outer header's dictionaries passed a limit set
     * by the heap or an array's size.
     */
    LIMIT,

    /** An OutOfMemoryError was thrown. */
    OUT_OF_MEMORY,
}

/** Why [KdbxResult.Failed] happened. */
internal enum class FailureCause {
    /** The platform's default provider lacks or failed at an algorithm the container uses. */
    PLATFORM,

    /**
     * A KashPass bug: a primitive used after close, or another exception the decoder or the
     * encoder caught.
     */
    INTERNAL,
}

/**
 * The layer at which a file is damaged. [inPayload] is true for damage in the encrypted payload
 * or its block framing, found after the header HMAC passed: a repair import checks the header and
 * its HMAC as usual and reads past such damage. [KdbxResultTest] classifies every value.
 */
internal enum class KdbxDamage(val inPayload: Boolean) {
    /** The file does not start with a KDBX signature. */
    NOT_A_KDBX_FILE(false),

    /** The input ends inside the outer header, its SHA-256 or its HMAC. */
    TRUNCATED(false),

    /** An outer header field has a negative or overlong length or a wrong size, the IV included. */
    HEADER_FIELD(false),

    /** The KDF parameters are malformed or refused by the KDF (Argon2 salt, AES-KDF seed). */
    KDF_PARAMETERS(false),

    /** The SHA-256 stored after the header differs from the header's. */
    HEADER_HASH(false),

    /** A block length is negative or longer than the bytes left. */
    BLOCK_LENGTH(true),

    /** A block HMAC differs: the block was changed, moved, repeated or left out. */
    BLOCK_HMAC(true),

    /** The input ends before the end block. */
    END_BLOCK_MISSING(true),

    /** The ciphertext is not a whole number of cipher blocks. */
    CIPHERTEXT_LENGTH(true),

    /** The AES padding is not valid PKCS#7. */
    PADDING(true),

    /** The compressed payload is not valid gzip or zlib data. */
    COMPRESSED_DATA(true),

    /** The inner header is cut or malformed. */
    INNER_HEADER(true),

    /** The inner stream id or key is missing or malformed. */
    INNER_STREAM(true),

    /**
     * The XML is not well-formed, has content after its root, has a root other than KeePassFile
     * or no root group, or holds a value or structure the container decoder refuses.
     */
    XML(true),

    /** A protected value is not Base64. */
    PROTECTED_VALUE(true),

    /** A date is not a valid KDBX 4 date. */
    DATE(true),

    /** The XML Meta/HeaderHash differs from the header's SHA-256 or is not Base64. */
    XML_HEADER_HASH(true),

    /** A Meta/Binaries item has an ID that is not a non-negative integer, or bad content. */
    META_BINARY(true),
}

/** What made a file unsupported. */
internal sealed interface KdbxUnsupported {

    /** A format version other than KDBX 4.x; KeePass 1 is major 1. */
    data class FormatVersion(val major: Int, val minor: Int) : KdbxUnsupported

    /** An outer cipher other than AES-256 or ChaCha20, by UUID. */
    data class Cipher(val uuid: UUID) : KdbxUnsupported

    /** A KDF other than AES-KDF, Argon2d or Argon2id, by UUID. */
    data class Kdf(val uuid: UUID) : KdbxUnsupported

    /** A VariantDictionary with a major version above 1. */
    data class DictionaryVersion(val major: Int) : KdbxUnsupported

    /** A VariantDictionary value type the format does not define. */
    data class DictionaryValueType(val type: Int) : KdbxUnsupported

    /** A compression id other than none (0) or gzip (1). */
    data class Compression(val id: Int) : KdbxUnsupported

    /** An inner stream id other than ArcFour variant (1), Salsa20 (2) or ChaCha20 (3). */
    data class InnerStream(val id: Int) : KdbxUnsupported
}

/**
 * The decrypted payload of an opened file: the XML is [xmlLength] bytes of [buffer] from
 * [xmlOffset]. [close] zero-fills [buffer] and drops it, so [buffer] is empty afterwards and the
 * payload can be collected while the caller goes on; it can run more than once. A caller keeps
 * no reference to the payload past [close].
 */
internal class Plaintext(buffer: ByteArray, val xmlOffset: Int, val xmlLength: Int) : AutoCloseable {

    var buffer: ByteArray = buffer
        private set

    init {
        Bytes.checkRange(buffer.size, xmlOffset, xmlLength)
    }

    override fun close() {
        buffer.fill(0)
        buffer = EMPTY
    }

    private companion object {
        val EMPTY = ByteArray(0)
    }
}

/**
 * Carries a failed outcome out of the decoder's readers to the decoder's boundary, which turns it
 * back into [result]. Stackless and without a message.
 */
internal class KdbxFailure(val result: KdbxResult) : Exception(null, null, false, false)

/** Throws [KdbxFailure] for a file damaged at [reason]. */
internal fun damaged(reason: KdbxDamage): Nothing = throw KdbxFailure(KdbxResult.Damaged(reason))
