package org.onekash.kashpass.vault.kdbx

/**
 * The only exceptions the container primitives throw. Each carries no message and no stack trace,
 * so nothing from a key, a plaintext or a file reaches a log or a crash report through it. Each
 * subclass's KDoc names what the decoder or the encoder reports for it. An OutOfMemoryError is
 * not caught here; the decoder reports it as not enough memory.
 */
sealed class KdbxException : Exception(null, null, false, false) {

    /**
     * A key, nonce, IV, key part, limit or range has the wrong size. The decoder checks every
     * length it reads from a file before a primitive sees it, so it reports this as an internal
     * failure, never as damage.
     */
    class InvalidLength(val field: Field) : KdbxException()

    /**
     * The AES ciphertext is not a whole number of 16-byte blocks; the decoder reports a damaged
     * file.
     */
    class CiphertextNotBlockMultiple : KdbxException()

    /**
     * The PKCS#7 padding after AES-CBC decryption is not valid ([AesCbc]); the decoder reports a
     * damaged file, never a wrong password.
     */
    class BadPadding : KdbxException()

    /**
     * A keystream ran past its block counter. The decoder reports the outer cipher's as damaged
     * ciphertext; the inner stream's 64-bit counter does not run out within one file.
     */
    class KeystreamExhausted : KdbxException()

    /**
     * A primitive was used after `close()`, a bug in the caller. The decoder never reports it as
     * a damaged file.
     */
    class Closed : KdbxException()

    /**
     * The compressed payload is not valid gzip or zlib data; the decoder reports a damaged
     * file.
     */
    class CompressedData(val fault: Fault) : KdbxException()

    /**
     * The decompressed payload is larger than [limit] bytes; the decoder reports that the vault
     * needs more memory than this device has.
     */
    class InflatedTooLarge(val limit: Int) : KdbxException()

    /**
     * The platform's default provider lacks an algorithm the container uses or failed inside it.
     * Android API 31 and later always provide AES-CBC, SHA-256 and SHA-512.
     */
    class AlgorithmUnavailable : KdbxException()

    /**
     * The KDF refuses its parameters (for example an Argon2 salt under 8 bytes); the decoder
     * reports damaged KDF parameters.
     */
    class KdfParametersInvalid : KdbxException()

    /**
     * The KDF needs more memory than the heap or an array allows; the decoder reports that the
     * vault needs more memory than this device has.
     */
    class DerivationTooLarge : KdbxException()

    /** A dictionary to write is larger than an array can hold; the save fails. */
    class DictionaryTooLarge : KdbxException()

    /** What [InvalidLength] found the wrong size. */
    enum class Field {
        KEY,
        NONCE,
        IV,
        ARCFOUR_KEY,
        MASTER_SEED,
        TRANSFORMED_KEY,
        PASSWORD_HASH,
        KEY_FILE_PART,

        /** A composite key with neither a password nor a key-file part, which opens no vault. */
        NO_KEY_PART,
        LIMIT,

        /** An offset or length outside the array it indexes. */
        RANGE,
    }

    /** What [CompressedData] found wrong, in the terms of RFC 1950, 1951 and 1952. */
    enum class Fault {
        GZIP_METHOD,
        GZIP_FLAGS,
        HEADER_CRC,
        ZLIB_HEADER,
        ZLIB_METHOD,
        ZLIB_WINDOW,
        ZLIB_DICTIONARY,
        DEFLATE_DATA,
        CRC,
        ISIZE,
        ADLER,
    }
}
