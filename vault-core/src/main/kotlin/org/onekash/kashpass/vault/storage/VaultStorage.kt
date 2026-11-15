package org.onekash.kashpass.vault.storage

/**
 * Reads and writes vault and key files: whole files, and a file's first bytes for a signature
 * check. The app implements it over the Storage Access Framework; tests use the shared fake in
 * test fixtures, which enforces the same contract.
 */
interface VaultStorage {

    /**
     * Reads the file at [location] into one array. Implementations read at most [maxBytes] + 1
     * bytes and report [StorageFailure.TOO_LARGE] when the file is bigger than [maxBytes].
     */
    suspend fun read(location: String, maxBytes: Int): ReadResult

    /**
     * Reads like [read], but always from a provider call started now, never one shared with an
     * earlier caller. The saver uses it, so its conflict check and read-back see the file as it is.
     */
    suspend fun readFresh(location: String, maxBytes: Int): ReadResult = read(location, maxBytes)

    /**
     * Reads the first [count] bytes of [location] from a provider call started now, or the whole
     * file when it is shorter. It reads no further than [count] bytes and never reports
     * [StorageFailure.TOO_LARGE]. Bytes it read but doesn't return are zero-filled, on failure
     * too: a key file's first bytes are read this way.
     */
    suspend fun readPrefix(location: String, count: Int): ReadResult

    /** Reports whether [location] can be written, without opening it for writing. */
    suspend fun writability(location: String): Writability

    /**
     * Replaces the file's content with [bytes] in one pass, truncating whatever was longer.
     * [WriteResult.Written] means every byte was written and the stream closed without error;
     * it says nothing about what the provider later does with the file.
     */
    suspend fun write(location: String, bytes: ByteArray): WriteResult

    /** Returns what the provider reports about [location]; a value it doesn't report is null. */
    suspend fun metadata(location: String): FileMetadata

    /** Deletes [location] when the provider supports deleting it. */
    suspend fun delete(location: String): DeleteResult
}

/**
 * Returns the most bytes KashPass reads from a vault or key file on a heap of [maxHeapBytes]: the
 * heap divided by 8.6, with no fixed cap (about 30 MiB on a 256 MiB heap, 60 MiB on 512 MiB,
 * 119 MiB on 1 GiB). Opening and saving a vault of attachments that compress nothing take about
 * 5.7 times the file at their peak; 8.6 keeps a margin of 1.5 over that. Content limits are
 * separate ([org.onekash.kashpass.vault.doc.VaultXmlCodec.Limits]). [VaultSizeLimitTest] pins it.
 */
fun maxVaultBytes(maxHeapBytes: Long): Int =
    (maxHeapBytes.coerceIn(0L, Long.MAX_VALUE / LIMIT_NUMERATOR) * LIMIT_NUMERATOR / LIMIT_DENOMINATOR)
        .coerceAtMost(MAX_ARRAY_BYTES.toLong()).toInt()

// The heap divided by 8.6, as 5/43 in integers.
private const val LIMIT_NUMERATOR = 5L
private const val LIMIT_DENOMINATOR = 43L

// The largest array a JVM or ART allocates reliably.
private const val MAX_ARRAY_BYTES = Int.MAX_VALUE - 8

/** Outcome of [VaultStorage.read], [VaultStorage.readFresh] and [VaultStorage.readPrefix]. */
sealed interface ReadResult {

    /** The complete file, or for [VaultStorage.readPrefix] at most the requested first bytes. */
    class Bytes(val bytes: ByteArray) : ReadResult

    /** The file could not be read. */
    data class Failed(val cause: StorageFailure) : ReadResult
}

/** Why a vault file could not be read or written; the app turns it into a message with a fix. */
enum class StorageFailure {
    /** Deleted, moved, or not served by the provider. */
    NOT_FOUND,

    /** The persisted access grant was revoked by the system or the user. */
    PERMISSION_REVOKED,

    /** Any other failure, including a cloud file not available offline. */
    IO_FAILURE,

    /** Bigger than [maxVaultBytes] for this device's heap. */
    TOO_LARGE,

    /** The provider didn't answer within the deadline ([DeadlineStorage]). */
    TIMED_OUT,
}

/** Outcome of [VaultStorage.writability]. */
enum class Writability {
    WRITABLE,

    /** The location is not a `content:` URI, so no provider serves it. */
    NOT_CONTENT,

    /** The provider reports a virtual document, which has no bytes to write. */
    NOT_WRITABLE,

    /** KashPass holds no write grant for the location. */
    NO_WRITE_GRANT,

    /** The provider couldn't be reached: the file is gone or the provider failed. */
    UNAVAILABLE,

    /** The provider didn't answer within the deadline ([DeadlineStorage]). */
    TIMED_OUT,
}

/** Outcome of [VaultStorage.write]. */
sealed interface WriteResult {

    /** Every byte was written and the stream closed without error. */
    data object Written : WriteResult

    /**
     * The write failed. [afterOpen] is true when the file was already opened for writing, so it
     * can be truncated or partly written; false means the file was not touched.
     */
    data class Failed(val cause: StorageFailure, val afterOpen: Boolean) : WriteResult
}

/** What a provider reports about a file. */
data class FileMetadata(val displayName: String?, val size: Long?, val lastModifiedMillis: Long?)

/** Outcome of [VaultStorage.delete]. */
enum class DeleteResult { DELETED, UNSUPPORTED, FAILED }
