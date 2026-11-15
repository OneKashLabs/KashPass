package org.onekash.kashpass.vault.doc

/** Whether KashPass can save a vault without risking content it can't hold exactly. */
sealed interface Saveability {

    data object Saveable : Saveability

    /** The vault opens read-only for [reason]. */
    data class ReadOnly(val reason: ReadOnlyReason) : Saveability
}

/** Why a vault is read-only. */
enum class ReadOnlyReason {
    /** The XML has a document type declaration. */
    DOCTYPE,

    /**
     * The decrypted XML, or the payload a save writes (inner header with the attachments, and
     * the XML), is too large to encode again within the memory budget.
     */
    TOO_LARGE_TO_SAVE,

    /** An entry attachment's `Ref` named no attachment when it was read. */
    ATTACHMENT_REF_OUT_OF_RANGE,

    /**
     * An attachment no entry references. No open gives this reason: a save drops such an
     * attachment ([BinaryPool.rebuild]). The value stays because values are only appended.
     */
    UNREFERENCED_ATTACHMENT,

    /** A Protected="True" element has child elements, so protected values can misalign. */
    PROTECTED_CONTAINER,

    /**
     * A backup opened to view or save as a new file
     * ([org.onekash.kashpass.vault.save.VaultSaving.saveBackupCopy]).
     */
    BACKUP,

    /**
     * The last good copy, shown while the file can't be read or its header needs more memory than
     * the heap allows.
     */
    LAST_COPY,

    /** The last good copy of a corrupted file. */
    LAST_COPY_CORRUPTED,

    /** The file's provider grants reading only ([FileAccess.PROVIDER_READ_ONLY]). */
    PROVIDER_READ_ONLY,

    /** A file another app handed over, open for this session only ([FileAccess.SESSION_ONLY]). */
    OPENED_FROM_APP,

    /** The last good copy of a file corrupted after the header HMAC verified the key. */
    LAST_COPY_CORRUPTED_AFTER_HEADER,
}

/**
 * How KashPass holds the file it opens. Every vault made from one open keeps it
 * ([OpenedVault.access]), so a reload or a backup opened from the session applies it again. A
 * backup's own read-only reason is the one shown; the access stays for the file.
 */
enum class FileAccess {
    /** The remembered vault with a read and write grant: saveable unless its content says not. */
    READ_WRITE,

    /** The remembered vault whose provider granted reading only. */
    PROVIDER_READ_ONLY,

    /**
     * A file another app handed over for this session. Read-only, and nothing about it is stored
     * ([org.onekash.kashpass.vault.open.VaultOpener.storesFor]).
     */
    SESSION_ONLY,
}
