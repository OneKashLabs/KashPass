package org.onekash.kashpass.vault.kdbx

/**
 * Builds the KDBX composite key: SHA-256 over the key parts, the password part before the key-file
 * part. KashPass takes the parts, never the password text.
 */
internal object CompositeKey {

    /**
     * Returns SHA-256([passwordHash] || [keyFilePart]) over the parts present, as a new 32-byte
     * array the caller zero-fills. [passwordHash] is SHA-256 of the UTF-8 password and is 32 bytes;
     * an empty password is the hash of the empty string, never an absent part. [keyFilePart] is
     * what the key file yields: 32 bytes for a raw, hex or hashed file and the decoded data of any
     * non-empty length for an XML key file. Throws [KdbxException.InvalidLength] for a hash that is
     * not 32 bytes, an empty key-file part, or no part at all. The caller's arrays are left as they
     * are.
     */
    fun compute(passwordHash: ByteArray?, keyFilePart: ByteArray?): ByteArray {
        if (passwordHash == null && keyFilePart == null) throw KdbxException.InvalidLength(KdbxException.Field.NO_KEY_PART)
        if (passwordHash != null && passwordHash.size != Digests.SHA256_BYTES) {
            throw KdbxException.InvalidLength(KdbxException.Field.PASSWORD_HASH)
        }
        if (keyFilePart != null && keyFilePart.isEmpty()) throw KdbxException.InvalidLength(KdbxException.Field.KEY_FILE_PART)
        return Digests.sha256(*listOfNotNull(passwordHash, keyFilePart).toTypedArray())
    }
}
