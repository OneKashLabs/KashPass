package org.onekash.kashpass.vault.doc

/**
 * What an unlock was given. It sets what biometric unlock seals (`VaultSession.unlockKey`
 * in the open package): the passphrase hash, never a key-file part.
 */
enum class UnlockOrigin {
    /** A password alone. */
    PASSWORD,

    /** A password and a key file. */
    PASSWORD_AND_KEY_FILE,

    /** A key file with an empty password field: the key file alone, or with an empty password. */
    KEY_FILE_ONLY,

    /** A stored passphrase hash alone (biometric unlock). */
    STORED_KEY,

    /** A stored passphrase hash and a key file read for this unlock (biometric unlock). */
    STORED_KEY_AND_KEY_FILE,
}
