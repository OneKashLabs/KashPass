package org.onekash.kashpass.vault.storage

import org.onekash.kashpass.vault.header.KeePassSignature

/** What an unlock gets from the vault's key file. */
sealed interface KeyFileRead {

    /** No key file is set for the vault. */
    data object None : KeyFileRead

    /**
     * The whole file. The unlock that receives it zero-fills it on every path; the opener does so
     * after parsing it. Nothing else keeps it.
     */
    class Bytes(val bytes: ByteArray) : KeyFileRead {
        override fun toString() = "Bytes(${bytes.size} bytes)"
    }

    /** The file could not be read. */
    data class Failed(val cause: StorageFailure) : KeyFileRead

    /** The file is a KeePass database, which is refused as a key file. */
    data object KeePassVault : KeyFileRead
}

/**
 * Reports whether the file at [location] starts with a KeePass signature
 * ([KeePassSignature.matches]), from a [VaultStorage.readPrefix] of
 * [KeePassSignature.BYTES] bytes. A file that can't be read now or is shorter reports
 * false. The returned prefix is zero-filled after the check, and the storage zero-fills a prefix
 * it doesn't return ([VaultStorage.readPrefix]): it can be key-file material. [KeyFileReadTest]
 * pins it.
 */
suspend fun VaultStorage.startsWithKeePassSignature(location: String): Boolean =
    when (val read = readPrefix(location, KeePassSignature.BYTES)) {
        is ReadResult.Failed -> false
        is ReadResult.Bytes -> try {
            KeePassSignature.matches(read.bytes)
        } finally {
            read.bytes.fill(0)
        }
    }

/**
 * Reads the key file at [location] from a provider call started now, with the vault's size cap
 * [maxBytes] ([maxVaultBytes] for this heap): a key file of any size is valid, so the cap is the
 * heap's. A file with a KeePass signature ([KeePassSignature.matches]) is zero-filled and reported
 * as [KeyFileRead.KeePassVault]. [KeyFileReadTest] pins each rule.
 */
suspend fun VaultStorage.readKeyFile(
    location: String,
    maxBytes: Int = maxVaultBytes(Runtime.getRuntime().maxMemory()),
): KeyFileRead = when (val read = readFresh(location, maxBytes)) {
    is ReadResult.Failed -> KeyFileRead.Failed(read.cause)
    is ReadResult.Bytes -> if (KeePassSignature.matches(read.bytes)) {
        read.bytes.fill(0)
        KeyFileRead.KeePassVault
    } else {
        KeyFileRead.Bytes(read.bytes)
    }
}
