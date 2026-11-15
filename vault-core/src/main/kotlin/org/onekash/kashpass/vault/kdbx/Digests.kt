package org.onekash.kashpass.vault.kdbx

import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.ProviderException

/**
 * SHA-256 and SHA-512 from the platform's default provider (no provider is named). Each part is
 * fed to the digest in turn, so a hash over several arrays never builds their concatenation, and
 * the `Into` variants write the hash into an array the caller owns (a key buffer from [Buffers]).
 * MessageDigest resets its state after each digest. Provider failures become
 * [KdbxException.AlgorithmUnavailable].
 */
internal object Digests {

    const val SHA256_BYTES = 32
    const val SHA512_BYTES = 64

    /** Returns SHA-256 over [parts] in order, as a new array the caller zero-fills if secret. */
    fun sha256(vararg parts: ByteArray): ByteArray = ByteArray(SHA256_BYTES).also { sha256Into(it, 0, *parts) }

    /** Returns SHA-512 over [parts] in order, as a new array the caller zero-fills if secret. */
    fun sha512(vararg parts: ByteArray): ByteArray = ByteArray(SHA512_BYTES).also { sha512Into(it, 0, *parts) }

    /** Writes SHA-256 over [parts] into [out] from [outOffset]. */
    fun sha256Into(out: ByteArray, outOffset: Int, vararg parts: ByteArray) = into("SHA-256", SHA256_BYTES, out, outOffset, parts)

    /** Writes SHA-512 over [parts] into [out] from [outOffset]. */
    fun sha512Into(out: ByteArray, outOffset: Int, vararg parts: ByteArray) = into("SHA-512", SHA512_BYTES, out, outOffset, parts)

    /** A fresh SHA-256 digest from the default provider. */
    fun sha256Digest(): MessageDigest = instance("SHA-256")

    private fun into(algorithm: String, size: Int, out: ByteArray, outOffset: Int, parts: Array<out ByteArray>) {
        Bytes.checkRange(out.size, outOffset, size)
        val digest = instance(algorithm)
        provider {
            for (p in parts) digest.update(p)
            digest.digest(out, outOffset, size)
        }
    }

    private fun instance(algorithm: String): MessageDigest = provider { MessageDigest.getInstance(algorithm) }

    /** Runs [block], turning a provider failure into [KdbxException.AlgorithmUnavailable]. */
    inline fun <T> provider(block: () -> T): T = try {
        block()
    } catch (e: GeneralSecurityException) {
        throw KdbxException.AlgorithmUnavailable()
    } catch (e: ProviderException) {
        throw KdbxException.AlgorithmUnavailable()
    }
}
