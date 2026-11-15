package org.onekash.kashpass.vault.doc

import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.header.UnsupportedReason
import org.onekash.kashpass.vault.kdbx.FailureCause
import org.onekash.kashpass.vault.kdbx.KdbxDamage
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.kdbx.KdbxUnsupported
import org.onekash.kashpass.vault.kdbx.OuterHeader
import org.onekash.kashpass.vault.policy.KdfRejection

/** Why an open failed for a reason that is not the file's. Values are only appended. */
enum class DecodeFailure {
    /** The platform's default provider lacks or failed at an algorithm the container uses. */
    PLATFORM,

    /** A KashPass bug. */
    INTERNAL,
}

/**
 * A KDBX 4 outer header read once from one byte array ([VaultXmlCodec.header]). [kdf] is built
 * once from the header's KDF parameters: the opener checks it, compares it with the baseline and
 * stores it, and [VaultXmlCodec.decode] derives with the parameters it was built from, without
 * reading the header again.
 */
internal class CheckedHeader(internal val outer: OuterHeader) {
    val kdf: KdfSettings = outer.kdf.toSettings()
}

/** The outcome of [VaultXmlCodec.header]. */
internal sealed interface HeaderRead {
    class Valid(val header: CheckedHeader) : HeaderRead

    /** The header is damaged or unsupported; [result] says how. Nothing was derived. */
    class Invalid(val result: Decoded) : HeaderRead
}

/** The outcome of [VaultXmlCodec.decode]: one value for every way a decode ends. */
internal sealed interface Decoded {

    /** The vault opened; [bytesAfterEnd] is true when the file has bytes after its end block. */
    class Opened(val document: VaultDocument, val bytesAfterEnd: Boolean) : Decoded

    /** The password or key file did not verify. */
    data object WrongKey : Decoded

    data class Damaged(val reason: DamageReason) : Decoded

    data class Unsupported(val reason: UnsupportedReason) : Decoded

    /** The KDF settings are outside the policy's bounds; nothing was derived. */
    data class Refused(val rejection: KdfRejection) : Decoded

    /** The file is larger than [limitBytes], the read limit. */
    data class TooLarge(val limitBytes: Int) : Decoded

    data object NotEnoughMemory : Decoded

    data class Failed(val cause: DecodeFailure) : Decoded

    companion object {
        /**
         * Maps a container outcome other than [KdbxResult.Opened]. [keyChecked] is true when the
         * result came after the header HMAC verified the key, which only an inner stream id can
         * make unsupported.
         */
        fun of(result: KdbxResult, keyChecked: Boolean): Decoded = when (result) {
            is KdbxResult.Opened -> Failed(DecodeFailure.INTERNAL)
            KdbxResult.WrongKey -> WrongKey
            is KdbxResult.Damaged -> Damaged(reason(result.reason))
            is KdbxResult.Unsupported -> Unsupported(reason(result.what, keyChecked))
            is KdbxResult.TooLarge -> TooLarge(result.limitBytes)
            is KdbxResult.NotEnoughMemory -> NotEnoughMemory
            is KdbxResult.Failed -> Failed(
                when (result.cause) {
                    FailureCause.PLATFORM -> DecodeFailure.PLATFORM
                    FailureCause.INTERNAL -> DecodeFailure.INTERNAL
                },
            )
        }

        private fun reason(damage: KdbxDamage): DamageReason = when (damage) {
            KdbxDamage.NOT_A_KDBX_FILE -> DamageReason.NOT_A_KEEPASS_FILE
            KdbxDamage.TRUNCATED -> DamageReason.TRUNCATED
            KdbxDamage.HEADER_FIELD -> DamageReason.HEADER_FIELD
            KdbxDamage.KDF_PARAMETERS -> DamageReason.KDF_PARAMETERS
            KdbxDamage.HEADER_HASH -> DamageReason.HEADER_HASH
            KdbxDamage.BLOCK_LENGTH -> DamageReason.BLOCK_LENGTH
            KdbxDamage.BLOCK_HMAC -> DamageReason.BLOCK_HMAC
            KdbxDamage.END_BLOCK_MISSING -> DamageReason.END_BLOCK_MISSING
            KdbxDamage.CIPHERTEXT_LENGTH -> DamageReason.CIPHERTEXT_LENGTH
            KdbxDamage.PADDING -> DamageReason.PADDING
            KdbxDamage.COMPRESSED_DATA -> DamageReason.COMPRESSED_DATA
            KdbxDamage.INNER_HEADER -> DamageReason.INNER_HEADER
            KdbxDamage.INNER_STREAM -> DamageReason.INNER_STREAM
            KdbxDamage.XML -> DamageReason.XML
            KdbxDamage.PROTECTED_VALUE -> DamageReason.PROTECTED_VALUE
            KdbxDamage.DATE -> DamageReason.DATE
            KdbxDamage.XML_HEADER_HASH -> DamageReason.XML_HEADER_HASH
            KdbxDamage.META_BINARY -> DamageReason.META_BINARY
        }

        private fun reason(what: KdbxUnsupported, keyChecked: Boolean): UnsupportedReason = when (what) {
            is KdbxUnsupported.FormatVersion -> UnsupportedReason.FormatVersion(what.major, what.minor)
            is KdbxUnsupported.Cipher -> UnsupportedReason.Cipher(what.uuid.toString())
            is KdbxUnsupported.Kdf -> UnsupportedReason.Kdf(what.uuid.toString())
            is KdbxUnsupported.DictionaryVersion -> UnsupportedReason.DictionaryVersion(what.major)
            is KdbxUnsupported.DictionaryValueType -> UnsupportedReason.DictionaryValueType(what.type)
            is KdbxUnsupported.Compression -> UnsupportedReason.Compression(what.id)
            is KdbxUnsupported.InnerStream -> UnsupportedReason.InnerStream(what.id, keyChecked)
        }
    }
}
