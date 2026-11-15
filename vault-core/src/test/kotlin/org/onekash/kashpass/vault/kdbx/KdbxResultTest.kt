package org.onekash.kashpass.vault.kdbx

import java.util.UUID
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import org.junit.jupiter.api.Test

class KdbxResultTest {

    @Test
    fun `every damage value says whether it is in the payload`() {
        val inPayload = setOf(
            KdbxDamage.BLOCK_LENGTH, KdbxDamage.BLOCK_HMAC, KdbxDamage.END_BLOCK_MISSING, KdbxDamage.CIPHERTEXT_LENGTH,
            KdbxDamage.PADDING, KdbxDamage.COMPRESSED_DATA, KdbxDamage.INNER_HEADER, KdbxDamage.INNER_STREAM,
            KdbxDamage.XML, KdbxDamage.PROTECTED_VALUE, KdbxDamage.DATE, KdbxDamage.XML_HEADER_HASH, KdbxDamage.META_BINARY,
        )
        val header = setOf(
            KdbxDamage.NOT_A_KDBX_FILE, KdbxDamage.TRUNCATED, KdbxDamage.HEADER_FIELD, KdbxDamage.KDF_PARAMETERS,
            KdbxDamage.HEADER_HASH,
        )
        // A new value must be put in one of the two sets.
        assertEquals(KdbxDamage.entries.toSet(), inPayload + header)
        for (d in KdbxDamage.entries) assertEquals(d in inPayload, d.inPayload, d.name)
    }

    @Test
    fun `no result shows bytes in its string form`() {
        val secret = ByteArray(32) { 0x41 }
        val header = OuterHeader(
            KdbxSignature.NORMAL, 4, 1, OuterCipher.AES_256, Compression.GZIP, secret, secret,
            KdfParameters.Aes(600_000UL, secret), null, secret, 3, 100,
        )
        val container = KdbxContainer(header, InnerHeader(3, secret, listOf(Attachment(true, secret))), false)
        val results = listOf(
            KdbxResult.Opened(container, Plaintext(secret.copyOf(), 0, 32)),
            KdbxResult.WrongKey,
            KdbxResult.Damaged(KdbxDamage.PADDING),
            KdbxResult.Unsupported(KdbxUnsupported.Cipher(UUID(1, 2))),
            KdbxResult.TooLarge(64),
            KdbxResult.NotEnoughMemory(MemoryCause.LIMIT),
            KdbxResult.Failed(FailureCause.PLATFORM),
        )
        for (r in results) {
            val text = "$r ${(r as? KdbxResult.Opened)?.let { "${it.container} ${it.plaintext} ${it.container.header} ${it.container.inner}" }}"
            assertFalse("AAAA" in text || "65, 65" in text || "41414141" in text, text)
        }
    }

    @Test
    fun `closing the plaintext zero-fills its buffer and can run twice`() {
        val buffer = byteArrayOf(1, 2, 3, 4)
        val plaintext = Plaintext(buffer, 1, 2)
        plaintext.close()
        assertContentEquals(ByteArray(4), buffer)
        plaintext.close()
        assertContentEquals(ByteArray(4), buffer)
    }
}
