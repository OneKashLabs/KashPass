package org.onekash.kashpass.vault.testing

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.onekash.kashpass.vault.kdbx.AesCbc
import org.onekash.kashpass.vault.kdbx.ChaCha20
import org.onekash.kashpass.vault.kdbx.Digests
import org.onekash.kashpass.vault.kdbx.HmacSha256
import org.onekash.kashpass.vault.kdbx.KdbxException
import org.onekash.kashpass.vault.kdbx.Salsa20

/**
 * Published vectors for the container primitives: AES-256-CBC (NIST SP 800-38A F.2.5 and F.2.6),
 * HMAC-SHA-256 (RFC 4231 test cases 1-7), SHA-256 and SHA-512 (the FIPS 180-4 example messages)
 * and PKCS#7 edge cases, which run on the platform's crypto provider, and the ChaCha20 and
 * Salsa20 vectors of [KeystreamVectors]. [failures] runs them all and names each that fails, so
 * the same set runs on the host JVM and on Android's provider under Robolectric.
 */
object PrimitiveVectors {

    class Hmac(val name: String, val key: String, val data: String, val mac: String)

    class Digest(val name: String, val message: String, val sha256: String, val sha512: String)

    const val NIST_KEY = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    const val NIST_IV = "000102030405060708090a0b0c0d0e0f"
    const val NIST_PLAINTEXT = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
    const val NIST_CIPHERTEXT = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d" +
        "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"

    /** RFC 4231 sections 4.2-4.8; test case 5's MAC is the 128-bit truncation it publishes. */
    val hmac: List<Hmac> = listOf(
        Hmac("RFC 4231 test case 1", "0b".repeat(20), "4869205468657265", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        Hmac(
            "RFC 4231 test case 2", "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        ),
        Hmac("RFC 4231 test case 3", "aa".repeat(20), "dd".repeat(50), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        Hmac(
            "RFC 4231 test case 4", "0102030405060708090a0b0c0d0e0f10111213141516171819", "cd".repeat(50),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
        Hmac("RFC 4231 test case 5", "0c".repeat(20), "546573742057697468205472756e636174696f6e", "a3b6167473100ee06e0c796c2955552b"),
        Hmac(
            "RFC 4231 test case 6", "aa".repeat(131),
            "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
        Hmac(
            "RFC 4231 test case 7", "aa".repeat(131),
            "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b6579" +
                "20616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565" +
                "647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c" +
                "676f726974686d2e",
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    )

    val digests: List<Digest> = listOf(
        Digest(
            "FIPS 180-4 abc", "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        Digest(
            "FIPS 180-4 empty message", "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        Digest(
            "FIPS 180-4 448-bit message", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335" +
                "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
        ),
        Digest(
            "FIPS 180-4 896-bit message",
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018" +
                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
    )

    /** Plaintext lengths around the AES block size for the padding round trip. */
    val paddingLengths = listOf(0, 1, 15, 16, 17, 31, 32, 1024 * 1024 + 1)

    /**
     * Single plaintext blocks whose padding is invalid: a last byte of 0, 17 or 255, and a last
     * byte of 16 with one earlier pad byte changed, at each of the 15 positions before it.
     */
    fun badPaddingBlocks(): List<Pair<String, ByteArray>> = buildList {
        for (last in listOf(0, 17, 255)) add("last byte $last" to ByteArray(16) { if (it == 15) last.toByte() else 1 })
        for (back in 1..15) add("pad 16 with byte $back before the end changed" to ByteArray(16) { if (it == 15 - back) 15 else 16 })
    }

    /**
     * Runs every vector and edge case, with [hmacVectors] in place of [hmac]; returns the name of
     * each that fails, empty when all pass.
     */
    fun failures(hmacVectors: List<Hmac> = hmac): List<String> = buildList {
        fun check(name: String, ok: () -> Boolean) {
            val passed = try {
                ok()
            } catch (e: Exception) {
                false
            }
            if (!passed) add(name)
        }
        val key = NIST_KEY.hexToByteArray()
        val iv = NIST_IV.hexToByteArray()
        check("NIST SP 800-38A F.2.5 CBC-AES256.Encrypt") {
            val data = NIST_PLAINTEXT.hexToByteArray()
            AesCbc.cbc(Cipher.ENCRYPT_MODE, key, iv, data, 0, data.size)
            data.contentEquals(NIST_CIPHERTEXT.hexToByteArray())
        }
        check("NIST SP 800-38A F.2.6 CBC-AES256.Decrypt") {
            val data = NIST_CIPHERTEXT.hexToByteArray()
            AesCbc.cbc(Cipher.DECRYPT_MODE, key, iv, data, 0, data.size)
            data.contentEquals(NIST_PLAINTEXT.hexToByteArray())
        }
        check("NIST SP 800-38A F.2.6 in place at an offset") {
            val buf = ByteArray(5) + NIST_CIPHERTEXT.hexToByteArray() + ByteArray(3)
            AesCbc.cbc(Cipher.DECRYPT_MODE, key, iv, buf, 5, 64)
            buf.copyOfRange(5, 69).contentEquals(NIST_PLAINTEXT.hexToByteArray())
        }
        for (v in hmacVectors) check(v.name) {
            val expected = v.mac.hexToByteArray()
            val mac = HmacSha256(v.key.hexToByteArray()).use { it.mac(v.data.hexToByteArray()) }
            mac.copyOf(expected.size).contentEquals(expected)
        }
        for (v in digests) {
            val message = v.message.encodeToByteArray()
            check("${v.name} SHA-256") { Digests.sha256(message).contentEquals(v.sha256.hexToByteArray()) }
            check("${v.name} SHA-512") { Digests.sha512(message).contentEquals(v.sha512.hexToByteArray()) }
        }
        for (n in paddingLengths) check("PKCS#7 round trip of $n bytes") {
            val plain = ByteArray(n) { (it * 7).toByte() }
            val encrypted = AesCbc.encrypt(key, iv, plain)
            val jca = Cipher.getInstance("AES/CBC/PKCS5Padding")
                .apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv)) }
                .doFinal(plain)
            val sameAsJca = jca.contentEquals(encrypted)
            val length = AesCbc.decrypt(key, iv, encrypted, 0, encrypted.size)
            sameAsJca && length == n && encrypted.copyOf(n).contentEquals(plain)
        }
        for ((name, block) in badPaddingBlocks()) check("bad padding: $name") {
            val data = block.copyOf()
            AesCbc.cbc(Cipher.ENCRYPT_MODE, key, iv, data, 0, data.size)
            try {
                AesCbc.decrypt(key, iv, data, 0, data.size)
                false
            } catch (e: KdbxException.BadPadding) {
                true
            }
        }
        val chachaVectors = KeystreamVectors.chacha.map { it to ChaCha20.Counter.RFC8439 } + (KeystreamVectors.chachaLargeCounterTc8 to ChaCha20.Counter.LARGE)
        for ((v, counter) in chachaVectors) check(v.name) {
            val data = v.plaintext.hexToByteArray()
            ChaCha20(v.key.hexToByteArray(), v.nonce.hexToByteArray(), counter, initialCounter = v.counter).use { it.xor(data, 0, data.size) }
            data.contentEquals(v.ciphertext.hexToByteArray())
        }
        check("RFC 8439 2.3.2") {
            val block = ByteArray(64)
            val v = KeystreamVectors
            ChaCha20(v.RFC8439_BLOCK_KEY.hexToByteArray(), v.RFC8439_BLOCK_NONCE.hexToByteArray(), ChaCha20.Counter.RFC8439, initialCounter = v.RFC8439_BLOCK_COUNTER)
                .use { it.xor(block, 0, 64) }
            block.contentEquals(v.RFC8439_BLOCK.hexToByteArray())
        }
        for (v in KeystreamVectors.salsa) check(v.name) {
            val expected = v.keystream.hexToByteArray()
            val data = ByteArray(expected.size)
            Salsa20(v.key.hexToByteArray(), v.nonce.hexToByteArray(), initialBlock = (v.position / 64).toLong()).use { it.xor(data, 0, data.size) }
            data.contentEquals(expected)
        }
        for (n in listOf(1, 15, 17)) check("ciphertext of $n bytes is not a block multiple") {
            try {
                AesCbc.decrypt(key, iv, ByteArray(n), 0, n)
                false
            } catch (e: KdbxException.CiphertextNotBlockMultiple) {
                true
            }
        }
    }
}
