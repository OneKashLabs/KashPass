package org.onekash.kashpass.vault.kdbx

import java.security.SecureRandom
import java.util.Base64
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import org.onekash.kashpass.vault.doc.KdfEngine
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.xml.ByteSink

/** Settings, keys and an XML writer for encoder tests. */
internal object EncoderRig {

    const val PASSWORD = "kashpass-test"
    const val SECRET = "s3crét ☃"

    val composite: ByteArray get() = KdbxToolkit.Key(PASSWORD).composite()

    val aesKdf = KdfParameters.Aes(1_000UL, ByteArray(32))
    val argon2d = KdfParameters.Argon2(Argon2Type.ARGON2D, ByteArray(32), 2u, 65_536UL, 2UL, 0x13u, null, null)
    val argon2id = KdfParameters.Argon2(Argon2Type.ARGON2ID, ByteArray(32), 2u, 65_536UL, 2UL, 0x13u, null, null)

    /** The save settings for a file with [cipher], [compression] and [kdf]. */
    fun settings(cipher: OuterCipher, compression: Compression, kdf: KdfParameters): SaveSettings = SaveSettings.from(header(cipher, compression, kdf))

    /**
     * A KDBX 4.[minor] outer header with [cipher], [compression] and [kdf], a zero master seed
     * and IV, and no KDF dictionary, public custom data or inner stream fallbacks.
     */
    fun header(cipher: OuterCipher, compression: Compression, kdf: KdfParameters, minor: Int = 0): OuterHeader =
        OuterHeader(KdbxSignature.NORMAL, 4, minor, cipher, compression, ByteArray(32), ByteArray(cipher.ivSize), kdf, null, null, null, 0)

    /** Derives with KashPass's own KDF. */
    fun derive(p: KdfParameters, composite: ByteArray): ByteArray = KdfEngine().derive(p, composite)

    val attachments = listOf(
        Attachment(false, "recovery codes".encodeToByteArray()),
        Attachment(true, ByteArray(256) { it.toByte() }),
        Attachment(false, ByteArray(0)),
    )

    /**
     * A KeePass document with one entry whose protected password is [SECRET], XORed with
     * [keystream] and Base64-encoded.
     */
    fun xml(keystream: Keystream): ByteArray {
        val secret = SECRET.encodeToByteArray()
        keystream.xor(secret, 0, secret.size)
        val value = Base64.getEncoder().encodeToString(secret)
        return """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
            |<KeePassFile><Meta><Generator>KeePass</Generator></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Name>Root</Name>
            |<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><String><Key>Title</Key><Value>Example</Value></String>
            |<String><Key>Password</Key><Value Protected="True">$value</Value></String>
            |<Binary><Key>codes.txt</Key><Value Ref="0" /></Binary></Entry></Group></Root></KeePassFile>""".trimMargin().encodeToByteArray()
    }

    /**
     * Writes the payload as the codec does: a [ByteSink] on the payload sink's arrays that gives
     * back each array it outgrows, the inner header, then the XML [content] returns, handed over
     * without a copy. [written] receives the XML bytes.
     */
    fun writer(written: (ByteArray) -> Unit = {}, content: (Keystream) -> ByteArray = ::xml): (PayloadSink) -> Unit = { payload ->
        val sink = ByteSink(payload::allocate, 64, payload::release)
        payload.writeInnerHeader { b, o, l -> sink.write(b, o, l) }
        val xml = content(payload.keystream)
        written(xml)
        sink.write(xml)
        payload.handOver(sink.buffer, sink.size)
    }

    /** Encodes with [settings] and the rig's defaults. */
    fun encode(
        settings: SaveSettings,
        writeXml: (PayloadSink) -> Unit = writer(),
        attachments: List<Attachment> = this.attachments,
        minor: Int = 0,
        kdfAllowed: (KdfParameters) -> Boolean = { true },
        derive: (KdfParameters, ByteArray) -> ByteArray = ::derive,
        random: SecureRandom = SecureRandom(),
        buffers: Buffers = Buffers.Default,
        composite: ByteArray = this.composite,
        step: (KdbxEncoder.Step) -> Unit = {},
    ): EncodeResult = KdbxEncoder.encode(settings, minor, composite, kdfAllowed, derive, attachments, writeXml, random, buffers, step)
}

/** Reads the outer header of [raw] as a save starts from it. */
internal fun openedHeader(raw: RawKdbx): OuterHeader =
    assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(raw.headerBytes())).header

/** Writes the header of a save of [raw] as KDBX 4.[minor], drawing from [random]. */
internal fun writtenHeader(raw: RawKdbx, minor: Int = minOf(raw.minor, 1), random: SecureRandom = SecureRandom()): KdbxHeaderWriter.Write.Written =
    assertIs<KdbxHeaderWriter.Write.Written>(KdbxHeaderWriter.write(SaveSettings.from(openedHeader(raw)), minor, random))

/** Asserts that [actual] holds [expected]'s KDF settings; the salt or seed too when [withSalt]. */
internal fun assertKdfEquals(expected: KdfParameters, actual: KdfParameters, withSalt: Boolean, message: String = "") {
    when (expected) {
        is KdfParameters.Aes -> {
            val a = assertIs<KdfParameters.Aes>(actual, message)
            assertEquals(expected.rounds, a.rounds, message)
            if (withSalt) assertContentEquals(expected.seed, a.seed, message)
        }
        is KdfParameters.Argon2 -> {
            val a = assertIs<KdfParameters.Argon2>(actual, message)
            assertEquals(expected.type, a.type, message)
            assertEquals(expected.parallelism, a.parallelism, message)
            assertEquals(expected.memoryBytes, a.memoryBytes, message)
            assertEquals(expected.iterations, a.iterations, message)
            assertEquals(expected.version, a.version, message)
            assertContentEquals(expected.secretKey, a.secretKey, message)
            assertContentEquals(expected.associatedData, a.associatedData, message)
            if (withSalt) assertContentEquals(expected.salt, a.salt, message)
        }
    }
}

/** The salt (Argon2) or seed (AES-KDF) of [kdf]. */
internal fun saltOf(kdf: KdfParameters): ByteArray = when (kdf) {
    is KdfParameters.Aes -> kdf.seed
    is KdfParameters.Argon2 -> kdf.salt
}
