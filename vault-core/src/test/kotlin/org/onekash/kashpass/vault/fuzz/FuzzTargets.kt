package org.onekash.kashpass.vault.fuzz

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import org.onekash.kashpass.vault.doc.VaultKey
import org.onekash.kashpass.vault.doc.BinaryPool
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.DecodeFailure
import org.onekash.kashpass.vault.doc.Decoded
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.EncodeHooks
import org.onekash.kashpass.vault.doc.Encoded
import org.onekash.kashpass.vault.doc.HeaderRead
import org.onekash.kashpass.vault.doc.KdfEngine
import org.onekash.kashpass.vault.doc.KeyDerivation
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.parseInt32Invariant
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDelete
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.kdbx.AesCbc
import org.onekash.kashpass.vault.kdbx.Argon2Type
import org.onekash.kashpass.vault.kdbx.Attachment
import org.onekash.kashpass.vault.kdbx.Compression
import org.onekash.kashpass.vault.kdbx.EncoderRig
import org.onekash.kashpass.vault.kdbx.FailureCause
import org.onekash.kashpass.vault.kdbx.InnerHeaderReader
import org.onekash.kashpass.vault.kdbx.KdbxDamage
import org.onekash.kashpass.vault.kdbx.KdbxFailure
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.kdbx.KeySchedule
import org.onekash.kashpass.vault.kdbx.MemoryCause
import org.onekash.kashpass.vault.kdbx.OuterCipher
import org.onekash.kashpass.vault.kdbx.SaveSettings
import org.onekash.kashpass.vault.kdbx.VariantDictionary
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawField
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.le32
import org.onekash.kashpass.vault.xml.ByteSink
import org.onekash.kashpass.vault.xml.XmlElement
import org.onekash.kashpass.vault.xml.XmlReadResult
import org.onekash.kashpass.vault.xml.XmlReader
import org.onekash.kashpass.vault.xml.XmlWriter
import org.onekash.kashpass.vault.kdbx.KdfParameters as KdbxKdfParameters

/**
 * The fuzz targets, shared by the Jazzer harnesses ([DecoderFuzzTest]) and the corpus replay
 * ([FuzzReplayTest]). Each target throws [AssertionError] when the code under test lets an
 * exception escape, reports an internal failure, runs out of memory on an input of at most 64 KiB,
 * or takes longer than [timeLimitMillis] on such an input; the key derivation is replaced by a
 * fixed key, or in [roundTrip] runs with at most 32 KiB and two passes, so the time is the
 * container's. The encode targets also throw it when the encoder returns anything but the bytes
 * for a document within the limits, or a reader refuses or misreads the bytes it wrote.
 */
internal object FuzzTargets {

    /** Inputs up to this size must finish within the time limit and never run out of memory. */
    const val SMALL = 64 * 1024

    @Volatile
    var timeLimitMillis = 1_000L

    /**
     * Decompressed content is capped here, so the fuzzer's 256 MiB heap stays bounded: dense
     * custom fields at the 3 MiB XML cap open, encode and decode again in a 136 MiB heap, under
     * 256 / 1.5 MiB; the payload, attachments included, inflates to at most 8 MiB.
     */
    val LIMITS = VaultXmlCodec.Limits(open = 3 * 1024 * 1024, save = 3L * 1024 * 1024, decompression = 8 * 1024 * 1024, payloadSave = 8L * 1024 * 1024)

    /** The heap the fuzzer runs with; the header dictionaries are read within its budget. */
    const val HEAP = 256L * 1024 * 1024

    /** The transformed key every fuzzed file is built and read with. */
    private val TRANSFORMED = ByteArray(32) { (it * 11 + 5).toByte() }
    private val PASSWORD_HASH = ByteArray(32) { 1 }
    private val fixedKey: (KdbxKdfParameters, ByteArray) -> ByteArray = { _, _ -> TRANSFORMED.copyOf() }

    private val header by lazy { RawKdbx.parse(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx")).copy(rest = ByteArray(0)) }

    /** A whole file: header, hashes, blocks and everything after them. */
    fun decode(data: ByteArray) = timed(data.size) {
        check(ContainerDecode.decode(data, PASSWORD_HASH, null, LIMITS, Int.MAX_VALUE, maxHeapBytes = HEAP, derive = fixedKey), data.size)
    }

    /**
     * The payload of a well-formed file with valid MACs: the first byte's low bit picks gzip (1)
     * or none (0) as the header's compression, the rest is the payload as the outer cipher
     * encrypts it, so the fuzzer reaches the gzip reader, the inner header and the XML.
     */
    fun body(data: ByteArray) = timed(data.size) {
        check(ContainerDecode.decode(file(data), PASSWORD_HASH, null, LIMITS, Int.MAX_VALUE, maxHeapBytes = HEAP, derive = fixedKey), data.size)
    }

    /** An inner header followed by anything. */
    fun innerHeader(data: ByteArray) = timed(data.size) {
        try {
            InnerHeaderReader.read(data, data.size, OUTER)
        } catch (e: KdbxFailure) {
            check(e.result, data.size)
        }
    }

    /** A VariantDictionary. */
    fun dictionary(data: ByteArray) = timed(data.size) {
        try {
            VariantDictionary.read(data, KdbxDamage.KDF_PARAMETERS, HEAP / KdbxHeaderReader.DICTIONARY_HEAP_DIVISOR)
        } catch (e: KdbxFailure) {
            check(e.result, data.size)
        }
    }

    /**
     * The decrypted XML of a well-formed file whose inner header is fixed ([XML_INNER]: the
     * ChaCha20 stream and two attachments), so the fuzzer reaches the XML reader, the KDBX
     * context machine, the value rules, protected values, Meta/Binaries and the attachment
     * references resolved as they are read.
     */
    fun xml(data: ByteArray) = timed(data.size) {
        check(ContainerDecode.decode(file(bodyInput(XML_INNER + data, gzip = false)), PASSWORD_HASH, null, LIMITS, Int.MAX_VALUE, maxHeapBytes = HEAP, derive = fixedKey), data.size)
    }

    /**
     * A document built from the input, encoded by KashPass's encoder and decoded again. The input
     * chooses the cipher, the compression, the KDF (small parameters derived by [KdfEngine], or
     * the fixed key), the opened minor version, the attachments (a 0-byte one and duplicates
     * included, each referenced by the seed entry and its history), the protected values and up to
     * three edits (add, edit, delete). The decoded document equals the encoded one: the same XML
     * bytes but for protected values and `Ref` numbers, the same protected plaintext in document
     * order, and the same attachment content and flag for each reference.
     */
    fun roundTrip(data: ByteArray) = timed(data.size) {
        val c = Choices(data)
        val settings = settings(c)
        val real = c.byte() and 1 == 1
        val document = edited(seed(c, settings), c)
        val keys = if (real) KdfEngine() else FIXED_KEYS
        val bytes = encode(document, keys, data.size) ?: return@timed
        val decoded = decodeDocument(bytes, keys) ?: throw AssertionError("the owned decoder refuses the owned encoder's output")
        same("the owned decoder", document, decoded, attachments = true)
    }

    /**
     * The XML of [xml]'s file, opened, given save settings from the first byte and encoded by
     * KashPass's encoder with the fixed key: KashPass's decoder opens the output, the test toolkit
     * ([KdbxToolkit], which shares no container code with KashPass) opens it too, and both decrypt
     * the same XML bytes and the same attachment pool.
     */
    fun crossEncode(data: ByteArray) = timed(data.size) {
        val settings = settings(Choices(data.copyOf(minOf(1, data.size))))
        val xml = if (data.isEmpty()) data else data.copyOfRange(1, data.size)
        val opened = decodeDocument(file(bodyInput(XML_INNER + xml, gzip = false)), FIXED_KEYS) ?: return@timed
        if (opened.saveability != Saveability.Saveable) return@timed
        val document = VaultDocument(opened.xml, settings, opened.attachments, CREDENTIALS, opened.protectedValues, opened.xmlBytes, opened.saveability)
        val bytes = encode(document, FIXED_KEYS, data.size) ?: return@timed
        var ours: ByteArray? = null
        val result = ContainerDecode.decode(bytes, PASSWORD_HASH, null, LIMITS, Int.MAX_VALUE, maxHeapBytes = HEAP, derive = fixedKey, onXml = { b, off, len -> ours = b.copyOfRange(off, off + len) })
        if (result !is ContainerDecode.Result.Opened) throw AssertionError("the owned decoder refuses the owned encoder's output: $result")
        val pool = result.read.pool.values.toList()
        val theirs = try {
            KdbxToolkit.open(bytes, TRANSFORMED.copyOf()).layers
        } catch (e: Exception) {
            throw AssertionError("the toolkit refuses the owned encoder's output: ${e.javaClass.name}")
        }
        if (!MessageDigest.isEqual(ours, theirs.xml)) throw AssertionError("the owned decoder and the toolkit decrypt different XML")
        val toolkitPool = theirs.inner.filter { it.id == KdbxToolkit.INNER_BINARY }.map { Attachment(it.data[0].toInt() and 1 != 0, it.data.copyOfRange(1, it.data.size)) }
        if (!samePool(pool, toolkitPool)) throw AssertionError("the owned decoder and the toolkit read different attachments")
    }

    private fun samePool(a: List<Attachment>, b: List<Attachment>) = a.size == b.size && a.zip(b).all { (x, y) -> sameAttachment(x, y) }

    private fun sameAttachment(x: Attachment?, y: Attachment?) = x != null && y != null && x.protected == y.protected && x.data.contentEquals(y.data)

    private val CREDENTIALS = VaultKey.password("kashpass-fuzz".toCharArray())
    private val FIXED_KEYS = KeyDerivation { _, _ -> TRANSFORMED.copyOf() }
    private val NOW: Instant = Instant.parse("2026-10-28T12:00:00Z")

    /** The input read as choices; past its end every byte is 0. */
    private class Choices(private val data: ByteArray) {
        private var at = 0

        fun byte(): Int = if (at < data.size) data[at++].toInt() and 0xFF else 0

        /** A number in 0 until [n], for [n] up to 65,536. */
        fun below(n: Int): Int = ((byte() shl 8) or byte()) % n

        fun bytes(max: Int): ByteArray = ByteArray(below(max + 1)) { byte().toByte() }

        fun text(max: Int): String = String(bytes(max), Charsets.UTF_8)
    }

    // Save settings from [c]: cipher, compression, KDF and opened minor version; Argon2 memory is
    // at least 8 KiB per lane, which every reader derives alike.
    private fun settings(c: Choices): SaveSettings {
        val b = c.byte()
        val cipher = if (b and 1 == 0) OuterCipher.AES_256 else OuterCipher.CHACHA20
        val compression = if (b and 2 == 0) Compression.GZIP else Compression.NONE
        val kdf = when ((b shr 2) and 3) {
            1, 2 -> {
                val lanes = 1 + c.below(2)
                KdbxKdfParameters.Argon2(
                    if ((b shr 2) and 3 == 1) Argon2Type.ARGON2D else Argon2Type.ARGON2ID, ByteArray(32), lanes.toUInt(),
                    8192UL * lanes.toULong() * (1 + c.below(2)).toULong(), 1UL + c.below(2).toULong(), if (b and 0x40 == 0) 0x13u else 0x10u, null, null,
                )
            }
            else -> KdbxKdfParameters.Aes(1UL + c.below(64).toULong(), ByteArray(32))
        }
        return SaveSettings.from(EncoderRig.header(cipher, compression, kdf, minor = (b shr 4) and 1))
    }

    // A seed document: one entry with a protected password and every attachment [c] chooses
    // referenced by name, and a history entry that references one of them again.
    private fun seed(c: Choices, settings: SaveSettings): VaultDocument {
        val attachments = ArrayList<Attachment>()
        repeat(c.below(5)) {
            val kind = c.byte()
            attachments += when {
                kind % 4 == 0 -> Attachment(kind and 0x10 != 0, ByteArray(0))
                kind % 4 == 1 && attachments.isNotEmpty() -> attachments[c.below(attachments.size)].let { Attachment(if (kind and 0x10 != 0) !it.protected else it.protected, it.data.copyOf()) }
                else -> Attachment(kind and 0x10 != 0, c.bytes(300))
            }
        }
        val binaries = attachments.indices.joinToString("") { "<Binary><Key>a$it.bin</Key><Value Ref=\"$it\" /></Binary>" }
        val again = if (attachments.isEmpty()) "" else "<Binary><Key>again.bin</Key><Value Ref=\"${c.below(attachments.size)}\" /></Binary>"
        val recycleBin = if (c.byte() and 1 == 1) "True" else "False"
        val xml = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
            |<KeePassFile><Meta><Generator>KashPass</Generator><MemoryProtection><ProtectPassword>True</ProtectPassword></MemoryProtection>
            |<RecycleBinEnabled>$recycleBin</RecycleBinEnabled></Meta><Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Name>Root</Name>
            |<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><String><Key>Title</Key><Value>Seed</Value></String>
            |<String><Key>Password</Key><Value Protected="True"></Value></String>$binaries
            |<History><Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><String><Key>Title</Key><Value>Old</Value></String>
            |<String><Key>Password</Key><Value Protected="True"></Value></String>$again</Entry></History></Entry>
            |</Group></Root></KeePassFile>""".trimMargin().encodeToByteArray()
        val tree = (XmlReader.read(xml, 0, xml.size, Int.MAX_VALUE) as XmlReadResult.Parsed).document
        val values = HashMap<XmlElement, ProtectedText>()
        fun walk(e: XmlElement) {
            if (e.attribute("Protected") == "True") values[e] = ProtectedText.fromUtf8(c.bytes(40))
            e.elements().forEach(::walk)
        }
        walk(tree.root)
        return VaultDocument(tree, settings, attachments, CREDENTIALS, values, xml.size.toLong(), Saveability.Saveable)
    }

    // Applies up to three edits [c] chooses: add an entry, edit the seed entry, delete it.
    private fun edited(document: VaultDocument, c: Choices): VaultDocument {
        var d = document
        repeat(c.below(4)) {
            val id = DocumentIds.entries(d).keys.firstOrNull()
            val draft = EntryDraft(c.text(24), c.text(16), ProtectedText.fromUtf8(c.bytes(24)), c.text(16), c.text(48))
            d = when (c.byte() % 3) {
                0 -> EntryEdits.add(d, null, draft, NOW, UUID(c.byte().toLong(), c.byte().toLong() + 3)).document
                1 -> id?.let { (EntryEdits.edit(d, it, draft, NOW) as? EditResult.Changed)?.document } ?: d
                else -> id?.let { EntryDelete.delete(d, it, NOW)?.document } ?: d
            }
        }
        return d
    }

    // Encodes [document]; null for NotEnoughMemory on an input above [SMALL]. Every other
    // outcome but the bytes is a finding: the settings are within the KDF bounds.
    private fun encode(document: VaultDocument, keys: KeyDerivation, size: Int): ByteArray? = when (val e = VaultXmlCodec.encode(document, derive = keys)) {
        is Encoded.Bytes -> e.bytes
        Encoded.NotEnoughMemory -> if (size <= SMALL) throw AssertionError("ran out of memory encoding $size bytes") else null
        is Encoded.Refused -> throw AssertionError("the encoder refuses settings within the KDF bounds: ${e.rejection}")
        Encoded.Failed -> throw AssertionError("internal failure in the encoder")
    }

    // Opens [bytes] as the app does, with [keys]; null when the file does not open, and an
    // internal failure is a finding.
    private fun decodeDocument(bytes: ByteArray, keys: KeyDerivation): VaultDocument? {
        val header = (VaultXmlCodec.header(bytes, HEAP) as? HeaderRead.Valid)?.header ?: return null
        return when (val d = VaultXmlCodec.decode(bytes, header, CREDENTIALS, VaultXmlCodec.Budget(LIMITS, Int.MAX_VALUE, Runtime.getRuntime().maxMemory()), derive = keys::derive)) {
            is Decoded.Opened -> d.document
            is Decoded.Failed -> if (d.cause == DecodeFailure.INTERNAL) throw AssertionError("internal failure") else null
            else -> null
        }
    }

    // Fails unless [b], as [reader] read it, holds [a]'s XML, protected plaintext and, when
    // [attachments], each reference's attachment.
    private fun same(reader: String, a: VaultDocument, b: VaultDocument, attachments: Boolean) {
        val (xmlA, valuesA) = canonical(a)
        val (xmlB, valuesB) = canonical(b)
        if (!xmlA.contentEquals(xmlB)) throw AssertionError("$reader reads other XML than was encoded")
        if (valuesA.size != valuesB.size || valuesA.zip(valuesB).any { (x, y) -> !x.contentEquals(y) }) throw AssertionError("$reader reads other protected values than were encoded")
        if (!attachments) return
        val refsA = BinaryPool.values(a.xml.root).map { a.attachments.getOrNull(parseInt32Invariant(it.attribute("Ref")) ?: -1) }
        val refsB = BinaryPool.values(b.xml.root).map { b.attachments.getOrNull(parseInt32Invariant(it.attribute("Ref")) ?: -1) }
        val same = refsA.size == refsB.size && refsA.zip(refsB).all { (x, y) -> sameAttachment(x, y) }
        if (!same) throw AssertionError("$reader reads other attachments than were encoded")
    }

    // [document]'s XML as a save writes it, with each protected value as `*` and each `Ref` as
    // `#`, and the protected values' UTF-8 in document order.
    private fun canonical(document: VaultDocument): Pair<ByteArray, List<ByteArray>> {
        val values = ArrayList<ByteArray>()
        val encode = EncodeHooks(document) { }
        val hooks = object : XmlWriter.Hooks {
            override fun omit(element: XmlElement) = encode.omit(element)
            override fun attribute(element: XmlElement, name: String): String? = if (name == "Ref") "#" else null
            override fun content(element: XmlElement, sink: ByteSink): Boolean {
                val value = document.protectedValues[element] ?: return false
                values += value.utf8()
                sink.write('*'.code)
                return true
            }
        }
        val sink = ByteSink(::ByteArray, 4096)
        XmlWriter.write(document.xml, sink, hooks)
        return sink.buffer.copyOf(sink.size) to values
    }

    private val XML_INNER = KdbxToolkit.innerBytes(
        listOf(
            RawField(KdbxToolkit.INNER_STREAM_ID, le32(3)),
            RawField(KdbxToolkit.INNER_STREAM_KEY, ByteArray(64) { (it * 7 + 3).toByte() }),
            RawField(KdbxToolkit.INNER_BINARY, byteArrayOf(0) + "first".toByteArray()),
            RawField(KdbxToolkit.INNER_BINARY, byteArrayOf(1) + "second".toByteArray()),
            RawField(KdbxToolkit.INNER_END, ByteArray(0)),
        ),
    )

    private val OUTER = EncoderRig.header(OuterCipher.AES_256, Compression.GZIP, KdbxKdfParameters.Aes(1UL, ByteArray(32)))

    /** Builds the file [body] reads: [data]'s first byte picks the compression. */
    fun file(data: ByteArray): ByteArray {
        val gzip = data.isNotEmpty() && data[0].toInt() and 1 == 1
        val payload = if (data.isEmpty()) data else data.copyOfRange(1, data.size)
        val h = header.withField(RawKdbx.COMPRESSION, le32(if (gzip) 1 else 0))
        val headerBytes = h.toBytes()
        val out = ByteArrayOutputStream()
        out.write(headerBytes)
        out.write(MessageDigest.getInstance("SHA-256").digest(headerBytes))
        KeySchedule(h.field(RawKdbx.MASTER_SEED), TRANSFORMED).use { keys ->
            out.write(keys.headerMac(headerBytes, 0, headerBytes.size))
            val ciphertext = AesCbc.encrypt(keys.cipherKey(), h.field(RawKdbx.ENCRYPTION_IV), payload)
            var index = 0L
            var at = 0
            while (true) {
                val n = minOf(BLOCK, ciphertext.size - at)
                out.write(keys.blockMac(index++, ciphertext, at, n))
                out.write(le32(n))
                out.write(ciphertext, at, n)
                at += n
                if (n == 0) break
            }
        }
        return out.toByteArray()
    }

    /** The bytes [body] turns into [file], for a payload as the cipher encrypts it. */
    fun bodyInput(payload: ByteArray, gzip: Boolean): ByteArray = byteArrayOf(if (gzip) 1 else 0) + payload

    private const val BLOCK = 1024 * 1024

    private fun check(result: ContainerDecode.Result, size: Int) {
        if (result is ContainerDecode.Result.Opened) {
            result.read.pool.values.forEach { it.data.fill(0) }
            return
        }
        if (result is ContainerDecode.Result.Failed) check(result.result, size)
    }

    private fun check(result: KdbxResult, size: Int) {
        if (result == KdbxResult.Failed(FailureCause.INTERNAL)) throw AssertionError("internal failure")
        if (size <= SMALL && result == KdbxResult.NotEnoughMemory(MemoryCause.OUT_OF_MEMORY)) {
            throw AssertionError("ran out of memory on $size bytes")
        }
    }

    private inline fun timed(size: Int, block: () -> Unit) {
        val start = System.nanoTime()
        block()
        val millis = (System.nanoTime() - start) / 1_000_000
        if (size <= SMALL && millis > timeLimitMillis) throw AssertionError("$size bytes took $millis ms")
    }
}
