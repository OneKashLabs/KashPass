package org.onekash.kashpass.vault.doc

import java.security.SecureRandom
import java.util.Base64
import kotlin.coroutines.cancellation.CancellationException
import org.onekash.kashpass.vault.kdbx.Attachment
import org.onekash.kashpass.vault.kdbx.Buffers
import org.onekash.kashpass.vault.kdbx.EncodeResult
import org.onekash.kashpass.vault.kdbx.InnerHeaderWriter
import org.onekash.kashpass.vault.kdbx.KdbxEncoder
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.PayloadSink
import org.onekash.kashpass.vault.kdbx.SaveSettings
import org.onekash.kashpass.vault.policy.KdfPolicy
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.xml.ByteSink
import org.onekash.kashpass.vault.xml.XmlDocument
import org.onekash.kashpass.vault.xml.XmlElement
import org.onekash.kashpass.vault.xml.XmlWriter
import org.onekash.kashpass.vault.kdbx.KdfParameters as KdbxKdfParameters

/**
 * Decodes vaults with KashPass's own KDBX 4 container ([ContainerDecode]) and encodes them with
 * KashPass's own encoder ([KdbxEncoder]), key derivation ([KdfEngine]) and XML writer
 * ([XmlWriter] with [EncodeHooks], into the encoder's payload array).
 */
internal object VaultXmlCodec {

    private val kdf = KdfEngine()

    /**
     * Size limits for the decrypted content of an open and a save, in bytes:
     * - [open]: the XML an open reads; more is NotEnoughMemory(LIMIT).
     * - [save]: the XML a save writes. A vault with more XML opens read-only
     *   ([ReadOnlyReason.TOO_LARGE_TO_SAVE]), and a save edited past it stops before the write.
     * - [decompression]: what an open inflates, the payload and every compressed attachment value
     *   together; more is NotEnoughMemory(LIMIT).
     * - [payloadSave]: the decompressed payload a save writes, the inner header with its
     *   attachments and the XML ([payloadBytes]); more is read-only or stopped as for [save].
     * [decompression] and [payloadSave] default to [open], so limits built from [open] and [save]
     * alone give the XML and the payload one budget. Each save cap is at most the matching open
     * limit, so the read-back of a save the caps admit is never refused by its own limits.
     */
    data class Limits(val open: Int, val save: Long, val decompression: Int = open, val payloadSave: Long = decompression.toLong()) {
        companion object {
            /**
             * Returns the limits for a heap of [maxHeapBytes]: each is the heap divided by the
             * heap an open, or an open and a save, needs per byte of that content, times a margin
             * of 1.5 ([VaultSizeLimitTest] pins them). XML costs more per byte than
             * attachments, as the tree holds every node.
             */
            fun forHeap(maxHeapBytes: Long): Limits {
                fun cap(divisor: Long) = minOf(maxHeapBytes / divisor, ByteSink.MAX_CAPACITY.toLong())
                return Limits(
                    open = cap(XML_OPEN_DIVISOR).toInt(),
                    save = cap(XML_SAVE_DIVISOR),
                    decompression = cap(PAYLOAD_OPEN_DIVISOR).toInt(),
                    payloadSave = cap(PAYLOAD_SAVE_DIVISOR),
                )
            }

            // Heap per byte of content, measured as the smallest JVM heap in which each test
            // vault opens, and in which it opens and saves, with storage read as the platform
            // adapter reads it. Dense custom fields need 24 bytes of heap per byte of XML to open
            // and 56 to open, edit and save, as the opened document and the edited copy are both
            // alive; attachments gzip can't shrink need 3.4 and 5.7 per byte of payload. Each
            // divisor is that cost times 1.5, rounded up.
            private const val XML_OPEN_DIVISOR = 36L
            private const val XML_SAVE_DIVISOR = 84L
            private const val PAYLOAD_OPEN_DIVISOR = 6L
            private const val PAYLOAD_SAVE_DIVISOR = 9L
        }
    }

    /**
     * The limits of one decode: [limits] for the decrypted content, [readLimitBytes] for the file
     * and [maxHeapBytes] for the Argon2 memory guard. [cancelled] returns true once the decode's
     * caller is cancelled; [decode]'s default key derivation then stops and throws
     * CancellationException ([KdfEngine]).
     */
    class Budget(val limits: Limits, val readLimitBytes: Int, val maxHeapBytes: Long, val cancelled: () -> Boolean = { false })

    /**
     * Reads the outer header of [bytes] once ([KdbxHeaderReader]); the returned [CheckedHeader] is
     * what the KDF checks see and what [decode] derives with. The header's dictionaries are read
     * within the budget for a heap of [maxHeapBytes]; past it, or on an OutOfMemoryError, the
     * result is Invalid([Decoded.NotEnoughMemory]).
     */
    fun header(bytes: ByteArray, maxHeapBytes: Long): HeaderRead = when (val read = KdbxHeaderReader.read(bytes, maxHeapBytes)) {
        is KdbxHeaderReader.Read.Valid -> HeaderRead.Valid(CheckedHeader(read.header))
        is KdbxHeaderReader.Read.Invalid -> HeaderRead.Invalid(Decoded.of(read.result, keyChecked = false))
    }

    /**
     * Opens [bytes], whose header [header] read, with [credentials]; every hash and HMAC is
     * checked and no parameter turns a check off. [derive] receives the header's own KDF
     * parameters; the default derives with [KdfEngine] under [Budget.cancelled]. A
     * CancellationException from [derive] reaches the caller. The password-hash and key-file-part
     * copies taken from [credentials] are zero-filled before this returns. An exception after the
     * container opened is [DecodeFailure.INTERNAL], never damage.
     */
    fun decode(
        bytes: ByteArray,
        header: CheckedHeader,
        credentials: VaultKey,
        budget: Budget,
        derive: (KdbxKdfParameters, ByteArray) -> ByteArray = { parameters, key -> kdf.derive(parameters, key, budget.cancelled) },
        buffers: Buffers = Buffers.Default,
    ): Decoded {
        val result = container(bytes, header, credentials, budget, derive, buffers)
        return when (result) {
            is ContainerDecode.Result.Refused -> Decoded.Refused(result.rejection)
            is ContainerDecode.Result.Failed -> Decoded.of(result.result, keyChecked = true)
            is ContainerDecode.Result.Opened -> try {
                Decoded.Opened(document(result.read, credentials, budget.limits), result.read.container.bytesAfterEnd)
            } catch (e: CancellationException) {
                throw e
            } catch (e: OutOfMemoryError) {
                result.read.zeroFill()
                Decoded.NotEnoughMemory
            } catch (e: Exception) {
                result.read.zeroFill()
                Decoded.Failed(DecodeFailure.INTERNAL)
            }
        }
    }

    /**
     * Returns the document for [read], opened with [credentials], under [limits]: the attachment
     * list and its references from [BinaryPool.opened], the header settings a save writes again
     * ([SaveSettings]), and the saveability ([saveability]). A reference that named no item when
     * read leaves the document read-only, unless the save leaves its `Value` out
     * ([EntryParts.omitted]).
     */
    fun document(read: ContainerRead, credentials: VaultKey, limits: Limits): VaultDocument {
        val unresolved = read.references.filter { (value, attachment) -> attachment == null && value.attribute("Ref") != null }.keys
        val dangling = unresolved.isNotEmpty() && EntryParts.omitted(read.xml.root).let { omitted -> unresolved.any { !EntryParts.within(it, omitted) } }
        val attachments = BinaryPool.opened(read)
        val saveability = saveability(read.xml, read.protectedContainer, read.xmlBytes, payloadBytes(read.xmlBytes, attachments), dangling, limits)
        val settings = SaveSettings.from(read.container.header)
        return VaultDocument(read.xml, settings, attachments, credentials, read.protectedValues, read.xmlBytes, saveability)
    }

    /**
     * Returns true when [bytes] open with [credentials] as [decode] opens them, for a save's
     * read-back: [derive] derives the key, so a save passes its [SaveKeyCache] and reuses the key
     * the encode derived; [maxHeapBytes] is the heap the Argon2 guard compares with. No document
     * is built, and the decrypted XML and attachments are zero-filled before this returns.
     */
    fun readBack(
        bytes: ByteArray,
        credentials: VaultKey,
        limits: Limits,
        derive: KeyDerivation,
        maxHeapBytes: Long,
        buffers: Buffers = Buffers.Default,
    ): Boolean {
        val header = (header(bytes, maxHeapBytes) as? HeaderRead.Valid)?.header ?: return false
        val result = container(bytes, header, credentials, Budget(limits, Int.MAX_VALUE, maxHeapBytes), derive::derive, buffers)
        val opened = result as? ContainerDecode.Result.Opened ?: return false
        opened.read.zeroFill()
        return true
    }

    // Opens [bytes] with KashPass's own container and the password hash and key-file part
    // [credentials] hold; both copies are zero-filled before this returns.
    private fun container(
        bytes: ByteArray,
        header: CheckedHeader,
        credentials: VaultKey,
        budget: Budget,
        derive: (KdbxKdfParameters, ByteArray) -> ByteArray,
        buffers: Buffers,
    ): ContainerDecode.Result = credentials.withParts { passwordHash, keyFilePart ->
        ContainerDecode.decode(
            bytes, header.outer, header.kdf, passwordHash, keyFilePart, budget.limits, budget.readLimitBytes,
            maxHeapBytes = budget.maxHeapBytes, derive = derive, buffers = buffers,
        )
    }

    /**
     * Encodes [document] as KDBX 4 with [KdbxEncoder]: the document's [SaveSettings], fresh master
     * seed, IV, KDF salt or seed and inner stream key from [random], the attachments in the order
     * [BinaryPool.rebuild] gives with each changed `Ref` written through [EncodeHooks], and the
     * minor version max([MinVersion], the opened minor capped at 1): a save never lowers the
     * version, and a 4.2 or later file saves as 4.1. The written header's KDF parameters pass
     * [KdfPolicy.checkBounds] before [derive] runs; a refusal is [Encoded.Refused] with the
     * policy's rejection. [derive]'s exceptions are translated by [KdfFailure.of], as an open
     * translates them; nothing but a CancellationException escapes. The composite key and the
     * payload are zero-filled before this returns, and the document's arrays are left as they
     * are.
     */
    fun encode(
        document: VaultDocument,
        random: SecureRandom = SecureRandom(),
        derive: KeyDerivation = kdf,
        buffers: Buffers = Buffers.Default,
    ): Encoded {
        val rebuilt: BinaryPool.Rebuilt
        val minor: Int
        val composite: ByteArray
        try {
            rebuilt = BinaryPool.rebuild(document)
            minor = document.savedMinor()
            composite = document.credentials.compositeKey()
        } catch (e: CancellationException) {
            throw e
        } catch (e: OutOfMemoryError) {
            return Encoded.NotEnoughMemory
        } catch (e: Exception) {
            return Encoded.Failed
        }
        var rejection: KdfRejection? = null
        val written = Written()
        val kdfAllowed = { p: KdbxKdfParameters -> KdfPolicy.checkBounds(p.toSettings()).also { rejection = it } == null }
        val result = try {
            KdbxEncoder.encode(
                document.settings, minor, composite, kdfAllowed, derive::derive, rebuilt.attachments,
                { payload -> writeXml(document, rebuilt, payload, written) }, random, buffers,
            )
        } finally {
            composite.fill(0)
        }
        return when (result) {
            is EncodeResult.Encoded -> Encoded.Bytes(result.bytes, written.xml, written.payload)
            EncodeResult.Refused -> Encoded.Refused(rejection)
            is EncodeResult.DeriveFailed -> when (val failure = KdfFailure.of(result.cause)) {
                is KdfFailure.OutOfBounds -> Encoded.Refused(failure.rejection)
                KdfFailure.Salt -> Encoded.Refused(null)
                KdfFailure.TooLarge -> Encoded.NotEnoughMemory
                KdfFailure.Unavailable, null -> Encoded.Failed
            }
            EncodeResult.NotEnoughMemory -> Encoded.NotEnoughMemory
            is EncodeResult.Failed -> Encoded.Failed
        }
    }

    // The sizes [writeXml] wrote: the XML and the whole payload.
    private class Written {
        var xml = 0L
        var payload = 0L
    }

    // Writes the inner header and the XML into one array from [payload], records the sizes in
    // [written] and hands the array over. An array the sink outgrows goes back to [payload] at
    // once; the encoder zero-fills every array [payload] allocated, the handed-over one included.
    private fun writeXml(document: VaultDocument, rebuilt: BinaryPool.Rebuilt, payload: PayloadSink, written: Written) {
        val sink = ByteSink(payload::allocate, capacity(document, rebuilt), payload::release)
        payload.writeInnerHeader { bytes, offset, length -> sink.write(bytes, offset, length) }
        val innerHeader = sink.size
        val hooks = EncodeHooks(document, rebuilt::ref) { bytes -> payload.keystream.xor(bytes, 0, bytes.size) }
        XmlWriter.write(document.xml, sink, hooks)
        written.xml = (sink.size - innerHeader).toLong()
        written.payload = sink.size.toLong()
        payload.handOver(sink.buffer, sink.size)
    }

    // The payload of [document] as it was read with the pool [rebuilt] writes, plus room for the
    // XML its edits added: an edit appends a history snapshot of one entry. Past that room the
    // sink grows to its need plus at most [ByteSink.GROWTH_STEP].
    private fun capacity(document: VaultDocument, rebuilt: BinaryPool.Rebuilt): Int =
        minOf(payloadBytes(document.xmlBytes, rebuilt.attachments) + EDIT_ROOM + document.xmlBytes / 8, ByteSink.MAX_CAPACITY.toLong()).toInt()

    private const val EDIT_ROOM = 64L * 1024

    /**
     * Returns the decompressed payload a save of [xmlBytes] of XML with [attachments] writes: the
     * inner header ([InnerHeaderWriter.size]) and the XML. For an opened document it bounds what
     * its save writes, as a save drops attachments no entry references and never adds any.
     */
    fun payloadBytes(xmlBytes: Long, attachments: List<Attachment>): Long = InnerHeaderWriter.size(attachments) + xmlBytes

    /** Returns [payloadBytes] for [document] as it was read. */
    fun payloadBytes(document: VaultDocument): Long = payloadBytes(document.xmlBytes, document.attachments)

    /**
     * Returns whether a document read from [xmlBytes] bytes of XML, whose save writes a payload of
     * [payloadBytes], can be saved: not with a DOCTYPE, a protected element holding elements, XML
     * above [Limits.save] or a payload above [Limits.payloadSave], or an entry attachment whose
     * `Ref` named no attachment when read ([danglingReference]): a reader takes that value's own
     * content, which a save cannot keep with the reference.
     */
    internal fun saveability(xml: XmlDocument, protectedContainer: Boolean, xmlBytes: Long, payloadBytes: Long, danglingReference: Boolean, limits: Limits): Saveability {
        val reason = when {
            xml.hasDoctype -> ReadOnlyReason.DOCTYPE
            protectedContainer -> ReadOnlyReason.PROTECTED_CONTAINER
            xmlBytes > limits.save || payloadBytes > limits.payloadSave -> ReadOnlyReason.TOO_LARGE_TO_SAVE
            danglingReference -> ReadOnlyReason.ATTACHMENT_REF_OUT_OF_RANGE
            else -> null
        }
        return if (reason == null) Saveability.Saveable else Saveability.ReadOnly(reason)
    }
}

/**
 * Writes the protected values and leaves out Meta/HeaderHash and the entry parts a reader skips
 * when [document]'s XML is saved.
 *
 * Each element [VaultDocument.protectedValues] holds, and no other, gets its value's UTF-8 XORed
 * with the inner stream, as Base64. [xor] XORs its argument in place and advances the stream, so
 * the values take the stream in document order, the order in which a reader and [ContainerDecode]
 * read them. The plaintext copy is zero-filled and no String of it is made.
 *
 * Meta/HeaderHash is left out: KDBX 4 files are written without it, but a reader checks it whenever
 * present, so a stale one would make the saved file unreadable. [VaultXmlCodecTest] pins both
 * rules.
 *
 * The elements [EntryParts.omitted] lists are left out: the earlier `Key` and `Value` children of
 * an entry's `String` or `Binary`, and a `History` inside a history entry. A protected value among
 * them, or inside them, takes no stream, as no reader of the saved file reads it.
 * [VaultXmlCodecTest] pins this rule.
 *
 * An entry attachment's `Ref` is written as [refs] returns it for the `Value` element, when not
 * null ([BinaryPool.Rebuilt.ref]); the tree is not changed.
 *
 * Every `Generator` in the root `Meta` is written as [GENERATOR], and a root `Meta` without one
 * gets it as its first child; readers ignore the value. A file without a root `Meta` gets none, and
 * a `Generator` stored protected is written as it is. The tree keeps the value read.
 * [VaultXmlCodecTest] pins this rule.
 */
internal class EncodeHooks(
    private val document: VaultDocument,
    private val refs: (XmlElement) -> String? = { null },
    private val xor: (ByteArray) -> Unit,
) : XmlWriter.Hooks {

    private val root = document.xml.root
    private val omitted = EntryParts.omitted(root)

    override fun attribute(element: XmlElement, name: String): String? = if (name == "Ref") refs(element) else null

    override fun omit(element: XmlElement) =
        element in omitted || element.name == "HeaderHash" && element.parent?.name == "Meta" && element.parent?.parent === root

    override fun prepend(element: XmlElement, sink: ByteSink) {
        if (isRootMeta(element) && element.child("Generator") == null) sink.writeUtf8("<Generator>$GENERATOR</Generator>")
    }

    private fun isRootMeta(element: XmlElement?) = element != null && element.name == "Meta" && element.parent === root

    override fun content(element: XmlElement, sink: ByteSink): Boolean {
        // A Generator stored protected keeps its value: its place in the inner stream must stay.
        if (element.name == "Generator" && isRootMeta(element.parent) && element !in document.protectedValues) {
            sink.writeUtf8(GENERATOR)
            return true
        }
        val value = document.protectedValues[element] ?: return false
        val bytes = value.utf8()
        var encoded: ByteArray? = null
        try {
            xor(bytes)
            encoded = Base64.getEncoder().encode(bytes)
            sink.write(encoded)
        } finally {
            bytes.fill(0)
            encoded?.fill(0)
        }
        return true
    }

    companion object {
        /** The `Meta/Generator` text a save writes ([EncodeHooks]). */
        const val GENERATOR = "KashPass"
    }
}
