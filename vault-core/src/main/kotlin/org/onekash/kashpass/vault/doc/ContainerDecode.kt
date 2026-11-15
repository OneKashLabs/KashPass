package org.onekash.kashpass.vault.doc

import java.security.MessageDigest
import java.util.IdentityHashMap
import java.util.TreeMap
import java.util.concurrent.CancellationException
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.kdbx.Attachment
import org.onekash.kashpass.vault.kdbx.Buffers
import org.onekash.kashpass.vault.kdbx.CompositeKey
import org.onekash.kashpass.vault.kdbx.Compression
import org.onekash.kashpass.vault.kdbx.FailureCause
import org.onekash.kashpass.vault.kdbx.GzipReader
import org.onekash.kashpass.vault.kdbx.InnerStream
import org.onekash.kashpass.vault.kdbx.KdbxContainer
import org.onekash.kashpass.vault.kdbx.KdbxDamage
import org.onekash.kashpass.vault.kdbx.KdbxDecoder
import org.onekash.kashpass.vault.kdbx.KdbxException
import org.onekash.kashpass.vault.kdbx.KdbxFailure
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.kdbx.Keystream
import org.onekash.kashpass.vault.kdbx.MemoryCause
import org.onekash.kashpass.vault.kdbx.OuterHeader
import org.onekash.kashpass.vault.kdbx.Plaintext
import org.onekash.kashpass.vault.kdbx.damaged
import org.onekash.kashpass.vault.policy.KdfPolicy
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.xml.XmlDocument
import org.onekash.kashpass.vault.xml.XmlElement
import org.onekash.kashpass.vault.xml.XmlReadResult
import org.onekash.kashpass.vault.xml.XmlReader
import org.onekash.kashpass.vault.kdbx.KdfParameters as KdbxKdfParameters
import org.onekash.kashpass.vault.doc.KdbxXmlContext.Action
import org.onekash.kashpass.vault.doc.KdbxXmlContext.Context
import org.onekash.kashpass.vault.doc.KdbxXmlContext.Value

/**
 * An opened vault from KashPass's own container: the [container], the XML tree with its protected
 * values decrypted, and the attachment [pool] by ID. [references] holds, for each entry attachment
 * value, the pool item its `Ref` named when the value was read (null when it named none); a later
 * `Meta/Binaries` item can replace that ID in [pool]. [xmlBytes] is the size of the decrypted XML.
 * [protectedContainer] is true when a protected element has child elements. The container's stream
 * key is zero-filled once the protected values are read.
 *
 * The tree's source ([XmlDocument.source]) is a copy of the payload's XML range in an array of its
 * own: the payload is zero-filled and dropped before the XML is parsed, and a save copies every
 * unchanged node from the source. A document that keeps the tree keeps the array until lock drops
 * the document; nothing zero-fills it while a save can read it.
 */
internal class ContainerRead(
    val container: KdbxContainer,
    val xml: XmlDocument,
    val xmlBytes: Long,
    val protectedValues: MutableMap<XmlElement, ProtectedText>,
    val pool: TreeMap<Int, Attachment>,
    val references: Map<XmlElement, Attachment?>,
    val protectedContainer: Boolean,
) {
    /**
     * Zero-fills every plaintext the read holds: each attachment, in the pool or by a reference,
     * and the XML source. Call it only for a read no document keeps.
     */
    fun zeroFill() {
        for (a in pool.values) a.data.fill(0)
        for (a in references.values) a?.data?.fill(0)
        xml.source.bytes.fill(0)
    }
}

/**
 * Opens a vault with KashPass's own KDBX 4 container: the outer header ([KdbxHeaderReader]),
 * the KDF policy, the key derivation ([KdfEngine]), the container ([KdbxDecoder]) and the XML.
 *
 * The KDF parameters [KdbxHeaderReader] builds are the one object the KDF policy sees (as
 * [KdfSettings]) and the KDF derives with; a refusal derives nothing. The XML is read in document
 * order through the KDBX context machine ([KdbxXmlContext]), by these rules:
 * - an element read as a value, or a non-empty element skipped as unknown, takes its
 *   Base64-decoded length of the inner stream when Protected="True"; an element that switches
 *   context never does, and an attachment whose `Ref` names an item in the pool is that item,
 *   read without the stream. A protected value that is not Base64 is damage;
 * - a value element with a child element is damage;
 * - a UUID that is not empty must be Base64 of 16 bytes; a non-empty custom icon Data must be
 *   Base64; a non-empty color must be one [HtmlColor] accepts;
 * - an entry String or Binary needs a Key and a Value, and an auto-type Association a Window and a
 *   KeystrokeSequence, when its end runs: a self-closing one has no end;
 * - an entry attachment value that names no pool item must be Base64, and inflate when
 *   Compressed="True";
 * - each `Meta/Binaries/Binary` with an `ID` joins the pool under that ID, replacing an
 *   inner-header attachment of the same ID; a protected one is not decompressed; an ID that is
 *   not a non-negative integer is damage. The `Meta/Binaries` element is then dropped from the
 *   tree: a KDBX 4 file holds attachments in the inner header, so a save writes its items
 *   there;
 * - `Meta/HeaderHash`, when not empty, must be the header's SHA-256 in Base64;
 * - every time value must read as [KdbxTime.readKdbx4] reads it;
 * - an end tag in a context that does not expect it, or a document that ends with the group
 *   stack not empty, is damage. A self-closing Group pushes
 *   the stack without an end that pops it.
 * The payload and every compressed attachment value share one decompression budget,
 * [VaultXmlCodec.Limits.decompression]; the XML alone is capped at [VaultXmlCodec.Limits.open].
 * [ContainerDecodeTest] pins each rule.
 *
 * An open holds these copies of the vault, each for the time named, and no other:
 * - the file, the caller's array, for the whole open;
 * - the ciphertext of all blocks ([KdbxDecoder]), decrypted in place, until gzip has inflated it;
 *   without gzip it is the payload;
 * - the payload, until the attachments and the XML are copied out of it;
 * - the attachments and the XML copy the tree reads, which the document keeps until lock.
 * So the file, the ciphertext and the payload are held together only while gzip inflates, and the
 * payload and the tree never are.
 */
internal object ContainerDecode {

    /** The outcome of [decode]. */
    sealed interface Result {
        class Opened(val read: ContainerRead) : Result

        /** The KDF policy refused the settings; nothing was derived. */
        data class Refused(val rejection: KdfRejection) : Result

        /** Any other outcome of the container: never [KdbxResult.Opened]. */
        data class Failed(val result: KdbxResult) : Result
    }

    private val engine = KdfEngine()

    /**
     * Opens [bytes] with the password hash and key-file part given (either can be null, not
     * both); both stay the caller's. [readLimitBytes] is the device's read limit: a larger input is
     * [KdbxResult.TooLarge]. Reads the header with [KdbxHeaderReader], its dictionaries within the
     * budget for a heap of [maxHeapBytes], and decodes as the other [decode] does.
     */
    fun decode(
        bytes: ByteArray,
        passwordHash: ByteArray?,
        keyFilePart: ByteArray?,
        limits: VaultXmlCodec.Limits,
        readLimitBytes: Int,
        kdfPolicy: (KdfSettings) -> KdfRejection? = KdfPolicy::checkBounds,
        maxHeapBytes: Long = Runtime.getRuntime().maxMemory(),
        derive: (KdbxKdfParameters, ByteArray) -> ByteArray = engine::derive,
        buffers: Buffers = Buffers.Default,
        onXml: (ByteArray, Int, Int) -> Unit = { _, _, _ -> },
    ): Result {
        if (bytes.size > readLimitBytes) return Result.Failed(KdbxResult.TooLarge(readLimitBytes))
        val header = when (val read = KdbxHeaderReader.read(bytes, maxHeapBytes)) {
            is KdbxHeaderReader.Read.Invalid -> return Result.Failed(read.result)
            is KdbxHeaderReader.Read.Valid -> read.header
        }
        return decode(bytes, header, header.kdf.toSettings(), passwordHash, keyFilePart, limits, readLimitBytes, kdfPolicy, maxHeapBytes, derive, buffers, onXml)
    }

    /**
     * Opens [bytes], whose outer header [KdbxHeaderReader] read as [header], with [settings] the
     * caller built from that header's KDF parameters; the header is not read again. [kdfPolicy]
     * sees [settings] (an opener has run the bounds and the downgrade comparison on the same
     * object); Argon2 memory above half of [maxHeapBytes] is not enough memory, before any
     * derivation; [derive] is the KDF and receives the header's own [KdbxKdfParameters]. [onXml]
     * sees the decrypted XML bytes in the payload, for tests that compare them; the payload is
     * zero-filled once the XML is copied out, before parsing, so [onXml] copies what it keeps. An
     * opened read's tree owns a copy of the XML ([ContainerRead]).
     */
    fun decode(
        bytes: ByteArray,
        header: OuterHeader,
        settings: KdfSettings,
        passwordHash: ByteArray?,
        keyFilePart: ByteArray?,
        limits: VaultXmlCodec.Limits,
        readLimitBytes: Int,
        kdfPolicy: (KdfSettings) -> KdfRejection? = KdfPolicy::checkBounds,
        maxHeapBytes: Long = Runtime.getRuntime().maxMemory(),
        derive: (KdbxKdfParameters, ByteArray) -> ByteArray = engine::derive,
        buffers: Buffers = Buffers.Default,
        onXml: (ByteArray, Int, Int) -> Unit = { _, _, _ -> },
    ): Result {
        if (bytes.size > readLimitBytes) return Result.Failed(KdbxResult.TooLarge(readLimitBytes))
        kdfPolicy(settings)?.let { return Result.Refused(it) }
        // Argon2 allocates its memory at once; near the heap limit that succeeds and then fails
        // in another thread's allocation.
        if (settings is KdfSettings.Argon2 && KdfPolicy.argon2MemoryUsedBytes(settings).toLong() > maxHeapBytes / 2) {
            return Result.Failed(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT))
        }
        val composite = try {
            CompositeKey.compute(passwordHash, keyFilePart)
        } catch (e: KdbxException) {
            return Result.Failed(KdbxResult.Failed(FailureCause.INTERNAL))
        }
        var refused: KdfRejection? = null
        val result = try {
            KdbxDecoder.decode(bytes, header, composite, translated(derive) { refused = it }, limits.decompression, buffers)
        } finally {
            composite.fill(0)
        }
        refused?.let { return Result.Refused(it) }
        if (result !is KdbxResult.Opened) return Result.Failed(result)
        val container = result.container
        return result.plaintext.use { plaintext ->
            try {
                Result.Opened(readXml(bytes, container, plaintext, limits, buffers, onXml))
            } catch (e: Throwable) {
                container.inner.streamKey.fill(0)
                for (a in container.inner.attachments) a.data.fill(0)
                when (e) {
                    is CancellationException -> throw e
                    is KdbxFailure -> Result.Failed(e.result)
                    is KdbxException.InflatedTooLarge -> Result.Failed(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT))
                    is KdbxException.AlgorithmUnavailable -> Result.Failed(KdbxResult.Failed(FailureCause.PLATFORM))
                    is OutOfMemoryError -> Result.Failed(KdbxResult.NotEnoughMemory(MemoryCause.OUT_OF_MEMORY))
                    else -> Result.Failed(KdbxResult.Failed(FailureCause.INTERNAL))
                }
            }
        }
    }

    // KdfEngine's failures ([KdfFailure]) as the container's types, so the decoder maps them; a
    // bounds refusal is passed to [refused] and reported as such.
    private fun translated(
        derive: (KdbxKdfParameters, ByteArray) -> ByteArray,
        refused: (KdfRejection) -> Unit,
    ): (KdbxKdfParameters, ByteArray) -> ByteArray = { parameters, composite ->
        try {
            derive(parameters, composite)
        } catch (e: Exception) {
            when (val failure = KdfFailure.of(e)) {
                is KdfFailure.OutOfBounds -> {
                    refused(failure.rejection)
                    throw KdbxException.KdfParametersInvalid()
                }
                KdfFailure.Salt -> throw KdbxException.KdfParametersInvalid()
                KdfFailure.TooLarge -> throw KdbxException.DerivationTooLarge()
                KdfFailure.Unavailable -> throw KdbxException.AlgorithmUnavailable()
                null -> throw e
            }
        }
    }

    // Copies [plaintext]'s XML range into an array the tree owns, closes [plaintext] so the
    // payload is zero-filled and can be collected before the tree is built, and reads the copy;
    // a failure zero-fills the copy. The payload and the copy are held together only for the
    // copy itself.
    private fun readXml(
        bytes: ByteArray,
        container: KdbxContainer,
        plaintext: Plaintext,
        limits: VaultXmlCodec.Limits,
        buffers: Buffers,
        onXml: (ByteArray, Int, Int) -> Unit,
    ): ContainerRead {
        onXml(plaintext.buffer, plaintext.xmlOffset, plaintext.xmlLength)
        val length = plaintext.xmlLength
        if (length > limits.open) throw KdbxFailure(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT))
        val source = buffers.bytes(length)
        plaintext.buffer.copyInto(source, 0, plaintext.xmlOffset, plaintext.xmlOffset + length)
        // The payload's own decompression comes out of the same budget as the attachment values.
        val inflated = if (container.header.compression == Compression.GZIP) plaintext.xmlOffset.toLong() + length else 0L
        plaintext.close()
        try {
            return parseXml(bytes, container, source, inflated, limits, buffers)
        } catch (e: Throwable) {
            source.fill(0)
            throw e
        }
    }

    // Reads the XML in [source], the copy of the payload's XML range; [inflated] bytes of the
    // decompression budget are spent.
    private fun parseXml(
        bytes: ByteArray,
        container: KdbxContainer,
        source: ByteArray,
        inflated: Long,
        limits: VaultXmlCodec.Limits,
        buffers: Buffers,
    ): ContainerRead {
        val xml = when (val parsed = XmlReader.read(source, 0, source.size, limits.open)) {
            is XmlReadResult.Parsed -> parsed.document
            XmlReadResult.TooLarge -> throw KdbxFailure(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT))
            is XmlReadResult.Malformed -> damaged(KdbxDamage.XML)
        }
        val root = xml.root
        if (root.name != "KeePassFile" || rootGroupOf(root) == null) damaged(KdbxDamage.XML)
        val header = container.header
        // The decoder checked that the stored hash is the header's SHA-256.
        val headerHash = bytes.copyOfRange(header.length, header.length + 32)
        val pool = TreeMap<Int, Attachment>()
        container.inner.attachments.forEachIndexed { i, a -> pool[i] = a }
        var walking: Walk? = null
        val walk = try {
            InnerStream.open(container.inner.streamId, container.inner.streamKey, buffers).use { stream ->
                Walk(stream, headerHash, pool, limits.decompression - inflated, buffers).also {
                    walking = it
                    it.document(root)
                }
            }
        } catch (e: Throwable) {
            // Items from Meta/Binaries are plaintext only the pool and the references hold.
            for (a in pool.values) a.data.fill(0)
            walking?.references?.values?.forEach { it?.data?.fill(0) }
            throw e
        }
        container.inner.streamKey.fill(0)
        for (meta in root.children("Meta")) {
            for (binaries in meta.children("Binaries")) {
                forEach(binaries) { walk.values.remove(it) }
                meta.remove(binaries)
            }
        }
        return ContainerRead(container, xml, source.size.toLong(), walk.values, pool, walk.references, walk.container)
    }

    private fun forEach(element: XmlElement, action: (XmlElement) -> Unit) {
        action(element)
        for (child in element.elements()) forEach(child, action)
    }

    private class Walk(
        private val stream: Keystream,
        private val headerHash: ByteArray,
        private val pool: TreeMap<Int, Attachment>,
        private var budget: Long,
        private val buffers: Buffers,
    ) {
        val values = HashMap<XmlElement, ProtectedText>()
        val references = IdentityHashMap<XmlElement, Attachment?>()
        var container = false

        // Reader state: whether the current entry is a history entry, the group depth, and whether
        // the current String, Binary and Association have read their parts.
        private var inHistory = false
        private var groups = 0
        private var stringKey = false
        private var stringValue = false
        private var binaryKey = false
        private var binaryValue = false
        private var window = false
        private var keystrokes = false

        /** Reads [root] from [Context.NULL]; damage unless it ends there with no group open. */
        fun document(root: XmlElement) {
            val end = element(root, Context.NULL)
            if (end != Context.NULL || groups != 0) damaged(KdbxDamage.XML)
        }

        // Returns the context after [e], which the reader met in [ctx].
        private fun element(e: XmlElement, ctx: Context): Context {
            when (val action = KdbxXmlContext.action(ctx, e.name, inHistory, e.attribute("ID") != null)) {
                is Action.Read -> read(e, action.value)
                Action.Unknown -> unknown(e)
                is Action.Switch -> {
                    beforeSwitch(ctx, action.to)
                    // Protected is ignored on these; the encoder would replace the children.
                    if (isProtected(e) && e.hasElementChildren) container = true
                    if (e.selfClosing) return ctx
                    var current = action.to
                    for (child in e.elements()) current = element(child, current)
                    return end(current, e.name)
                }
            }
            return ctx
        }

        // State changes on entering [to] from [ctx]; they run for a self-closing element too.
        private fun beforeSwitch(ctx: Context, to: Context) {
            when {
                ctx == Context.ROOT && to == Context.GROUP -> {
                    if (groups != 0) damaged(KdbxDamage.XML)
                    groups = 1
                }
                ctx == Context.GROUP && to == Context.GROUP -> groups++
                ctx == Context.GROUP && to == Context.ENTRY -> inHistory = false
                ctx == Context.ENTRY_HISTORY && to == Context.ENTRY -> inHistory = true
            }
        }

        // Returns the context after the end tag [name] in [ctx], or damage.
        private fun end(ctx: Context, name: String): Context = when {
            ctx == Context.KEEPASS_FILE && name == "KeePassFile" -> Context.NULL
            (ctx == Context.META && name == "Meta") || (ctx == Context.ROOT && name == "Root") -> Context.KEEPASS_FILE
            (ctx == Context.MEMORY_PROTECTION && name == "MemoryProtection") || (ctx == Context.CUSTOM_ICONS && name == "CustomIcons") ||
                (ctx == Context.BINARIES && name == "Binaries") || (ctx == Context.CUSTOM_DATA && name == "CustomData") -> Context.META
            ctx == Context.CUSTOM_ICON && name == "Icon" -> Context.CUSTOM_ICONS
            ctx == Context.CUSTOM_DATA_ITEM && name == "Item" -> Context.CUSTOM_DATA
            ctx == Context.GROUP && name == "Group" -> if (--groups == 0) Context.ROOT else Context.GROUP
            (ctx == Context.GROUP_TIMES && name == "Times") || (ctx == Context.GROUP_CUSTOM_DATA && name == "CustomData") -> Context.GROUP
            ctx == Context.GROUP_CUSTOM_DATA_ITEM && name == "Item" -> Context.GROUP_CUSTOM_DATA
            ctx == Context.ENTRY && name == "Entry" -> if (inHistory) Context.ENTRY_HISTORY else Context.GROUP
            (ctx == Context.ENTRY_TIMES && name == "Times") || (ctx == Context.ENTRY_AUTO_TYPE && name == "AutoType") ||
                (ctx == Context.ENTRY_CUSTOM_DATA && name == "CustomData") -> Context.ENTRY
            ctx == Context.ENTRY_STRING && name == "String" -> {
                // A String without a Key or a Value is damage.
                if (!stringKey || !stringValue) damaged(KdbxDamage.XML)
                stringKey = false
                stringValue = false
                Context.ENTRY
            }
            ctx == Context.ENTRY_BINARY && name == "Binary" -> {
                if (!binaryKey || !binaryValue) damaged(KdbxDamage.XML)
                binaryKey = false
                binaryValue = false
                Context.ENTRY
            }
            ctx == Context.ENTRY_AUTO_TYPE_ITEM && name == "Association" -> {
                // An Association without a Window or a KeystrokeSequence is damage.
                if (!window || !keystrokes) damaged(KdbxDamage.XML)
                window = false
                keystrokes = false
                Context.ENTRY_AUTO_TYPE
            }
            ctx == Context.ENTRY_CUSTOM_DATA_ITEM && name == "Item" -> Context.ENTRY_CUSTOM_DATA
            ctx == Context.ENTRY_HISTORY && name == "History" -> {
                inHistory = false
                Context.ENTRY
            }
            ctx == Context.ROOT_DELETED_OBJECTS && name == "DeletedObjects" -> Context.ROOT
            ctx == Context.DELETED_OBJECT && name == "DeletedObject" -> Context.ROOT_DELETED_OBJECTS
            else -> damaged(KdbxDamage.XML)
        }

        // An unknown element: a non-empty protected one is read through [processNode] and its
        // children skipped; any other non-empty one is searched for protected ones.
        private fun unknown(e: XmlElement) {
            if (e.selfClosing) return
            val plain = processNode(e)
            if (plain != null) {
                values[e] = ProtectedText.fromUtf8(plain)
                return
            }
            for (child in e.elements()) unknown(child)
        }

        // The plaintext of a protected element, which takes the inner stream, or null for one that
        // is not protected. A protected element with a child element is damage.
        private fun processNode(e: XmlElement): ByteArray? {
            if (!isProtected(e)) return null
            if (e.hasElementChildren) damaged(KdbxDamage.XML)
            val plain = ConvertBase64.decode(e.text()) ?: damaged(KdbxDamage.PROTECTED_VALUE)
            stream.xor(plain, 0, plain.size)
            return plain
        }

        private fun read(e: XmlElement, value: Value) {
            when (value) {
                Value.BINARY_VALUE -> {
                    references[e] = binaryValue(e)
                    binaryValue = true
                }
                Value.META_BINARY -> pooled(e, metaBinary(e))
                Value.TEXT -> readValue(e)
                Value.STRING_KEY -> readValue(e).also { stringKey = true }
                Value.STRING_VALUE -> readValue(e).also { stringValue = true }
                Value.BINARY_KEY -> readValue(e).also { binaryKey = true }
                Value.WINDOW -> readValue(e).also { window = true }
                Value.KEYSTROKES -> readValue(e).also { keystrokes = true }
                Value.UUID -> {
                    val text = readText(e)
                    if (text.isNotEmpty()) {
                        val bytes = ConvertBase64.decode(text) ?: damaged(KdbxDamage.XML)
                        // A UUID is exactly 16 bytes; an empty value reads as zeros.
                        if (bytes.isNotEmpty() && bytes.size != 16) damaged(KdbxDamage.XML)
                    }
                }
                Value.TIME -> KdbxTime.readKdbx4(readText(e)) ?: damaged(KdbxDamage.DATE)
                Value.COLOR -> if (!HtmlColor.accepts(readText(e))) damaged(KdbxDamage.XML)
                Value.ICON_DATA -> readText(e).let { if (it.isNotEmpty() && ConvertBase64.decode(it) == null) damaged(KdbxDamage.XML) }
                Value.HEADER_HASH -> checkHeaderHash(readText(e))
            }
        }

        // Reads a value kept as text: a protected one is kept as a [ProtectedText], with no String
        // of its plaintext.
        private fun readValue(e: XmlElement) {
            val plain = processNode(e)
            if (plain != null) {
                values[e] = ProtectedText.fromUtf8(plain)
            } else if (e.hasElementChildren) {
                damaged(KdbxDamage.XML)
            }
        }

        // The text of a value the reader parses (a UUID, time, color, icon data or header hash): a
        // protected one decrypted, an unprotected one as [XmlElement.text] reads it.
        private fun readText(e: XmlElement): String {
            val plain = processNode(e) ?: run {
                if (e.hasElementChildren) damaged(KdbxDamage.XML)
                return e.text()
            }
            return plain.decodeToString().also { values[e] = ProtectedText.fromUtf8(plain) }
        }

        private fun checkHeaderHash(text: String) {
            if (text.isEmpty()) return
            val stored = ConvertBase64.decode(text) ?: damaged(KdbxDamage.XML_HEADER_HASH)
            if (!MessageDigest.isEqual(stored, headerHash)) damaged(KdbxDamage.XML_HEADER_HASH)
        }

        // The pool item a non-empty integer Ref names, read without the stream; such an element
        // with a child element is damage.
        private fun resolved(e: XmlElement): Attachment? {
            val item = ref(e)?.let(pool::get) ?: return null
            if (e.hasElementChildren) damaged(KdbxDamage.XML)
            return item
        }

        // An entry attachment value: the pool item its Ref names (null when it names none). One
        // that names none is read from its own text; KashPass keeps its reference.
        private fun binaryValue(e: XmlElement): Attachment? {
            resolved(e)?.let { return it }
            val plain = processNode(e)
            if (plain != null) {
                values[e] = ProtectedText.fromUtf8(plain)
            } else {
                plainBinary(e, KdbxDamage.XML).data.fill(0)
            }
            return null
        }

        private fun metaBinary(e: XmlElement): Attachment =
            resolved(e) ?: processNode(e)?.let { Attachment(true, owned(it)) } ?: plainBinary(e, KdbxDamage.META_BINARY)

        // An unprotected attachment value: Base64, decompressed when Compressed="True". Bad
        // content is damage at [layer].
        private fun plainBinary(e: XmlElement, layer: KdbxDamage): Attachment {
            if (e.hasElementChildren) damaged(KdbxDamage.XML)
            val raw = ConvertBase64.decode(e.text()) ?: damaged(layer)
            if (raw.isEmpty() || e.attribute("Compressed") != "True") return Attachment(false, owned(raw))
            if (budget < 1) throw KdbxFailure(KdbxResult.NotEnoughMemory(MemoryCause.LIMIT))
            val inflated = try {
                GzipReader.inflate(raw, 0, raw.size, minOf(budget, Int.MAX_VALUE.toLong()).toInt(), buffers)
            } catch (x: KdbxException.CompressedData) {
                damaged(layer)
            } finally {
                raw.fill(0)
            }
            budget -= inflated.size
            val data = inflated.bytes.copyOf(inflated.size)
            inflated.bytes.fill(0)
            return Attachment(false, data)
        }

        private fun pooled(e: XmlElement, attachment: Attachment) {
            val id = parseInt32Invariant(e.attribute("ID"))
            if (id == null || id < 0) {
                if (pool.values.none { it === attachment }) attachment.data.fill(0)
                damaged(KdbxDamage.META_BINARY)
            }
            val replaced = pool.put(id, attachment)
            // A replaced item's plaintext is unreachable once neither the pool nor a reference read
            // before the replacement holds it.
            if (replaced != null && pool.values.none { it === replaced } && references.values.none { it === replaced }) {
                replaced.data.fill(0)
            }
        }

        // Moves [bytes] into an array from [buffers], so zeroing checks see it, and zero-fills
        // [bytes].
        private fun owned(bytes: ByteArray): ByteArray = buffers.bytes(bytes.size).also {
            bytes.copyInto(it)
            bytes.fill(0)
        }

        private fun ref(e: XmlElement): Int? = e.attribute("Ref")?.takeIf { it.isNotEmpty() }?.let(::parseInt32Invariant)

        private fun isProtected(e: XmlElement) = e.attribute("Protected") == "True"
    }

}

/**
 * Parses [text] as a 32-bit integer: surrounding white space, an optional sign, ASCII digits; null
 * otherwise or past Int32.
 */
internal fun parseInt32Invariant(text: String?): Int? {
    if (text == null) return null
    val t = text.trim { it == ' ' || it in '\t'..'\r' }
    if (!INVARIANT_INTEGER.matches(t)) return null
    return t.toIntOrNull()
}

private val INVARIANT_INTEGER = Regex("[+-]?[0-9]+")
