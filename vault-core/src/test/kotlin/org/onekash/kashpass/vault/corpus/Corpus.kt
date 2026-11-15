package org.onekash.kashpass.vault.corpus

import kotlin.random.Random
import org.onekash.kashpass.vault.fixtures.CredentialMode
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.Gzip
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.KdbxToolkit.Block
import org.onekash.kashpass.vault.testing.KdbxToolkit.Layers
import org.onekash.kashpass.vault.testing.KdbxToolkit.beforeEnd
import org.onekash.kashpass.vault.testing.KdbxToolkit.editBlock
import org.onekash.kashpass.vault.testing.KdbxToolkit.replaceFirst
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawEntry
import org.onekash.kashpass.vault.testing.RawField
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.testing.le32
import org.onekash.kashpass.vault.testing.le64
import org.onekash.kashpass.vault.testing.uuidBytes

/** The recipes of [Corpus]: base vaults opened from the fixtures and every case built from them. */
internal class CorpusRecipes {

    private val O = Seen.OPEN
    private val R = Seen.REFUSE
    // A case built in a loop, under its name.
    private fun recordedCase(
        name: String,
        keepass2: Seen,
        spec: Spec,
        same: String? = BASE,
        windows: Seen? = null,
        windowsReason: String? = null,
        make: () -> ByteArray,
    ) = case(
        name, keepass2, spec, same = same, windows = windows, windowsReason = windowsReason, make = make,
    )

    /** Names in the damage table that no case in [built] has. */
    fun unknownRecordedNames(built: Set<String>): Set<String> = DAMAGE.keys - built

    // The damage layer of each named DAMAGED case.
    private val DAMAGE = mapOf(
        "xml-uuid-not-base64" to "XML",
        "xml-uuid-12-bytes" to "XML",
        "xml-value-with-child-element" to "XML",
        "xml-protected-value-with-child-element" to "XML",
        "xml-icon-data-not-base64" to "XML",
        "xml-color-not-a-color" to "XML",
        "xml-color-hash-not-hex" to "XML",
        "xml-string-without-key" to "XML",
        "xml-string-without-value" to "XML",
        "xml-binary-without-key" to "XML",
        "xml-binary-without-value" to "XML",
        "xml-association-without-window" to "XML",
        "xml-association-without-sequence" to "XML",
        "xml-binary-inline-not-base64" to "XML",
        "xml-binary-ref-missing-not-base64" to "XML",
        "xml-group-self-closing-in-group" to "XML",
        "xml-group-self-closing-in-root" to "XML",
        "kdf-missing-uuid-before-valid-kdf" to "KDF_PARAMETERS",
        "attachment-no-flag-byte" to "INNER_HEADER",
        "block-0-data-flipped" to "BLOCK_HMAC",
        "block-0-hmac-flipped" to "BLOCK_HMAC",
        "block-0-length-huge" to "BLOCK_LENGTH",
        "block-0-length-min" to "BLOCK_LENGTH",
        "block-0-length-minus-1" to "BLOCK_HMAC",
        "block-0-length-negative" to "BLOCK_LENGTH",
        "block-0-length-plus-1" to "BLOCK_HMAC",
        "block-end-hmac-wrong" to "BLOCK_HMAC",
        "block-end-hmac-wrong-chacha20" to "BLOCK_HMAC",
        "block-end-length-huge" to "BLOCK_LENGTH",
        "block-end-length-min" to "BLOCK_LENGTH",
        "block-end-length-negative" to "BLOCK_LENGTH",
        "block-missing-end" to "END_BLOCK_MISSING",
        "block-missing-end-chacha20" to "END_BLOCK_MISSING",
        "block-multi-1-data-flipped" to "BLOCK_HMAC",
        "block-multi-1-hmac-flipped" to "BLOCK_HMAC",
        "block-multi-1-length-minus-1" to "BLOCK_HMAC",
        "block-multi-first-dropped" to "BLOCK_HMAC",
        "block-multi-first-repeated" to "BLOCK_HMAC",
        "block-multi-swapped" to "BLOCK_HMAC",
        "cipher-aes-ciphertext-not-block-multiple" to "CIPHERTEXT_LENGTH",
        "cipher-aes-iv-12-bytes" to "HEADER_FIELD",
        "cipher-chacha20-iv-16-bytes" to "HEADER_FIELD",
        "compression-gzip-with-plain-content" to "COMPRESSED_DATA",
        "compression-none-with-gzip-content" to "INNER_HEADER",
        "dict-bool-of-2-bytes" to "KDF_PARAMETERS",
        "dict-entry-0-length-huge" to "KDF_PARAMETERS",
        "dict-entry-0-length-negative" to "KDF_PARAMETERS",
        "dict-entry-1-length-huge" to "KDF_PARAMETERS",
        "dict-entry-1-length-negative" to "KDF_PARAMETERS",
        "dict-entry-2-length-huge" to "KDF_PARAMETERS",
        "dict-entry-2-length-negative" to "KDF_PARAMETERS",
        "dict-rounds-uint64-then-uint32" to "KDF_PARAMETERS",
        "dict-uint32-of-5-bytes" to "KDF_PARAMETERS",
        "dict-uuid-15-bytes" to "KDF_PARAMETERS",
        "gzip-crc-wrong" to "COMPRESSED_DATA",
        "gzip-cut-inside-member" to "XML",
        "gzip-isize-wrong" to "COMPRESSED_DATA",
        "gzip-two-members-content-split" to "XML",
        "header-cipher-id-15-bytes" to "HEADER_FIELD",
        "header-cipher-id-17-bytes" to "HEADER_FIELD",
        "header-compression-3-bytes" to "HEADER_FIELD",
        "header-compression-5-bytes" to "HEADER_FIELD",
        "header-compression-missing-plain-content" to "COMPRESSED_DATA",
        "header-field-0-id-2-length-huge" to "TRUNCATED",
        "header-field-0-id-2-length-negative" to "HEADER_FIELD",
        "header-field-1-id-3-length-huge" to "TRUNCATED",
        "header-field-1-id-3-length-negative" to "HEADER_FIELD",
        "header-field-2-id-4-length-huge" to "TRUNCATED",
        "header-field-2-id-4-length-negative" to "HEADER_FIELD",
        "header-field-3-id-11-length-huge" to "TRUNCATED",
        "header-field-3-id-11-length-negative" to "HEADER_FIELD",
        "header-field-4-id-7-length-huge" to "TRUNCATED",
        "header-field-4-id-7-length-negative" to "HEADER_FIELD",
        "header-field-5-id-0-length-huge" to "TRUNCATED",
        "header-field-5-id-0-length-negative" to "HEADER_FIELD",
        "header-iv-missing" to "HEADER_FIELD",
        "header-iv-repeated-different" to "COMPRESSED_DATA",
        "header-seed-31-bytes" to "HEADER_FIELD",
        "header-seed-33-bytes" to "HEADER_FIELD",
        "header-sha256-wrong" to "HEADER_HASH",
        "inner-field-0-id-1-length-huge" to "INNER_HEADER",
        "inner-field-0-id-1-length-negative" to "INNER_HEADER",
        "inner-field-1-id-2-length-huge" to "INNER_HEADER",
        "inner-field-1-id-2-length-negative" to "INNER_HEADER",
        "inner-field-2-id-3-length-huge" to "INNER_HEADER",
        "inner-field-2-id-3-length-negative" to "INNER_HEADER",
        "inner-field-3-id-0-length-huge" to "INNER_HEADER",
        "inner-field-3-id-0-length-negative" to "INNER_HEADER",
        "inner-stream-id-5-bytes" to "INNER_STREAM",
        "inner-stream-key-empty" to "INNER_STREAM",
        "inner-stream-key-in-neither-header" to "INNER_STREAM",
        "kdbx3-no-kdf-at-all" to "KDF_PARAMETERS",
        "kdbx3-rounds-after-argon2" to "KDF_PARAMETERS",
        "kdf-argon2-salt-7-bytes" to "KDF_PARAMETERS",
        "padding-0" to "PADDING",
        "padding-17" to "PADDING",
        "padding-inconsistent" to "PADDING",
        "spec-block-early-end" to "PADDING",
        "spec-date-iso" to "DATE",
        "spec-date-not-base64" to "DATE",
        "spec-date-seconds-negative" to "DATE",
        "spec-date-seconds-past-9999" to "DATE",
        "spec-dict-name-length-huge" to "KDF_PARAMETERS",
        "spec-dict-name-length-negative" to "KDF_PARAMETERS",
        "spec-dict-no-terminator" to "KDF_PARAMETERS",
        "spec-header-end-missing" to "TRUNCATED",
        "spec-inner-end-missing" to "INNER_HEADER",
        "spec-inner-protected-not-base64" to "PROTECTED_VALUE",
        "spec-meta-binary-id-negative" to "META_BINARY",
        "spec-meta-binary-id-not-integer" to "META_BINARY",
        "spec-public-custom-data-empty" to "HEADER_FIELD",
        "spec-signature-1-wrong" to "NOT_A_KDBX_FILE",
        "spec-signature-2-wrong" to "NOT_A_KDBX_FILE",
        "xml-garbage-after-root" to "XML",
        "xml-header-hash-not-base64" to "XML_HEADER_HASH",
        "xml-declaration-junk-token" to "XML",
        "xml-declaration-element-text-inside" to "XML",
        "xml-declaration-no-version" to "XML",
        "xml-declaration-version-1-1" to "XML",
        "xml-declaration-standalone-before-encoding" to "XML",
        "xml-declaration-standalone-maybe" to "XML",
        "xml-declaration-unquoted-version" to "XML",
        "xml-declaration-encoding-unknown" to "XML",
        "xml-header-hash-wrong" to "XML_HEADER_HASH",
        "xml-nul-after-root" to "XML",
    )

    private val key = KdbxToolkit.Key(TestFiles.password)
    private fun open(name: String) = KdbxToolkit.open(Fixtures.bytes(name), key)

    // AES-256, AES-KDF 6,000 rounds, gzip, one data block, one 20-byte attachment.
    private val weak by lazy { open("keepass2-weak-aeskdf-6000.kdbx") }

    // The same vault re-encrypted under ChaCha20 with a 12-byte IV.
    private val chacha by lazy {
        val h = weak.layers.header.withField(RawKdbx.CIPHER_ID, uuidBytes(KdbxToolkit.CHACHA20_CIPHER))
            .withField(RawKdbx.ENCRYPTION_IV, Random(11).nextBytes(12))
        KdbxToolkit.open(KdbxToolkit.build(weak.layers.copy(header = h)), key)
    }

    // Two data blocks: a 1.2 MiB attachment.
    private val multi by lazy { open("keepass2-multiblock-attachment.kdbx") }

    private val noCompression by lazy { open("keepass2-compression-none.kdbx") }

    // The weak vault re-keyed with a small in-bounds Argon2id (1 MiB, one lane, 2 iterations).
    private val argon2 by lazy {
        val h = weak.layers.header.withKdf { argon2Dictionary() }
        KdbxToolkit.open(KdbxToolkit.build(weak.layers.copy(header = h)), key)
    }

    private val weakKdf by lazy { RawDictionary.parse(weak.layers.header.field(RawKdbx.KDF_PARAMETERS)) }

    // The AES fixture with KDF parameters [dict]; [deriveFromOriginal] keys it with the original
    // settings, for parameters no reader derives.
    private fun weakWithKdf(dict: RawDictionary, deriveFromOriginal: Boolean = false): ByteArray {
        val h = weak.layers.header
        return KdbxToolkit.build(weak.layers.copy(header = h.withField(RawKdbx.KDF_PARAMETERS, dict.toBytes()), kdfHeader = if (deriveFromOriginal) h else null))
    }

    private fun argon2Dictionary(salt: ByteArray = Random(12).nextBytes(32), extra: List<RawEntry> = emptyList()) = RawDictionary(
        0x0100,
        listOf(
            RawEntry(RawDictionary.BYTES, "\$UUID", uuidBytes(KdbxToolkit.ARGON2ID)),
            RawEntry(RawDictionary.BYTES, "S", salt),
            RawEntry(RawDictionary.UINT32, "P", le32(1)),
            RawEntry(RawDictionary.UINT64, "M", le64(1024L * 1024L)),
            RawEntry(RawDictionary.UINT64, "I", le64(2L)),
            RawEntry(RawDictionary.UINT32, "V", le32(0x13)),
        ) + extra,
    )

    private fun aesDictionary(rounds: Long, seed: ByteArray) = RawDictionary(
        0x0100,
        listOf(
            RawEntry(RawDictionary.BYTES, "\$UUID", uuidBytes(KdbxToolkit.AES_KDF)),
            RawEntry(RawDictionary.UINT64, "R", le64(rounds)),
            RawEntry(RawDictionary.BYTES, "S", seed),
        ),
    )


    private fun Layers.innerWith(transform: (List<RawField>) -> List<RawField>) = copy(inner = transform(inner))

    private fun Layers.xmlEdit(transform: (String) -> String) =
        copy(xml = transform(String(xml, Charsets.ISO_8859_1)).toByteArray(Charsets.ISO_8859_1))

    private fun flip(b: ByteArray, at: Int) = b.copyOf().also { it[at] = (it[at].toInt() xor 0x01).toByte() }

    private val cases = mutableListOf<CorpusCase>()

    // The base case of the AES fixture; most cases must report its content when KeePass 2 opens
    // them.
    private val BASE = "block-baseline-aes"
    private val MULTI = "block-multi-baseline"

    private fun case(
        name: String,
        keepass2: Seen,
        spec: Spec,
        same: String? = BASE,
        policy: Int? = null,
        mode: CredentialMode = CredentialMode.PASSWORD,
        keyFileName: String? = null,
        keyFile: ByteArray? = null,
        windows: Seen? = null,
        windowsReason: String? = null,
        heap: Long? = null,
        make: () -> ByteArray,
    ) {
        val damage = DAMAGE[name] ?: if (spec == Spec.DAMAGED) truncationDamage(name) else null
        cases += CorpusCase(name, keepass2, spec, same.takeIf { it != name }, policy, mode, keyFileName, keyFile, windows, windowsReason, damage, heap, make)
    }

    // A cut is damage at the layer it falls in: inside the header, its hash or its HMAC; inside a
    // block's HMAC and length; or inside a block's data. The bases are the AES and multi-block
    // vaults.
    private fun truncationDamage(name: String): String? {
        val match = Regex("""^truncated-(multi-)?at-(\d+)$""").find(name) ?: return null
        val split = if (match.groupValues[1].isEmpty()) weakSplit else multiSplit
        val cut = match.groupValues[2].toInt()
        var at = split.headerBytes.size + 64
        if (cut < at) return "TRUNCATED"
        for (block in split.blocks) {
            if (cut < at + 36) return "END_BLOCK_MISSING"
            if (cut < at + 36 + block.data.size) return "BLOCK_LENGTH"
            at += 36 + block.data.size
        }
        error("$name: the cut is past the end block")
    }

    private val weakSplit by lazy { KdbxToolkit.split(KdbxToolkit.build(weak.layers)) }
    private val multiSplit by lazy { KdbxToolkit.split(KdbxToolkit.build(multi.layers)) }

    /** Builds every case, in a fixed order, from the fixtures. */
    fun build(): List<CorpusCase> {
        blockStream()
        outerHeader()
        kdbx3Fields()
        dictionary()
        cipherAndPadding()
        compression()
        innerHeader()
        attachments()
        xml()
        credentials()
        kdbxSpec()
        dates()
        metaBinaryPool()
        windows()
        xmlValues()
        duplicateChildren()
        truncation()
        return cases.toList()
    }

    private fun blockStream() {
        case("block-baseline-aes", O, Spec.OPENS) { KdbxToolkit.build(weak.layers) }
        case("block-baseline-chacha20", O, Spec.OPENS) { KdbxToolkit.build(chacha.layers) }
        case("block-bytes-after-end", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(afterEnd = Random(20).nextBytes(100))) }
        case("block-bytes-after-end-chacha20", O, Spec.OPENS) { KdbxToolkit.build(chacha.layers.copy(afterEnd = Random(21).nextBytes(100))) }
        case("block-missing-end", R, Spec.DAMAGED) { KdbxToolkit.build(weak.layers.copy(editBlocks = { _, b -> b.dropLast(1) })) }
        case("block-missing-end-chacha20", R, Spec.DAMAGED) { KdbxToolkit.build(chacha.layers.copy(editBlocks = { _, b -> b.dropLast(1) })) }
        case(
            "block-end-hmac-wrong", R, Spec.DAMAGED,
        ) { KdbxToolkit.build(weak.layers.editBlock(-1) { Block(flip(it.hmac, 0), 0, ByteArray(0)) }) }
        case(
            "block-end-hmac-wrong-chacha20", R, Spec.DAMAGED,
        ) { KdbxToolkit.build(chacha.layers.editBlock(-1) { Block(flip(it.hmac, 0), 0, ByteArray(0)) }) }
        case("block-0-hmac-flipped", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.editBlock(0) { Block(flip(it.hmac, 7), it.declaredLength, it.data) })
        }
        case("block-0-data-flipped", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.editBlock(0) { Block(it.hmac, it.declaredLength, flip(it.data, 100)) })
        }
        for ((label, delta) in listOf("plus-1" to 1, "minus-1" to -1)) {
            case("block-0-length-$label", R, Spec.DAMAGED) {
                KdbxToolkit.build(weak.layers.editBlock(0) { Block(it.hmac, it.declaredLength + delta, it.data) })
            }
        }
        for ((label, length) in listOf("negative" to -1, "huge" to Int.MAX_VALUE, "min" to Int.MIN_VALUE)) {
            case("block-0-length-$label", R, Spec.DAMAGED) {
                KdbxToolkit.build(weak.layers.editBlock(0) { Block(it.hmac, length, it.data) })
            }
            case("block-end-length-$label", R, Spec.DAMAGED) {
                KdbxToolkit.build(weak.layers.editBlock(-1) { Block(it.hmac, length, ByteArray(0)) })
            }
        }
        case("block-size-37", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(blockSize = 37)) }
        case("block-multi-baseline", O, Spec.OPENS, same = null) { KdbxToolkit.build(multi.layers) }
        case("block-multi-first-dropped", R, Spec.DAMAGED) { KdbxToolkit.build(multi.layers.copy(editBlocks = { _, b -> b.drop(1) })) }
        case("block-multi-first-repeated", R, Spec.DAMAGED) { KdbxToolkit.build(multi.layers.copy(editBlocks = { _, b -> listOf(b[0]) + b })) }
        case("block-multi-swapped", R, Spec.DAMAGED) { KdbxToolkit.build(multi.layers.copy(editBlocks = { _, b -> listOf(b[1], b[0]) + b.drop(2) })) }
        case("block-multi-1-hmac-flipped", R, Spec.DAMAGED) {
            KdbxToolkit.build(multi.layers.editBlock(1) { Block(flip(it.hmac, 3), it.declaredLength, it.data) })
        }
        case("block-multi-1-data-flipped", R, Spec.DAMAGED) {
            KdbxToolkit.build(multi.layers.editBlock(1) { Block(it.hmac, it.declaredLength, flip(it.data, 5)) })
        }
        case("block-multi-1-length-minus-1", R, Spec.DAMAGED) {
            KdbxToolkit.build(multi.layers.editBlock(1) { Block(it.hmac, it.declaredLength - 1, it.data) })
        }
        // Ciphertext lengths at the block size: ChaCha20 has no padding, so the ciphertext is
        // as long as the compressed payload.
        for ((label, target) in listOf("1mib" to (1 shl 20), "1mib-plus-1" to (1 shl 20) + 1, "2mib" to (2 shl 20))) {
            case("block-chacha20-ciphertext-$label", O, Spec.OPENS, same = null) { sized(target, chachaMulti = true) }
        }
        case("block-aes-ciphertext-1mib", O, Spec.OPENS, same = null) { sized(1 shl 20, chachaMulti = false) }
    }

    // Resizes the multi-block vault's large attachment until the ciphertext is [target] bytes.
    private fun sized(target: Int, chachaMulti: Boolean): ByteArray {
        val base = if (chachaMulti) {
            val h = multi.layers.header.withField(RawKdbx.CIPHER_ID, uuidBytes(KdbxToolkit.CHACHA20_CIPHER))
                .withField(RawKdbx.ENCRYPTION_IV, Random(13).nextBytes(12))
            multi.layers.copy(header = h)
        } else {
            multi.layers
        }
        val noise = Random(14).nextBytes(target)
        val binaries = base.inner.withIndex().filter { it.value.id == KdbxToolkit.INNER_BINARY }
        val large = binaries.maxBy { it.value.data.size }.index
        fun withLength(n: Int): Layers = base.copy(inner = base.inner.toMutableList().also { it[large] = RawField(KdbxToolkit.INNER_BINARY, byteArrayOf(0) + noise.copyOf(n)) })
        fun ciphertext(n: Int): Int {
            val l = withLength(n)
            val compressed = Gzip.compress(KdbxToolkit.innerBytes(l.inner) + l.xml)
            return if (chachaMulti) compressed.size else KdbxToolkit.pad(compressed).size
        }
        var n = target - 2048
        repeat(64) {
            val size = ciphertext(n)
            if (size == target) return KdbxToolkit.build(withLength(n))
            n += (target - size).let { if (it == 0) 0 else if (!chachaMulti && kotlin.math.abs(it) < 16) Integer.signum(it) else it }
        }
        error("no attachment length gives a $target-byte ciphertext")
    }

    private fun outerHeader() {
        val h = weak.layers.header
        case("header-unknown-id-13", O, Spec.OPENS) {
            KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(13, le32(7)))))
        }
        case("header-comment-id-1", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.COMMENT, "comment".toByteArray())))) }
        case("header-iv-repeated-same", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.ENCRYPTION_IV, h.field(RawKdbx.ENCRYPTION_IV))))) }
        case("header-iv-repeated-different", R, Spec.DAMAGED) {
            // Encrypted under the first IV; the last one wins.
            KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.ENCRYPTION_IV, Random(30).nextBytes(16))), ciphertext = weak.ciphertext))
        }
        case("header-compression-repeated-same", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.COMPRESSION, h.field(RawKdbx.COMPRESSION))))) }
        for (size in listOf(31, 33)) {
            case("header-seed-$size-bytes", R, Spec.DAMAGED) {
                KdbxToolkit.build(weak.layers.copy(header = h.withField(RawKdbx.MASTER_SEED, Random(31).nextBytes(size))))
            }
        }
        case("header-cipher-id-15-bytes", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(header = h.withField(RawKdbx.CIPHER_ID, uuidBytes(KdbxToolkit.AES_CIPHER).copyOf(15)), ciphertext = weak.ciphertext))
        }
        case("header-cipher-id-17-bytes", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(header = h.withField(RawKdbx.CIPHER_ID, uuidBytes(KdbxToolkit.AES_CIPHER) + 0), ciphertext = weak.ciphertext))
        }
        case("header-cipher-twofish", R, Spec.UNSUPPORTED) {
            KdbxToolkit.build(weak.layers.copy(header = h.withField(RawKdbx.CIPHER_ID, uuidBytes("ad68f29f-576f-4bb9-a36a-d47af965346c")), ciphertext = weak.ciphertext))
        }
        for (size in listOf(3, 5)) {
            case("header-compression-$size-bytes", R, Spec.DAMAGED) {
                KdbxToolkit.build(weak.layers.copy(header = h.withField(RawKdbx.COMPRESSION, ByteArray(size).also { it[0] = 1 })))
            }
        }
        case("header-iv-missing", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(header = h.withoutField(RawKdbx.ENCRYPTION_IV), ciphertext = weak.ciphertext))
        }
        case("header-sha256-wrong", R, Spec.DAMAGED) { KdbxToolkit.build(weak.layers.copy(headerHash = ByteArray(32))) }
        case("header-hmac-wrong", R, Spec.WRONG_KEY) { KdbxToolkit.build(weak.layers.copy(headerHmac = ByteArray(32))) }
        for ((label, minor) in listOf("4-1" to 1, "4-2" to 2, "4-65535" to 0xFFFF)) {
            case("header-version-$label", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.copy(minor = minor))) }
        }
        case("header-version-5-0", R, Spec.UNSUPPORTED) { KdbxToolkit.build(weak.layers.copy(header = h.copy(major = 5, minor = 0))) }
        case("header-version-3-1", R, Spec.UNSUPPORTED) { KdbxToolkit.build(weak.layers.copy(header = h.copy(major = 3, minor = 1))) }
        for (i in h.fields.indices) {
            val id = h.fields[i].id
            for ((label, length) in listOf("negative" to -1, "huge" to Int.MAX_VALUE)) {
                case("header-field-$i-id-$id-length-$label", R, Spec.DAMAGED) { KdbxToolkit.build(weak.layers.copy(header = h.withLength(i, length))) }
            }
        }
    }

    private fun kdbx3Fields() {
        val h = weak.layers.header
        val seed = (KdbxToolkit.effective(h).kdf as KdbxToolkit.Kdf.Aes).seed!!
        fun rounds(n: Long) = RawField(RawKdbx.TRANSFORM_ROUNDS, le64(n))
        fun tseed(b: ByteArray) = RawField(RawKdbx.TRANSFORM_SEED, b)
        case("kdbx3-stream-id-10-in-kdbx4", O, Spec.OPENS) {
            KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.INNER_RANDOM_STREAM_ID, le32(3)))))
        }
        case("kdbx3-stream-start-9-in-kdbx4", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.STREAM_START_BYTES, Random(40).nextBytes(32))))) }
        case("kdbx3-stream-key-8-junk-in-kdbx4", O, Spec.OPENS) {
            KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.PROTECTED_STREAM_KEY, Random(41).nextBytes(32)))))
        }
        // Field 6 before field 11 has no effect: field 11 replaces the whole KDF parameter set.
        case("kdbx3-rounds-before-kdf", O, Spec.OPENS) {
            KdbxToolkit.build(weak.layers.copy(header = h.insertBefore(RawKdbx.KDF_PARAMETERS, rounds(7000))))
        }
        case("kdbx3-rounds-before-kdf-derived-with-them", R, Spec.WRONG_KEY) {
            val hh = h.insertBefore(RawKdbx.KDF_PARAMETERS, rounds(7000))
            KdbxToolkit.build(weak.layers.copy(header = hh, kdfHeader = h.withKdf { aesDictionary(7000, seed) }))
        }
        // Field 6 after an AES-KDF dictionary replaces only the rounds.
        case("kdbx3-rounds-after-kdf", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.plusField(rounds(7000)))) }
        case("kdbx3-rounds-after-kdf-derived-without-them", R, Spec.WRONG_KEY) {
            KdbxToolkit.build(weak.layers.copy(header = h.plusField(rounds(7000)), kdfHeader = h))
        }
        case("kdbx3-seed-after-kdf", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.plusField(tseed(Random(42).nextBytes(32))))) }
        // After an Argon2 dictionary, field 6 alone leaves an AES-KDF with no seed; 5 and 6 make it
        // AES-KDF.
        val a = argon2.layers.header
        case("kdbx3-rounds-after-argon2", R, Spec.DAMAGED) { KdbxToolkit.build(argon2.layers.copy(header = a.plusField(rounds(6000)), kdfHeader = a)) }
        case("kdbx3-seed-and-rounds-after-argon2", O, Spec.OPENS) {
            KdbxToolkit.build(argon2.layers.copy(header = a.plusField(tseed(seed)).plusField(rounds(6000))))
        }
        case("kdbx3-seed-and-rounds-before-argon2-derived-aes", R, Spec.WRONG_KEY) {
            val hh = a.insertBefore(RawKdbx.KDF_PARAMETERS, tseed(seed)).insertBefore(RawKdbx.KDF_PARAMETERS, rounds(6000))
            KdbxToolkit.build(argon2.layers.copy(header = hh, kdfHeader = h))
        }
        // Without field 11, KeePass 2 starts from AES-KDF 600,000 rounds with no seed.
        case("kdbx3-no-kdf-seed-and-rounds", O, Spec.OPENS) {
            KdbxToolkit.build(weak.layers.copy(header = h.withoutField(RawKdbx.KDF_PARAMETERS).plusField(tseed(seed)).plusField(rounds(6000))))
        }
        case("kdbx3-no-kdf-seed-only", O, Spec.OPENS) {
            KdbxToolkit.build(weak.layers.copy(header = h.withoutField(RawKdbx.KDF_PARAMETERS).plusField(tseed(seed))))
        }
        case("kdbx3-no-kdf-at-all", R, Spec.DAMAGED) { KdbxToolkit.build(weak.layers.copy(header = h.withoutField(RawKdbx.KDF_PARAMETERS), kdfHeader = h)) }
        // Repeated field 11: the last dictionary wins.
        case("kdf-argon2-then-aes", O, Spec.OPENS) {
            KdbxToolkit.build(weak.layers.copy(header = h.insertBefore(RawKdbx.KDF_PARAMETERS, RawField(RawKdbx.KDF_PARAMETERS, argon2Dictionary().toBytes()))))
        }
        case("kdf-aes-then-argon2-derived-aes", R, Spec.WRONG_KEY) {
            KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.KDF_PARAMETERS, argon2Dictionary().toBytes())), kdfHeader = h))
        }
        case("kdf-aes-then-aes-7000", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.KDF_PARAMETERS, aesDictionary(7000, seed).toBytes())))) }
        // Missing cipher and compression fields take KeePass 2's defaults.
        case("header-cipher-missing", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.withoutField(RawKdbx.CIPHER_ID))) }
        case("header-compression-missing-gzip-content", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(header = h.withoutField(RawKdbx.COMPRESSION))) }
        case("header-compression-missing-plain-content", R, Spec.DAMAGED) {
            val n = noCompression.layers
            KdbxToolkit.build(n.copy(header = n.header.withoutField(RawKdbx.COMPRESSION), compressed = noCompression.contentBytes))
        }
        case("header-stream-id-10-is-4", R, Spec.UNSUPPORTED) {
            KdbxToolkit.build(weak.layers.copy(header = h.plusField(RawField(RawKdbx.INNER_RANDOM_STREAM_ID, le32(4)))))
        }
    }

    private fun dictionary() {
        val h = weak.layers.header
        val seed = (KdbxToolkit.effective(h).kdf as KdbxToolkit.Kdf.Aes).seed!!
        val d = weakKdf
        case("dict-unknown-type", R, Spec.UNSUPPORTED) { weakWithKdf(d.plus(RawEntry(0x7F, "X", ByteArray(4))), deriveFromOriginal = true) }
        case("dict-trailing-bytes", O, Spec.OPENS) { weakWithKdf(d.copy(trailing = byteArrayOf(1, 2, 3))) }
        case("dict-repeated-key-same-value", O, Spec.OPENS) { weakWithKdf(d.plus(d.entries.first { it.key == "R" })) }
        case("dict-rounds-7000-then-6000", O, Spec.OPENS) { weakWithKdf(aesDictionary(7000, seed).plus(RawEntry(RawDictionary.UINT64, "R", le64(6000)))) }
        case("dict-rounds-6000-then-7000", O, Spec.OPENS) { weakWithKdf(aesDictionary(6000, seed).plus(RawEntry(RawDictionary.UINT64, "R", le64(7000)))) }
        case("dict-rounds-uint64-then-uint32", R, Spec.DAMAGED) { weakWithKdf(d.plus(RawEntry(RawDictionary.UINT32, "R", le32(6000))), deriveFromOriginal = true) }
        case("dict-uint32-of-5-bytes", R, Spec.DAMAGED) { weakWithKdf(d.plus(RawEntry(RawDictionary.UINT32, "Z", ByteArray(5))), deriveFromOriginal = true) }
        case("dict-bool-of-2-bytes", R, Spec.DAMAGED) { weakWithKdf(d.plus(RawEntry(0x08, "B", ByteArray(2))), deriveFromOriginal = true) }
        case("dict-version-1-255", O, Spec.OPENS) { weakWithKdf(d.copy(version = 0x01FF)) }
        case("dict-version-2-0", R, Spec.UNSUPPORTED) { weakWithKdf(d.copy(version = 0x0200), deriveFromOriginal = true) }
        case("dict-version-0-0", O, Spec.OPENS) { weakWithKdf(d.copy(version = 0)) }
        case("dict-empty-name", O, Spec.OPENS) { weakWithKdf(d.plus(RawEntry(RawDictionary.UINT32, "", le32(1)))) }
        case("dict-extra-k-on-aes-kdf", O, Spec.OPENS) { weakWithKdf(d.plus(RawEntry(RawDictionary.BYTES, "K", ByteArray(8)))) }
        case("dict-uuid-15-bytes", R, Spec.DAMAGED) {
            weakWithKdf(d.copy(entries = d.entries.map { if (it.key == "\$UUID") it.copy(value = it.value.copyOf(15)) else it }), deriveFromOriginal = true)
        }
        for (i in d.entries.indices) {
            for ((label, length) in listOf("negative" to -1, "huge" to Int.MAX_VALUE)) {
                case("dict-entry-$i-length-$label", R, Spec.DAMAGED) {
                    weakWithKdf(d.copy(entries = d.entries.mapIndexed { j, e -> if (j == i) e.copy(declaredLength = length) else e }), deriveFromOriginal = true)
                }
            }
        }
        // AES-KDF seeds KeePass 2 hashes first; KeePass 2 cannot write them, its save draws a fresh
        // 32-byte seed.
        case("kdf-aes-seed-16-bytes", O, Spec.OPENS) {
            weakWithKdf(d.with("S", RawDictionary.BYTES, Random(50).nextBytes(16)))
        }
        case("kdf-aes-seed-empty", O, Spec.OPENS) {
            weakWithKdf(d.with("S", RawDictionary.BYTES, ByteArray(0)))
        }
        // KeePass 2 refuses a field 11 with no $UUID, even when a valid field 11 follows.
        recordedCase("kdf-missing-uuid-before-valid-kdf", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(header = h.insertBefore(RawKdbx.KDF_PARAMETERS, RawField(RawKdbx.KDF_PARAMETERS, d.without("\$UUID").toBytes()))))
        }
        case("kdf-aes-0-rounds", O, Spec.REFUSED_BY_POLICY, policy = 1) { weakWithKdf(d.with("R", RawDictionary.UINT64, le64(0))) }
        case("kdf-argon2-salt-7-bytes", R, Spec.DAMAGED) {
            KdbxToolkit.build(argon2.layers.copy(header = argon2.layers.header.withKdf { argon2Dictionary(salt = Random(51).nextBytes(7)) }, kdfHeader = argon2.layers.header))
        }
        case("kdf-argon2-k-not-bytes", O, Spec.OPENS) {
            KdbxToolkit.build(argon2.layers.copy(header = argon2.layers.header.withKdf { argon2Dictionary(salt = Random(12).nextBytes(32), extra = listOf(RawEntry(RawDictionary.UINT32, "K", le32(5)))) }))
        }
        case("kdf-argon2-a-not-bytes", O, Spec.OPENS) {
            KdbxToolkit.build(argon2.layers.copy(header = argon2.layers.header.withKdf { argon2Dictionary(salt = Random(12).nextBytes(32), extra = listOf(RawEntry(RawDictionary.UINT64, "A", le64(5)))) }))
        }
    }

    private fun cipherAndPadding() {
        val h = weak.layers.header
        val c = chacha.layers.header
        case("cipher-chacha20-iv-16-bytes", R, Spec.DAMAGED) {
            val iv = c.field(RawKdbx.ENCRYPTION_IV) + Random(60).nextBytes(4)
            KdbxToolkit.build(chacha.layers.copy(header = c.withField(RawKdbx.ENCRYPTION_IV, iv), cipherIv = iv.copyOf(12)))
        }
        case("cipher-aes-iv-12-bytes", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(header = h.withField(RawKdbx.ENCRYPTION_IV, h.field(RawKdbx.ENCRYPTION_IV).copyOf(12)), ciphertext = weak.ciphertext))
        }
        val compressed = weak.compressedBytes!!
        // Two or more padding bytes, so one of them can differ from the last.
        val padLength = (16 - compressed.size % 16).let { if (it < 2) it + 16 else it }
        fun padded(last: Int, other: Int? = null): ByteArray {
            val p = padLength
            return compressed + ByteArray(p) { i -> (if (i == p - 1) last else other ?: p).toByte() }
        }
        case("padding-17", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(padded = padded(17, 17)))
        }
        case("padding-0", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(padded = padded(0, 0)))
        }
        case("padding-inconsistent", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(padded = padded(last = padLength, other = 1)))
        }
        case("cipher-aes-ciphertext-not-block-multiple", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(ciphertext = weak.ciphertext.copyOf(weak.ciphertext.size - 5)))
        }
    }

    private fun compression() {
        val gz = weak.compressedBytes!!
        val content = weak.contentBytes
        case("gzip-two-members-content-split", R, Spec.DAMAGED) {
            val cut = content.size / 2
            KdbxToolkit.build(weak.layers.copy(compressed = Gzip.compress(content.copyOf(cut)) + Gzip.compress(content.copyOfRange(cut, content.size))))
        }
        case("gzip-second-member-non-empty", O, Spec.OPENS) {
            KdbxToolkit.build(weak.layers.copy(compressed = gz + Gzip.compress(ByteArray(100) { 'x'.code.toByte() })))
        }
        case("gzip-second-member-empty", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(compressed = gz + Gzip.compress(ByteArray(0)))) }
        case("gzip-data-after-member", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(compressed = gz + Random(70).nextBytes(16))) }
        case("gzip-crc-wrong", R, Spec.DAMAGED) { KdbxToolkit.build(weak.layers.copy(compressed = flip(gz, gz.size - 8))) }
        case("gzip-isize-wrong", R, Spec.DAMAGED) { KdbxToolkit.build(weak.layers.copy(compressed = flip(gz, gz.size - 4))) }
        case("gzip-trailer-missing", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(compressed = gz.copyOf(gz.size - 8))) }
        case("gzip-trailer-half", O, Spec.OPENS) { KdbxToolkit.build(weak.layers.copy(compressed = gz.copyOf(gz.size - 4))) }
        case("gzip-cut-inside-member", R, Spec.DAMAGED) { KdbxToolkit.build(weak.layers.copy(compressed = gz.copyOf(gz.size / 2))) }
        case("compression-none-with-gzip-content", R, Spec.DAMAGED) {
            KdbxToolkit.build(weak.layers.copy(header = weak.layers.header.withField(RawKdbx.COMPRESSION, le32(0)), compressed = gz))
        }
        case("compression-gzip-with-plain-content", R, Spec.DAMAGED) { KdbxToolkit.build(weak.layers.copy(compressed = content)) }
        case("compression-none-baseline", O, Spec.OPENS, same = null) { KdbxToolkit.build(noCompression.layers) }
        case(
            "gzip-bomb-512mib", O, Spec.NOT_ENOUGH_MEMORY,
        ) { KdbxToolkit.build(weak.layers.copy(compressed = bomb())) }
    }

    // A valid KeePassFile whose whitespace after the root's start tag inflates to 512 MiB.
    private fun bomb(): ByteArray {
        val xml = String(weak.layers.xml, Charsets.ISO_8859_1)
        val at = xml.indexOf("<KeePassFile>") + "<KeePassFile>".length
        val chunk = ByteArray(1 shl 20) { ' '.code.toByte() }
        val parts = sequence {
            yield(KdbxToolkit.innerBytes(weak.layers.inner))
            yield(xml.substring(0, at).toByteArray(Charsets.ISO_8859_1))
            repeat((Corpus.BOMB_BYTES / chunk.size).toInt()) { yield(chunk) }
            yield(xml.substring(at).toByteArray(Charsets.ISO_8859_1))
        }
        return Gzip.compressStream(parts)
    }

    private fun innerHeader() {
        val l = weak.layers
        val streamKey = l.inner.first { it.id == KdbxToolkit.INNER_STREAM_KEY }.data
        case("inner-unknown-id-9", O, Spec.OPENS) {
            KdbxToolkit.build(l.innerWith { it.beforeEnd(RawField(9, le32(1))) })
        }
        case("inner-stream-key-empty", R, Spec.DAMAGED) {
            KdbxToolkit.build(l.innerWith { it.replaceFirst(KdbxToolkit.INNER_STREAM_KEY, ByteArray(0)) }.copy(keepProtectedCiphertext = true))
        }
        case("inner-stream-key-32-bytes", O, Spec.OPENS) { KdbxToolkit.build(KdbxToolkit.withInnerStream(l, KdbxToolkit.CHACHA20, Random(80).nextBytes(32))) }
        case("inner-stream-id-0", R, Spec.UNSUPPORTED) {
            KdbxToolkit.build(l.innerWith { it.replaceFirst(KdbxToolkit.INNER_STREAM_ID, le32(0)) }.copy(keepProtectedCiphertext = true))
        }
        case("inner-stream-arcfour-variant", O, Spec.OPENS) {
            KdbxToolkit.build(KdbxToolkit.withInnerStream(l, KdbxToolkit.ARCFOUR_VARIANT, streamKey))
        }
        case("inner-stream-salsa20", O, Spec.OPENS) { KdbxToolkit.build(KdbxToolkit.withInnerStream(l, KdbxToolkit.SALSA20, Random(81).nextBytes(32))) }
        case("inner-stream-id-missing", O, Spec.OPENS) {
            KdbxToolkit.build(l.innerWith { f -> f.filterNot { it.id == KdbxToolkit.INNER_STREAM_ID } })
        }
        case("inner-stream-id-4", R, Spec.UNSUPPORTED) {
            KdbxToolkit.build(l.innerWith { it.replaceFirst(KdbxToolkit.INNER_STREAM_ID, le32(4)) }.copy(keepProtectedCiphertext = true))
        }
        case("inner-stream-id-5-bytes", R, Spec.DAMAGED) {
            KdbxToolkit.build(l.innerWith { it.replaceFirst(KdbxToolkit.INNER_STREAM_ID, le32(3) + 0) })
        }
        case("inner-stream-key-only-in-outer-8", O, Spec.OPENS) {
            KdbxToolkit.build(l.copy(header = l.header.plusField(RawField(RawKdbx.PROTECTED_STREAM_KEY, streamKey))).innerWith { f -> f.filterNot { it.id == KdbxToolkit.INNER_STREAM_KEY } })
        }
        case("inner-stream-id-only-in-outer-10", O, Spec.OPENS) {
            KdbxToolkit.build(l.copy(header = l.header.plusField(RawField(RawKdbx.INNER_RANDOM_STREAM_ID, le32(3)))).innerWith { f -> f.filterNot { it.id == KdbxToolkit.INNER_STREAM_ID } })
        }
        case("inner-stream-key-in-neither-header", R, Spec.DAMAGED) {
            KdbxToolkit.build(l.innerWith { f -> f.filterNot { it.id == KdbxToolkit.INNER_STREAM_KEY } }.copy(keepProtectedCiphertext = true))
        }
        case("inner-stream-key-repeated-junk-then-real", O, Spec.OPENS) {
            KdbxToolkit.build(l.innerWith { f -> val i = f.indexOfFirst { it.id == KdbxToolkit.INNER_STREAM_KEY }; f.take(i) + RawField(KdbxToolkit.INNER_STREAM_KEY, Random(82).nextBytes(64)) + f.drop(i) })
        }
        case("inner-stream-id-repeated-1-then-3", O, Spec.OPENS) {
            KdbxToolkit.build(l.innerWith { f -> val i = f.indexOfFirst { it.id == KdbxToolkit.INNER_STREAM_ID }; f.take(i) + RawField(KdbxToolkit.INNER_STREAM_ID, le32(1)) + f.drop(i) })
        }
        for (i in l.inner.indices) {
            for ((label, length) in listOf("negative" to -1, "huge" to Int.MAX_VALUE)) {
                case("inner-field-$i-id-${l.inner[i].id}-length-$label", R, Spec.DAMAGED) {
                    KdbxToolkit.build(l.copy(inner = l.inner.mapIndexed { j, f -> if (j == i) f.copy(declaredLength = length) else f }, keepProtectedCiphertext = true))
                }
            }
        }
    }

    private fun attachments() {
        val l = weak.layers
        val codes = l.inner.first { it.id == KdbxToolkit.INNER_BINARY }
        case("attachment-no-flag-byte", R, Spec.DAMAGED) {
            KdbxToolkit.build(l.innerWith { it.replaceFirst(KdbxToolkit.INNER_BINARY, ByteArray(0)) })
        }
        case("attachment-flag-only", O, Spec.OPENS, same = null) { KdbxToolkit.build(l.innerWith { it.replaceFirst(KdbxToolkit.INNER_BINARY, byteArrayOf(0)) }) }
        case(
            "attachment-flag-0x02", O, Spec.OPENS, same = null,
        ) { KdbxToolkit.build(l.innerWith { it.replaceFirst(KdbxToolkit.INNER_BINARY, byteArrayOf(2) + codes.data.copyOfRange(1, codes.data.size)) }) }
        case(
            "attachment-identical-pool-items", O, Spec.OPENS, same = null,
        ) {
            val other = RawField(KdbxToolkit.INNER_BINARY, byteArrayOf(0) + "third item".toByteArray())
            KdbxToolkit.build(l.innerWith { f -> val i = f.indexOf(codes); f.take(i + 1) + codes + other + f.drop(i + 1) }.xmlEdit { addBinaryRef(it, 2) })
        }
        case("attachment-unreferenced-pool-item", O, Spec.OPENS) {
            KdbxToolkit.build(l.innerWith { it.beforeEnd(RawField(KdbxToolkit.INNER_BINARY, byteArrayOf(0) + "unreferenced".toByteArray())) })
        }
        case("attachment-reference-out-of-range", O, Spec.OPENS_READ_ONLY, same = null) {
            KdbxToolkit.build(l.xmlEdit { it.replace("<Value Ref=\"0\" />", "<Value Ref=\"5\" />") })
        }
        case("attachment-reference-negative", O, Spec.OPENS_READ_ONLY, same = null) {
            KdbxToolkit.build(l.xmlEdit { it.replace("<Value Ref=\"0\" />", "<Value Ref=\"-1\" />") })
        }
    }

    // Helpers of the XML-level recipes.
    private val metaEnd = "\t\t<CustomData />\n\t</Meta>"
    private val third = "third item".toByteArray()

    private fun metaBinaries(items: String) = "\t\t<Binaries>\n$items\t\t</Binaries>\n"

    private fun b64(b: ByteArray): String = java.util.Base64.getEncoder().encodeToString(b)

    private fun String.insertBefore(anchor: String, text: String): String {
        check(anchor in this) { "anchor missing: $anchor" }
        return replace(anchor, text + anchor)
    }

    // Adds an attachment with pool reference [ref] to the entry whose user name is bob.
    private fun addBinaryRef(xml: String, ref: Int): String {
        val anchor = "<Value>bob</Value>\n\t\t\t\t</String>\n"
        check(anchor in xml) { "no bob entry" }
        return xml.replace(anchor, anchor + "\t\t\t\t<Binary>\n\t\t\t\t\t<Key>third.bin</Key>\n\t\t\t\t\t<Value Ref=\"$ref\" />\n\t\t\t\t</Binary>\n")
    }

    private fun xml() {
        val l = weak.layers
        case("xml-garbage-after-root", R, Spec.DAMAGED) {
            KdbxToolkit.build(l.copy(xml = l.xml + "garbage".toByteArray()))
        }
        case("xml-whitespace-after-root", O, Spec.OPENS) { KdbxToolkit.build(l.copy(xml = l.xml + "\n \t\n".toByteArray())) }
        case("xml-nul-after-root", R, Spec.DAMAGED) {
            KdbxToolkit.build(l.copy(xml = l.xml + byteArrayOf(0)))
        }
        val headerHash = java.util.Base64.getEncoder().encodeToString(KdbxToolkit.sha256(l.header.headerBytes()))
        fun withHash(value: String) = KdbxToolkit.build(l.xmlEdit { it.replace("<Generator></Generator>", "<Generator></Generator>\n\t\t<HeaderHash>$value</HeaderHash>") })
        case("xml-header-hash-correct", O, Spec.OPENS) { withHash(headerHash) }
        case("xml-header-hash-wrong", R, Spec.DAMAGED) { withHash(java.util.Base64.getEncoder().encodeToString(ByteArray(32))) }
        case("xml-header-hash-empty", O, Spec.OPENS) { withHash("") }
        case("xml-header-hash-not-base64", R, Spec.DAMAGED) { withHash("not*base64") }
        // The XML declaration as .NET's reader checks it (XML 1.0 section 2.8, XMLDecl).
        val text = String(l.xml, Charsets.ISO_8859_1)
        val declaration = text.substring(0, text.indexOf("?>") + 2)
        fun withDeclaration(d: String) = KdbxToolkit.build(l.copy(xml = text.replaceFirst(declaration, d).toByteArray(Charsets.ISO_8859_1)))
        for ((label, seen, d) in listOf(
            Triple("single-quotes", O, "<?xml version='1.0' encoding='utf-8' standalone='yes'?>"),
            Triple("spaces-around-equals", O, "<?xml version = \"1.0\"  encoding =\t\"utf-8\" ?>"),
            Triple("version-only", O, "<?xml version=\"1.0\"?>"),
            Triple("encoding-upper-case", O, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
            Triple("junk-token", R, "<?xml version=\"1.0\" encoding=\"utf-8\" junk standalone=\"yes\"?>"),
            Triple("element-text-inside", R, "<?xml version=\"1.0\" <Value>junk</Value> ?>"),
            Triple("no-version", R, "<?xml encoding=\"utf-8\"?>"),
            Triple("version-1-1", R, "<?xml version=\"1.1\" encoding=\"utf-8\"?>"),
            Triple("standalone-before-encoding", R, "<?xml version=\"1.0\" standalone=\"yes\" encoding=\"utf-8\"?>"),
            Triple("standalone-maybe", R, "<?xml version=\"1.0\" standalone=\"maybe\"?>"),
            Triple("unquoted-version", R, "<?xml version=1.0?>"),
            Triple("encoding-unknown", R, "<?xml version=\"1.0\" encoding=\"kashpass-unknown\"?>"),
        )) {
            case("xml-declaration-$label", seen, if (seen == O) Spec.OPENS else Spec.DAMAGED) { withDeclaration(d) }
        }
    }

    private fun credentials() {
        case("credentials-wrong-password", R, Spec.WRONG_KEY) { KdbxToolkit.build(weak.layers.copy(key = KdbxToolkit.Key("not-the-password"))) }
        val keyOnly = Fixtures.bytes("keepass2-keyfile-only-v1.kdbx")
        case(
            "credentials-wrong-key-file", R, Spec.WRONG_KEY,
            mode = CredentialMode.KEY_FILE_ONLY, keyFileName = "keepass2-keyfile-raw32.key", keyFile = Fixtures.bytes("keepass2-keyfile-raw32.key"),
        ) { keyOnly }
    }

    // Shapes the KDBX 4.1 specification (keepass.info/help/kb/kdbx.html and its XML schema)
    // describes, with KeePass 2's reading of each.
    private fun kdbxSpec() {
        val l = weak.layers
        val h = l.header
        fun signature(second: Int) = h.signature.copyOf().also { le32(second).copyInto(it, 4) }
        case("spec-signature-1-wrong", R, Spec.DAMAGED) {
            KdbxToolkit.build(l.copy(header = h.copy(signature = flip(h.signature, 0))))
        }
        case("spec-signature-2-wrong", R, Spec.DAMAGED) { KdbxToolkit.build(l.copy(header = h.copy(signature = signature(0)))) }
        case("spec-signature-keepass-1", R, Spec.UNSUPPORTED) { KdbxToolkit.build(l.copy(header = h.copy(signature = signature(0xB54BFB65.toInt())))) }
        // KeePass 2 accepts the pre-release second signature as the normal one.
        case("spec-signature-pre-release", O, Spec.OPENS) { KdbxToolkit.build(l.copy(header = h.copy(signature = signature(0xB54BFB66.toInt())))) }
        // The header fields with no end field and nothing after them: a reader runs out of bytes
        // looking for the next field. In a whole file the header hash would be read as a field,
        // and what that gives depends on the hash.
        case("spec-header-end-missing", R, Spec.DAMAGED) { h.withoutField(RawKdbx.END_OF_HEADER).headerBytes() }
        for ((label, value) in listOf("empty" to ByteArray(0), "zeros" to ByteArray(4), "100-bytes" to Random(90).nextBytes(100))) {
            case("spec-header-end-value-$label", O, Spec.OPENS) { KdbxToolkit.build(l.copy(header = h.withField(RawKdbx.END_OF_HEADER, value))) }
        }
        case("spec-compression-id-2", R, Spec.UNSUPPORTED) { KdbxToolkit.build(l.copy(header = h.withField(RawKdbx.COMPRESSION, le32(2)))) }

        // One item of each value type the specification lists.
        val everyType = listOf(
            RawEntry(RawDictionary.UINT32, "KashPass_UInt32", le32(7)),
            RawEntry(RawDictionary.UINT64, "KashPass_UInt64", le64(7L)),
            RawEntry(RawDictionary.BOOL, "KashPass_Bool", byteArrayOf(1)),
            RawEntry(RawDictionary.INT32, "KashPass_Int32", le32(-7)),
            RawEntry(RawDictionary.INT64, "KashPass_Int64", le64(-7L)),
            RawEntry(RawDictionary.STRING, "KashPass_String", "text".toByteArray()),
            RawEntry(RawDictionary.BYTES, "KashPass_Bytes", byteArrayOf(1, 2, 3)),
        )
        val custom = RawDictionary(0x0100, everyType)
        case("spec-public-custom-data-every-type", O, Spec.OPENS) {
            KdbxToolkit.build(l.copy(header = h.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, custom.toBytes()))))
        }
        case("spec-public-custom-data-version-2", R, Spec.UNSUPPORTED) {
            KdbxToolkit.build(l.copy(header = h.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, custom.copy(version = 0x0200).toBytes()))))
        }
        case("spec-public-custom-data-empty", R, Spec.DAMAGED) {
            KdbxToolkit.build(l.copy(header = h.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, ByteArray(0)))))
        }
        // KeePass 2 reads any number of entries; 20,000 empty byte arrays pass the dictionary
        // budget of a 16 MiB heap, a sixteenth of it.
        val many = RawDictionary(0x0100, List(20_000) { RawEntry(RawDictionary.BYTES, "%05d".format(it), ByteArray(0)) })
        case("spec-public-custom-data-many-entries", O, Spec.NOT_ENOUGH_MEMORY, heap = 16L * 1024 * 1024) {
            KdbxToolkit.build(l.copy(header = h.plusField(RawField(RawKdbx.PUBLIC_CUSTOM_DATA, many.toBytes()))))
        }

        val d = weakKdf
        case("spec-dict-entries-reordered", O, Spec.OPENS) { weakWithKdf(d.copy(entries = d.entries.reversed())) }
        case("spec-dict-every-value-type", O, Spec.OPENS) { weakWithKdf(d.copy(entries = d.entries + everyType)) }
        case("spec-dict-no-terminator", R, Spec.DAMAGED) { weakWithKdf(d.copy(terminated = false), deriveFromOriginal = true) }
        for ((label, length) in listOf("negative" to -1, "huge" to Int.MAX_VALUE)) {
            case("spec-dict-name-length-$label", R, Spec.DAMAGED) {
                weakWithKdf(d.copy(entries = listOf(d.entries[0].copy(declaredNameLength = length)) + d.entries.drop(1)), deriveFromOriginal = true)
            }
        }
        case("spec-dict-name-not-utf8", O, Spec.OPENS) {
            weakWithKdf(d.plus(RawEntry(RawDictionary.UINT32, "", le32(1), rawName = byteArrayOf(0xC3.toByte(), 0x28))))
        }

        // Argon2 bounds from the specification's KDF table; KeePass 2 checks them before deriving.
        val a = argon2.layers
        fun argon2With(change: (RawDictionary) -> RawDictionary, refused: Boolean) =
            KdbxToolkit.build(a.copy(header = a.header.withKdf { change(argon2Dictionary()) }, kdfHeader = if (refused) a.header else null))
        case("spec-argon2-salt-8-bytes", O, Spec.OPENS) { argon2With({ it.with("S", RawDictionary.BYTES, Random(91).nextBytes(8)) }, refused = false) }
        case("spec-argon2-memory-8-kib-one-lane", O, Spec.OPENS) { argon2With({ it.with("M", RawDictionary.UINT64, le64(8192)) }, refused = false) }
        case("spec-argon2-memory-not-kib-multiple", O, Spec.OPENS) {
            argon2With({ it.with("M", RawDictionary.UINT64, le64(1024L * 1024 + 512)) }, refused = false)
        }
        val bounds = listOf(
            Triple("iterations-0", "I", le64(0)),
            Triple("iterations-2-32", "I", le64(1L shl 32)),
            Triple("parallelism-0", "P", le32(0)),
            Triple("parallelism-2-24", "P", le32(1 shl 24)),
            Triple("memory-8191", "M", le64(8191)),
            Triple("memory-2-31", "M", le64(1L shl 31)),
            Triple("version-0x14", "V", le32(0x14)),
        )
        for ((label, name, value) in bounds) {
            val type = if (value.size == 8) RawDictionary.UINT64 else RawDictionary.UINT32
            case("spec-argon2-$label", R, Spec.REFUSED_BY_POLICY, policy = 1) {
                argon2With({ it.with(name, type, value) }, refused = true)
            }
        }

        // Block stream: an empty block ends it, block sizes are the writer's choice.
        case("spec-block-early-end", R, Spec.DAMAGED) {
            KdbxToolkit.build(multi.layers.copy(editBlocks = { macs, b -> listOf(b[0], macs.validBlock(1, ByteArray(0))) + b.drop(1) }))
        }
        case("spec-block-sizes-varied", O, Spec.OPENS) {
            KdbxToolkit.build(
                l.copy(
                    editBlocks = { macs, b ->
                        val ct = b.dropLast(1).fold(ByteArray(0)) { acc, x -> acc + x.data }
                        val cuts = listOf(0, 100, 101, 1101, ct.size)
                        cuts.zipWithNext().mapIndexed { i, (s, e) -> macs.validBlock(i.toLong(), ct.copyOfRange(s, e)) } +
                            macs.validBlock(cuts.size - 1L, ByteArray(0))
                    },
                ),
            )
        }
        case("spec-block-one-larger-than-1mib", O, Spec.OPENS, same = MULTI) { KdbxToolkit.build(multi.layers.copy(blockSize = 4 shl 20)) }

        // Inner header and inner encryption.
        case("spec-inner-end-value", O, Spec.OPENS) { KdbxToolkit.build(l.innerWith { it.dropLast(1) + RawField(KdbxToolkit.INNER_END, ByteArray(4)) }) }
        case("spec-inner-end-missing", R, Spec.DAMAGED) { KdbxToolkit.build(l.innerWith { it.dropLast(1) }.copy(keepProtectedCiphertext = true)) }
        case("spec-inner-salsa20-key-64-bytes", O, Spec.OPENS) { KdbxToolkit.build(KdbxToolkit.withInnerStream(l, KdbxToolkit.SALSA20, Random(92).nextBytes(64))) }
        // An empty protected value takes no keystream. Both copies put it in the bank entry, one
        // before the entry's protected values and one after them, so both must report the same
        // content; a reader that spends keystream on it garbles the values after it.
        val emptyField = "<String>\n\t\t\t\t\t<Key>Empty</Key>\n\t\t\t\t\t<Value Protected=\"True\"></Value>\n\t\t\t\t</String>\n"
        fun withEmpty(before: Boolean): Layers {
            val xml = String(l.xml, Charsets.ISO_8859_1)
            val entry = xml.lastIndexOf("<Entry>", xml.indexOf("<Value>Example Bank</Value>"))
            val at = if (before) xml.indexOf("<String>", entry) else xml.indexOf("<Binary>", entry)
            val protectedBefore = KdbxToolkit.protectedCountBefore(l.xml, at)
            val values = l.protectedValues.toMutableList().also { it.add(protectedBefore, ByteArray(0)) }
            return l.copy(xml = (xml.substring(0, at) + emptyField + "\t\t\t\t\t" + xml.substring(at)).toByteArray(Charsets.ISO_8859_1), protectedValues = values)
        }
        case("spec-inner-empty-protected-before-entry-values", O, Spec.OPENS, same = "spec-inner-empty-protected-after-entry-values") { KdbxToolkit.build(withEmpty(before = true)) }
        case("spec-inner-empty-protected-after-entry-values", O, Spec.OPENS, same = null) { KdbxToolkit.build(withEmpty(before = false)) }
        case("spec-inner-protected-not-base64", R, Spec.DAMAGED) {
            KdbxToolkit.build(l.xmlEdit { it.replaceFirst(Regex("<Value Protected=\"True\">[^<]*</Value>"), "<Value Protected=\"True\">not*base64</Value>") }.copy(keepProtectedCiphertext = true))
        }
        // Every element marked Protected="True" takes keystream in document order, not only
        // string values; these sit in Meta, before every entry, and report nothing themselves.
            "element decrypt with the wrong keystream"
        val generator = "<Generator></Generator>\n"
        fun String.insertAfter(anchor: String, text: String): String {
            check(anchor in this) { "anchor missing: $anchor" }
            return replace(anchor, anchor + text)
        }
        case("spec-inner-protected-unknown-element", O, Spec.OPENS) {
            val element = "\t\t<KashPassUnknown Protected=\"True\">AAAA</KashPassUnknown>\n"
            KdbxToolkit.build(l.xmlEdit { it.insertAfter(generator, element) }.copy(protectedValues = listOf("secret-unknown".toByteArray()) + l.protectedValues))
        }
        case("spec-meta-binary-protected-unreferenced", O, Spec.OPENS) {
            val items = "\t\t\t<Binary ID=\"1\" Protected=\"True\">AAAA</Binary>\n"
            KdbxToolkit.build(l.xmlEdit { it.insertBefore(metaEnd, metaBinaries(items)) }.copy(protectedValues = listOf("meta-binary".toByteArray()) + l.protectedValues))
        }

        // Meta/Binaries in KDBX 4: KeePass 2 reads them into the pool by ID (an item replaces
        // the inner-header item with the same index).
        case("spec-meta-binary-new-base", O, Spec.OPENS, same = null) {
            KdbxToolkit.build(l.innerWith { it.beforeEnd(RawField(KdbxToolkit.INNER_BINARY, byteArrayOf(0) + third)) }.xmlEdit { addBinaryRef(it, 1) })
        }
        case("spec-meta-binary-new", O, Spec.OPENS, same = "spec-meta-binary-new-base") {
            KdbxToolkit.build(l.xmlEdit { addBinaryRef(it.insertBefore(metaEnd, metaBinaries("\t\t\t<Binary ID=\"1\">${b64(third)}</Binary>\n")), 1) })
        }
        case("spec-meta-binary-compressed", O, Spec.OPENS, same = "spec-meta-binary-new-base") {
            KdbxToolkit.build(l.xmlEdit { addBinaryRef(it.insertBefore(metaEnd, metaBinaries("\t\t\t<Binary ID=\"1\" Compressed=\"True\">${b64(Gzip.compress(third))}</Binary>\n")), 1) })
        }
        val replacement = "replaced codes".toByteArray()
        case("spec-meta-binary-replaces-0-base", O, Spec.OPENS, same = null) {
            KdbxToolkit.build(l.innerWith { it.replaceFirst(KdbxToolkit.INNER_BINARY, byteArrayOf(0) + replacement) })
        }
        case("spec-meta-binary-replaces-0", O, Spec.OPENS, same = "spec-meta-binary-replaces-0-base") {
            KdbxToolkit.build(l.xmlEdit { it.insertBefore(metaEnd, metaBinaries("\t\t\t<Binary ID=\"0\">${b64(replacement)}</Binary>\n")) })
        }
        for ((label, id) in listOf("negative" to "-1", "not-integer" to "x")) {
            case("spec-meta-binary-id-$label", R, Spec.DAMAGED) {
                KdbxToolkit.build(l.xmlEdit { it.insertBefore(metaEnd, metaBinaries("\t\t\t<Binary ID=\"$id\">${b64(third)}</Binary>\n")) })
            }
        }
    }

    // KDBX 4 dates as KeePass 2 reads them: Base64 of 8 bytes of seconds since 0001-01-01; short or
    // long values are padded or cut to 8 bytes, an empty one is 0001-01-01, and a value that is not
    // Base64 or outside 0001-01-01 to 9999-12-31T23:59:59Z fails the load.
    private fun dates() {
        val l = weak.layers
        val time = Regex("<CreationTime>[^<]*</CreationTime>")
        fun withTime(value: String) = KdbxToolkit.build(l.xmlEdit { check(time.containsMatchIn(it)) { "no CreationTime" }; it.replaceFirst(time, "<CreationTime>$value</CreationTime>") })
        recordedCase("spec-date-iso", R, Spec.DAMAGED) { withTime("2026-10-25T12:00:00Z") }
        recordedCase("spec-date-empty", O, Spec.OPENS) { withTime("") }
        recordedCase("spec-date-4-bytes", O, Spec.OPENS) { withTime(b64(le32(0x12345678))) }
        recordedCase("spec-date-12-bytes", O, Spec.OPENS) { withTime(b64(le64(63_900_000_000L) + le32(7))) }
        recordedCase("spec-date-not-base64", R, Spec.DAMAGED) { withTime("not*base64") }
        recordedCase("spec-date-seconds-negative", R, Spec.DAMAGED) { withTime(b64(le64(-1L))) }
        // 9999-12-31T23:59:59Z is 315,537,897,599 seconds; one more is past the last valid date.
        recordedCase("spec-date-seconds-past-9999", R, Spec.DAMAGED) { withTime(b64(le64(315_537_897_600L))) }
    }

    // The attachment pool KeePass 2 builds is a map by ID: a Meta/Binaries item can leave gaps, a
    // protected item is not decompressed, and every compressed item draws on one decompression
    // budget.
    private fun metaBinaryPool() {
        val l = weak.layers
        val base = "spec-meta-binary-new-base"
        for ((label, id) in listOf("sparse-id" to "5", "id-max" to "2147483647")) {
            recordedCase("spec-meta-binary-$label", O, Spec.OPENS, same = base) {
                KdbxToolkit.build(l.xmlEdit { addBinaryRef(it.insertBefore(metaEnd, metaBinaries("\t\t\t<Binary ID=\"$id\">${b64(third)}</Binary>\n")), id.toInt()) })
            }
        }
        recordedCase("spec-meta-binary-protected-compressed", O, Spec.OPENS, same = null) {
            val items = "\t\t\t<Binary ID=\"1\" Protected=\"True\" Compressed=\"True\">AAAA</Binary>\n"
            KdbxToolkit.build(l.xmlEdit { addBinaryRef(it.insertBefore(metaEnd, metaBinaries(items)), 1) }.copy(protectedValues = listOf(third) + l.protectedValues))
        }
        // KeePass 2 resolves an entry's Ref when it reads it; a Meta/Binaries item after Root
        // replaces the pool slot only for references read later.
        fun metaAfterRoot(xml: String): String {
            val start = xml.indexOf("\t<Meta>")
            val end = xml.indexOf("\t</Meta>\n") + "\t</Meta>\n".length
            check(start >= 0 && end > start) { "no Meta" }
            val meta = xml.substring(start, end)
            val rest = xml.removeRange(start, end)
            return rest.replace("</KeePassFile>", meta + "</KeePassFile>")
        }
        recordedCase("spec-meta-binary-after-root-replaces-0", O, Spec.OPENS) {
            KdbxToolkit.build(l.xmlEdit { metaAfterRoot(it.insertBefore(metaEnd, metaBinaries("\t\t\t<Binary ID=\"0\">${b64("replaced codes".toByteArray())}</Binary>\n"))) })
        }
        recordedCase("spec-meta-binary-after-root-new-id", O, Spec.OPENS_READ_ONLY, same = null) {
            KdbxToolkit.build(l.xmlEdit { metaAfterRoot(addBinaryRef(it.insertBefore(metaEnd, metaBinaries("\t\t\t<Binary ID=\"5\">${b64(third)}</Binary>\n")), 5)) })
        }
        // Each item alone fits the 16 MiB test budget; together they pass it.
        recordedCase("spec-meta-binary-two-over-budget", O, Spec.NOT_ENOUGH_MEMORY) {
            val big = b64(Gzip.compress(ByteArray(10 * 1024 * 1024)))
            val items = "\t\t\t<Binary ID=\"1\" Compressed=\"True\">$big</Binary>\n\t\t\t<Binary ID=\"2\" Compressed=\"True\">$big</Binary>\n"
            KdbxToolkit.build(l.xmlEdit { it.insertBefore(metaEnd, metaBinaries(items)) })
        }
    }

    // Files KeePass 2 on Windows reads differently from KeePass 2 under Mono, or writes only on
    // Windows. On Windows the gzip reader also accepts a zlib (RFC 1950) stream; under Mono it
    // reads gzip only. KeePass 2 on Windows writes XML with CR LF line ends, which XML 1.0
    // section 2.11 turns into LF.
    private fun windows() {
        val l = weak.layers
        val zlibReason = ".NET Framework's GZipStream on Windows accepts a zlib stream (window bits 47); KeePassLib under Mono accepts only gzip"
        fun zlib(b: ByteArray): ByteArray {
            val deflater = java.util.zip.Deflater()
            deflater.setInput(b)
            deflater.finish()
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (!deflater.finished()) out.write(buf, 0, deflater.deflate(buf))
            deflater.end()
            return out.toByteArray()
        }
        recordedCase("gzip-flag-zlib-content", R, Spec.OPENS, windows = O, windowsReason = zlibReason) { KdbxToolkit.build(l.copy(compressed = zlib(KdbxToolkit.innerBytes(l.inner) + l.xml))) }
        recordedCase("spec-meta-binary-compressed-zlib", R, Spec.OPENS, same = "spec-meta-binary-new-base", windows = O, windowsReason = zlibReason) {
            val items = metaBinaries("\t\t\t<Binary ID=\"1\" Compressed=\"True\">${b64(zlib(third))}</Binary>\n")
            KdbxToolkit.build(l.xmlEdit { addBinaryRef(it.insertBefore(metaEnd, items), 1) })
        }
        val notes = Regex("<Key>Notes</Key>(\\s*)<Value>[^<]*</Value>")
        fun withNotes(xml: String) = xml.also { check(notes.containsMatchIn(it)) { "no Notes" } }.replaceFirst(notes, "<Key>Notes</Key>$1<Value>line one\nline two</Value>")
        case("xml-lf-in-notes-base", O, Spec.OPENS, same = null) { KdbxToolkit.build(l.xmlEdit { withNotes(it) }) }
        recordedCase("xml-crlf-line-ends", O, Spec.OPENS, same = "xml-lf-in-notes-base") { KdbxToolkit.build(l.xmlEdit { withNotes(it).replace("\r\n", "\n").replace("\n", "\r\n") }) }
    }

    // XML values and structure KeePass 2's KDBX 4 reader refuses where it reads them: UUIDs, value
    // elements with child elements, custom icon data, colors, entry String and Binary parts,
    // auto-type associations, attachment values that name no pool item, and a self-closing Group,
    // which pushes the group stack without an end that pops it. Each refusal has a case beside it
    // that opens.
    private fun xmlValues() {
        val l = weak.layers
        fun String.replaceOnce(old: String, new: String): String {
            check(old in this) { "no $old" }
            return replaceFirst(old, new)
        }
        // After the first entry's Tags, inside the entry KeePass 2 reads first.
        fun inFirstEntry(xml: String, element: String) = xml.replaceOnce("<Tags></Tags>\n", "<Tags></Tags>\n\t\t\t\t$element\n")
        fun inFirstAutoType(xml: String, element: String) =
            xml.replaceOnce("<DataTransferObfuscation>0</DataTransferObfuscation>\n", "<DataTransferObfuscation>0</DataTransferObfuscation>\n\t\t\t\t\t$element\n")
        // The root group's UUID is the first UUID element, the first entry's the second.
        fun uuidElement(xml: String, index: Int) = Regex("<UUID>[^<]*</UUID>").findAll(xml).elementAt(index).value
        recordedCase("xml-uuid-not-base64", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce(uuidElement(it, 0), "<UUID>not*base64</UUID>") }) }
        recordedCase("xml-uuid-12-bytes", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce(uuidElement(it, 1), "<UUID>AAAAAAAAAAAAAAAA</UUID>") }) }
        recordedCase("xml-uuid-empty", O, Spec.OPENS, same = null) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce(uuidElement(it, 1), "<UUID></UUID>") }) }
        recordedCase("xml-uuid-in-unknown-element", O, Spec.OPENS) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<KashPassUnknown><UUID>not*base64</UUID></KashPassUnknown>") }) }
        recordedCase("xml-value-with-child-element", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<Tags></Tags>", "<Tags>a<b/></Tags>") }) }
        recordedCase("xml-protected-value-with-child-element", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<Value>No password entry</Value>", "<Value Protected=\"True\">AAAA<b/></Value>") }) }
        recordedCase("xml-value-with-child-in-unknown-element", O, Spec.OPENS) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<KashPassUnknown><Tags>a<b/></Tags></KashPassUnknown>") }) }
        recordedCase("xml-icon-data-not-base64", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { it.insertBefore(metaEnd, "\t\t<CustomIcons><Icon><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID><Data>not*base64</Data></Icon></CustomIcons>\n") }) }
        recordedCase("xml-color-not-a-color", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<Color></Color>", "<Color>notacolor</Color>") }) }
        recordedCase("xml-color-hash-not-hex", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<Color></Color>", "<Color>#zzzzzz</Color>") }) }
        recordedCase("xml-color-named", O, Spec.OPENS) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<ForegroundColor></ForegroundColor>", "<ForegroundColor>Red</ForegroundColor>") }) }
        recordedCase("xml-color-rgb-list", O, Spec.OPENS) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<ForegroundColor></ForegroundColor>", "<ForegroundColor>10,20,30</ForegroundColor>") }) }
        recordedCase("xml-color-hex-short", O, Spec.OPENS) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<ForegroundColor></ForegroundColor>", "<ForegroundColor>#f00</ForegroundColor>") }) }
        recordedCase("xml-string-without-key", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<String><Value>v</Value></String>") }) }
        recordedCase("xml-string-without-value", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<String><Key>k</Key></String>") }) }
        recordedCase("xml-string-self-closing", O, Spec.OPENS) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<String />") }) }
        recordedCase("xml-string-empty-key", O, Spec.OPENS, same = null) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<String><Key></Key><Value>v</Value></String>") }) }
        recordedCase("xml-binary-without-key", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<Binary><Value Ref=\"0\" /></Binary>") }) }
        recordedCase("xml-binary-without-value", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<Binary><Key>k.txt</Key></Binary>") }) }
        recordedCase("xml-association-without-window", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { inFirstAutoType(it, "<Association><KeystrokeSequence>s</KeystrokeSequence></Association>") }) }
        recordedCase("xml-association-without-sequence", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { inFirstAutoType(it, "<Association><Window>w</Window></Association>") }) }
        recordedCase("xml-association-self-closing", O, Spec.OPENS) { KdbxToolkit.build(l.xmlEdit { inFirstAutoType(it, "<Association />") }) }
        recordedCase("xml-binary-inline-not-base64", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<Binary><Key>inline.txt</Key><Value>not*base64</Value></Binary>") }) }
        recordedCase("xml-binary-ref-missing-not-base64", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<Binary><Key>inline.txt</Key><Value Ref=\"7\">not*base64</Value></Binary>") }) }
        recordedCase("xml-binary-inline-base64", O, Spec.OPENS, same = null) { KdbxToolkit.build(l.xmlEdit { inFirstEntry(it, "<Binary><Key>inline.txt</Key><Value>${b64("inline".toByteArray())}</Value></Binary>") }) }
        recordedCase("xml-group-self-closing-in-group", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>\n", "<LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAAAA==</LastTopVisibleEntry>\n\t\t\t<Group />\n") }) }
        recordedCase("xml-group-self-closing-in-root", R, Spec.DAMAGED) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("\t<Root>\n", "\t<Root>\n\t\t<Group />\n") }) }
        // KeePass 2 makes the last Group it reads in any Root the root group.
        recordedCase("xml-root-empty-before-root", O, Spec.OPENS) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<KeePassFile>\n", "<KeePassFile>\n\t<Root></Root>\n") }) }
        recordedCase("xml-protected-context-element", O, Spec.OPENS_READ_ONLY) { KdbxToolkit.build(l.xmlEdit { it.replaceOnce("<String>", "<String Protected=\"True\">") }) }
    }

    // Entry parts KeePass 2 reads past: repeated Key or Value children of an entry String or Binary
    // (it keeps the last), separate Strings with one Key (it keeps the last), two History blocks
    // (one list) and a History inside a history entry (skipped). Each earlier copy goes in front of
    // the fixture's own element, so KeePass 2 reads the base content.
    private fun duplicateChildren() {
        val l = weak.layers
        // [base] with [text] inserted at the first [anchor], and the plaintexts [plain] of the
        // protected values [text] holds.
        fun insert(anchor: String, text: String, plain: List<String> = emptyList(), base: Layers = l): Layers {
            val xml = String(base.xml, Charsets.ISO_8859_1)
            val at = xml.indexOf(anchor)
            check(at >= 0) { "no $anchor" }
            val values = base.protectedValues.toMutableList()
            values.addAll(KdbxToolkit.protectedCountBefore(base.xml, at), plain.map { it.toByteArray() })
            return base.copy(xml = (xml.substring(0, at) + text + xml.substring(at)).toByteArray(Charsets.ISO_8859_1), protectedValues = values)
        }
        // Example Mail's password, the first protected value in the document.
        val mailPassword = Regex("<Value Protected=\"True\">[^<]*</Value>").find(String(l.xml, Charsets.ISO_8859_1))!!.value
        val bobUser = "<String>\n\t\t\t\t\t<Key>UserName</Key>\n\t\t\t\t\t<Value>bob</Value>"
        case(
            "xml-string-value-twice", O, Spec.OPENS,
        ) {
            KdbxToolkit.build(insert(mailPassword, "<Value Protected=\"True\">AAAA</Value>\n\t\t\t\t\t\t", listOf("earlier password")))
        }
        case(
            "xml-string-key-twice", O, Spec.OPENS,
        ) { KdbxToolkit.build(insert("<Key>UserName</Key>\n\t\t\t\t\t<Value>bob</Value>", "<Key>Login</Key>\n\t\t\t\t\t")) }
        case(
            "xml-string-same-key-twice", O, Spec.OPENS,
        ) {
            KdbxToolkit.build(insert(bobUser, "<String>\n\t\t\t\t\t<Key>UserName</Key>\n\t\t\t\t\t<Value>earlier</Value>\n\t\t\t\t</String>\n\t\t\t\t"))
        }
        case(
            "xml-binary-value-twice", O, Spec.OPENS,
        ) {
            val pool = l.innerWith { it.beforeEnd(RawField(KdbxToolkit.INNER_BINARY, byteArrayOf(0) + "earlier attachment".toByteArray())) }
            KdbxToolkit.build(insert("<Value Ref=\"0\" />", "<Value Ref=\"1\" />\n\t\t\t\t\t\t", base = pool))
        }
        case(
            "xml-binary-key-twice", O, Spec.OPENS,
        ) { KdbxToolkit.build(insert("<Key>recovery-codes.txt</Key>", "<Key>earlier.txt</Key>\n\t\t\t\t\t\t")) }
        val betweenHistoryItems = "\t\t\t\t\t\t</Entry>\n\t\t\t\t\t\t<Entry>"
        case(
            "xml-history-two-blocks", O, Spec.OPENS,
        ) {
            val split = "\t\t\t\t\t\t</Entry>\n\t\t\t\t\t</History>\n\t\t\t\t\t<History>\n\t\t\t\t\t\t<Entry>"
            KdbxToolkit.build(l.xmlEdit { check(betweenHistoryItems in it); it.replaceFirst(betweenHistoryItems, split) })
        }
        case(
            "xml-history-in-history-entry", O, Spec.OPENS,
        ) {
            val nested = "\t\t\t\t\t\t\t<History>\n\t\t\t\t\t\t\t\t<Entry>\n\t\t\t\t\t\t\t\t\t<UUID>X7bLXO6lmUunMo5tXbVQ8w==</UUID>\n" +
                "\t\t\t\t\t\t\t\t\t<String>\n\t\t\t\t\t\t\t\t\t\t<Key>Password</Key>\n\t\t\t\t\t\t\t\t\t\t<Value Protected=\"True\">AAAA</Value>\n\t\t\t\t\t\t\t\t\t</String>\n" +
                "\t\t\t\t\t\t\t\t</Entry>\n\t\t\t\t\t\t\t</History>\n"
            KdbxToolkit.build(insert(betweenHistoryItems, nested, listOf("nested password")))
        }
    }

    private fun truncation() {
        val bytes = KdbxToolkit.build(weak.layers)
        for (cut in bytes.indices) case("truncated-at-$cut", R, Spec.DAMAGED) { bytes.copyOf(cut) }
        val m = KdbxToolkit.build(multi.layers)
        val header = multi.layers.header.headerBytes().size + 64
        val starts = multi.blocks.runningFold(header) { at, b -> at + 36 + b.data.size }
        // The start of every block, the first one (right after the header) included.
        for (s in starts.dropLast(1)) {
            for (cut in listOf(s - 1, s, s + 1)) case("truncated-multi-at-$cut", R, Spec.DAMAGED) { m.copyOf(cut) }
        }
    }

}

/**
 * The corrupted-file corpus: every case is built by [KdbxToolkit] from a KeePass 2 fixture with
 * the throwaway password and fixed seeds, so its bytes are the same on every build. Each case
 * records what KeePass 2 does with it and what KashPass's decoder must do ([Spec]). The
 * default suite checks KashPass's decoder's outcome; the gated KeePass 2 run checks KeePass 2's.
 */
object Corpus {

    /** Size of the whitespace run inside the bomb's XML. */
    const val BOMB_BYTES = 512L * 1024 * 1024

    /** Every case, in a fixed order, built once per JVM. */
    val all: List<CorpusCase> by lazy { CorpusRecipes().build() }

    /** Builds every case again from the fixtures, base vaults included, with fresh bytes. */
    fun rebuild(): List<CorpusCase> = CorpusRecipes().build()
}
