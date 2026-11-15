package org.onekash.kashpass.vault.testing

import java.io.ByteArrayOutputStream
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.SecureRandom
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.ChaCha20ParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.onekash.kashpass.vault.doc.KdfEngine
import org.onekash.kashpass.vault.kdbx.Argon2Type
import org.onekash.kashpass.vault.kdbx.KdfParameters

/**
 * Takes a KDBX 4 test vault apart into every layer and puts it back together with valid hashes and
 * MACs, so a test can damage one layer behind the MACs that guard it: the outer header, the block
 * stream, the outer cipher and its padding, the gzip framing, the inner header, the XML and the
 * protected values. Test-only; the vaults are throwaway fixtures.
 *
 * Keys follow the KDBX header rules: fields apply in file order and the last one wins, KDBX 3
 * fields 5 and 6 turn the KDF into AES-KDF, an AES-KDF seed that is not 32 bytes is hashed with
 * SHA-256, and the inner stream falls back to outer fields 8 and 10, then to the ArcFour
 * variant. Argon2 goes through [KdfEngine], so it derives Argon2 keys only for settings inside
 * `KdfPolicy`'s bounds; [Layers.kdfHeader] builds a file with other settings under another key.
 */
object KdbxToolkit {

    /** The composite key inputs: a password (null for none) and a key-file part. */
    class Key(val password: String?, val keyPart: ByteArray? = null) {
        /**
         * SHA-256 over SHA-256 of the UTF-8 password and the key-file part, in that order. A lone
         * surrogate encodes as U+FFFD, as .NET's UTF-8 encoder writes it.
         */
        fun composite(): ByteArray {
            val parts = ByteArrayOutputStream()
            password?.let { parts.write(sha256(utf8(it))) }
            keyPart?.let { parts.write(it) }
            return sha256(parts.toByteArray())
        }

        private fun utf8(text: String): ByteArray {
            val out = Charsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE)
                .replaceWith(byteArrayOf(0xEF.toByte(), 0xBF.toByte(), 0xBD.toByte()))
                .encode(CharBuffer.wrap(text))
            return ByteArray(out.remaining()).also { out.get(it) }
        }
    }

    /** One block of the HMAC block stream as stored: MAC, the length field and the data. */
    class Block(val hmac: ByteArray, val declaredLength: Int, val data: ByteArray)

    /** Inner stream ids. */
    const val ARCFOUR_VARIANT = 1
    const val SALSA20 = 2
    const val CHACHA20 = 3

    const val INNER_END = 0
    const val INNER_STREAM_ID = 1
    const val INNER_STREAM_KEY = 2
    const val INNER_BINARY = 3

    const val AES_CIPHER = "31c1f2e6-bf71-4350-be58-05216afc5aff"
    const val CHACHA20_CIPHER = "d6038a2b-8b6f-4cb5-a524-339a31dbb59a"
    const val AES_KDF = "c9d9f39a-628a-4460-bf74-0d08c18a4fea"
    const val ARGON2D = "ef636ddf-8c29-444b-91f7-a9a403e30a0c"
    const val ARGON2ID = "9e298b19-56db-4773-b23d-fc3ec6f0a1e6"

    /**
     * The JDK's provider for ChaCha20: the app's Robolectric tests install Conscrypt as the
     * default provider, whose "ChaCha20" gives another keystream for the KDBX key and nonce.
     */
    const val JDK_PROVIDER = "SunJCE"

    /** The default KDBX 4 block size. */
    const val BLOCK_SIZE = 1024 * 1024

    /**
     * Every layer of a vault, editable with `copy`. [build] turns it back into a file: each layer
     * left null is computed from the layer above it, each one given is written as given.
     */
    data class Layers(
        val key: Key,
        /** The outer header fields; [RawKdbx.rest] is ignored. */
        val header: RawKdbx,
        /** Inner header fields in order, the end field included. */
        val inner: List<RawField>,
        /** The XML as stored, protected values encrypted with the inner stream. */
        val xml: ByteArray,
        /**
         * Plaintext of every protected value in document order, re-encrypted unless
         * [keepProtectedCiphertext].
         */
        val protectedValues: List<ByteArray>,
        val keepProtectedCiphertext: Boolean = false,
        /** Inner header and XML as one payload; null computes it from [inner] and [xml]. */
        val content: ByteArray? = null,
        /** The compressed payload; null compresses [content] when the header says gzip. */
        val compressed: ByteArray? = null,
        /** The plaintext the outer cipher encrypts; null pads [compressed] with PKCS#7 for AES. */
        val padded: ByteArray? = null,
        /** The outer ciphertext; null encrypts [padded]. */
        val ciphertext: ByteArray? = null,
        val blockSize: Int = BLOCK_SIZE,
        /** Edits the block list, end block included, after the MACs are computed. */
        val editBlocks: (Macs, List<Block>) -> List<Block> = { _, b -> b },
        /** Bytes after the end block. */
        val afterEnd: ByteArray = ByteArray(0),
        val headerHash: ByteArray? = null,
        val headerHmac: ByteArray? = null,
        /**
         * The header whose KDF settings derive the key; null uses [header]. For files whose own
         * settings no reader derives.
         */
        val kdfHeader: RawKdbx? = null,
        /**
         * The IV the outer cipher uses; null uses the header's. For an IV field of the wrong size.
         */
        val cipherIv: ByteArray? = null,
        // The file this was opened from, so an unedited layer keeps its original bytes.
        internal val source: Opened? = null,
    )

    /** The block and header MAC functions of one file, for tests that rebuild blocks. */
    class Macs(private val hmacBase: ByteArray) {
        /** The HMAC a KDBX 4 file stores for the block at [index] holding [data]. */
        fun block(index: Long, data: ByteArray): ByteArray =
            hmac(blockKey(index), le64(index) + le32(data.size) + data)

        /** A block at [index] holding [data] with its valid MAC. */
        fun validBlock(index: Long, data: ByteArray) = Block(block(index, data), data.size, data)

        /** The header HMAC over [headerBytes]. */
        fun header(headerBytes: ByteArray): ByteArray = hmac(blockKey(-1L), headerBytes)

        private fun blockKey(index: Long) = sha512(le64(index) + hmacBase)
    }

    /** A parsed vault: its layers as read and the derived keys. */
    class Opened internal constructor(
        val layers: Layers,
        val compressedBytes: ByteArray?,
        val contentBytes: ByteArray,
        val blocks: List<Block>,
        val transformedKey: ByteArray,
        val ciphertext: ByteArray,
    )

    /** Settings derived from the header fields in file order, with the KDBX defaults. */
    data class Effective(
        val cipher: ByteArray,
        val gzip: Boolean,
        val kdf: Kdf,
        val seed: ByteArray?,
        val iv: ByteArray?,
        val outerStreamKey: ByteArray?,
        val outerStreamId: Int?,
    )

    /** KDF settings as read from the header, with an AES-KDF [seed] of any length. */
    sealed interface Kdf {
        /**
         * Settings no reader can derive from; a file with them is built with [Layers.kdfHeader].
         */
        data object Unreadable : Kdf
        data class Aes(val rounds: ULong, val seed: ByteArray?) : Kdf
        data class Argon2(val id: Boolean, val salt: ByteArray, val parallelism: UInt, val memory: ULong, val iterations: ULong, val version: UInt, val secret: ByteArray?, val associated: ByteArray?) : Kdf
    }

    /** Opens a well-formed KDBX 4 [bytes] with [key]; throws when any hash or MAC is wrong. */
    fun open(bytes: ByteArray, key: Key): Opened = open(bytes, key) { derive(it, key) }

    /**
     * Opens [bytes] as [open] does with a [transformedKey] the caller has, for a file whose key no
     * reader derives (a fixed key in place of the KDF). The layers' [Layers.key] is a placeholder
     * [build] refuses; give the key the file was written with before a rebuild.
     */
    fun open(bytes: ByteArray, transformedKey: ByteArray): Opened = open(bytes, UNKNOWN_KEY) { transformedKey.copyOf() }

    private val UNKNOWN_KEY = Key(null, ByteArray(0))

    private fun open(bytes: ByteArray, key: Key, derive: (Kdf) -> ByteArray): Opened {
        val split = split(bytes)
        val header = split.header
        check(sha256(split.headerBytes).contentEquals(split.storedHash)) { "header SHA-256 does not match" }
        val effective = effective(header)
        val transformed = derive(effective.kdf)
        val ct = verifiedCiphertext(split, effective, transformed)
        val blocks = split.blocks
        val afterEnd = split.afterEnd
        val padded = decrypt(effective, transformed, ct)
        val compressed = if (isAes(effective)) unpad(padded) else padded
        val content = if (effective.gzip) Gzip.decompress(compressed) else compressed
        val (inner, xmlOffset) = parseInner(content)
        val xml = content.copyOfRange(xmlOffset, content.size)
        val stream = innerStream(inner, effective)
        val protectedValues = protectedValues(xml).map { stream.process(java.util.Base64.getDecoder().decode(it)) }
        val layers = Layers(
            key = key, header = header, inner = inner, xml = xml, protectedValues = protectedValues,
            blockSize = blocks.first().declaredLength.takeIf { blocks.size > 2 } ?: BLOCK_SIZE,
            afterEnd = afterEnd,
        )
        val opened = Opened(layers, if (effective.gzip) compressed else null, content, blocks, transformed, ct)
        return Opened(layers.copy(source = opened), opened.compressedBytes, content, blocks, transformed, ct)
    }

    /** A vault cut into its stored parts without deriving any key. */
    class Split(
        val header: RawKdbx,
        /** The outer header as stored, the bytes its SHA-256 and HMAC cover. */
        val headerBytes: ByteArray,
        val storedHash: ByteArray,
        val storedHmac: ByteArray,
        /** Every block up to and including the first empty one (the end block). */
        val blocks: List<Block>,
        val afterEnd: ByteArray,
    )

    /** Cuts a well-formed KDBX 4 [bytes] into header, hashes and blocks; checks no MAC. */
    fun split(bytes: ByteArray): Split {
        val header = RawKdbx.parse(bytes)
        val rest = header.rest
        val buf = ByteBuffer.wrap(rest, 64, rest.size - 64).order(ByteOrder.LITTLE_ENDIAN)
        val blocks = mutableListOf<Block>()
        while (true) {
            val hmac = ByteArray(32).also { buf.get(it) }
            val length = buf.int
            blocks += Block(hmac, length, ByteArray(length).also { buf.get(it) })
            if (length == 0) break
        }
        val afterEnd = ByteArray(buf.remaining()).also { buf.get(it) }
        return Split(header, header.headerBytes(), rest.copyOfRange(0, 32), rest.copyOfRange(32, 64), blocks, afterEnd)
    }

    /**
     * The outer-decrypted payload of [bytes] before decompression, AES padding removed. The
     * header HMAC and every block HMAC must be valid; the payload itself can be anything, so a
     * file with broken gzip data reads to this layer.
     */
    fun payload(bytes: ByteArray, key: Key): ByteArray {
        val split = split(bytes)
        return payload(split, derive(effective(split.header).kdf, key))
    }

    /** [payload] with a [transformedKey] the caller derived, for KDF settings [derive] refuses. */
    fun payload(bytes: ByteArray, transformedKey: ByteArray): ByteArray = payload(split(bytes), transformedKey)

    private fun payload(split: Split, transformedKey: ByteArray): ByteArray {
        val effective = effective(split.header)
        val padded = decrypt(effective, transformedKey, verifiedCiphertext(split, effective, transformedKey))
        return if (isAes(effective)) unpad(padded) else padded
    }

    // The data blocks joined, after the header HMAC and every block HMAC are checked.
    private fun verifiedCiphertext(split: Split, effective: Effective, transformedKey: ByteArray): ByteArray {
        val macs = macs(effective, transformedKey)
        check(macs.header(split.headerBytes).contentEquals(split.storedHmac)) { "header HMAC does not match (wrong key?)" }
        val ciphertext = ByteArrayOutputStream()
        split.blocks.forEachIndexed { index, block ->
            check(macs.block(index.toLong(), block.data).contentEquals(block.hmac)) { "block $index HMAC does not match" }
            ciphertext.write(block.data)
        }
        return ciphertext.toByteArray()
    }

    /** Builds the file [layers] describe. */
    fun build(layers: Layers): ByteArray {
        check(layers.key !== UNKNOWN_KEY) { "the layers were opened with a transformed key; give their key before a rebuild" }
        val source = layers.source
        val effective = effective(layers.header)
        val kdf = effective(layers.kdfHeader ?: layers.header).kdf
        val transformed = derive(kdf, layers.key)
        val xml = if (layers.keepProtectedCiphertext) layers.xml else reencrypt(layers.xml, layers.protectedValues, innerStream(layers.inner, effective))
        val content = layers.content ?: (innerBytes(layers.inner) + xml)
        val compressed = layers.compressed ?: when {
            !effective.gzip -> content
            source?.compressedBytes != null && source.contentBytes.contentEquals(content) -> source.compressedBytes
            else -> Gzip.compress(content)
        }
        val padded = layers.padded ?: if (isAes(effective)) pad(compressed) else compressed
        val ciphertext = layers.ciphertext ?: encrypt(layers.cipherIv?.let { effective.copy(iv = it) } ?: effective, transformed, padded)
        val macs = macs(effective, transformed)
        val blocks = mutableListOf<Block>()
        var offset = 0
        var index = 0L
        while (offset < ciphertext.size) {
            val end = minOf(ciphertext.size, offset + layers.blockSize)
            blocks += macs.validBlock(index++, ciphertext.copyOfRange(offset, end))
            offset = end
        }
        blocks += macs.validBlock(index, ByteArray(0))
        val headerBytes = layers.header.headerBytes()
        val out = ByteArrayOutputStream()
        out.write(headerBytes)
        out.write(layers.headerHash ?: sha256(headerBytes))
        out.write(layers.headerHmac ?: macs.header(headerBytes))
        for (b in layers.editBlocks(macs, blocks)) {
            out.write(b.hmac)
            out.write(le32(b.declaredLength))
            out.write(b.data)
        }
        out.write(layers.afterEnd)
        return out.toByteArray()
    }

    /**
     * Writes a new KDBX 4.[minor] vault for [key] with the toolkit's own header, inner header and
     * [build]: the standard KDBX 4 outer fields (cipher, compression, master seed, IV, KDF
     * dictionary, end), fresh random seed, IV, KDF salt or seed and inner stream key, [kdf] as the
     * KDF, then the inner header (stream id, stream key, one binary per [attachments] entry with
     * its protection flag, end) and [xml]. Each element of [xml] marked Protected="True" (written
     * with an explicit end tag) is stored as the next of [protectedValues] encrypted with
     * [innerStream] ([CHACHA20] with a 64-byte key, or [SALSA20] with a 32-byte key); with
     * [protectedValues] null, [xml] already holds its protected values encrypted under
     * [innerStreamKey].
     */
    fun newVault(
        xml: ByteArray,
        protectedValues: List<ByteArray>?,
        key: Key,
        kdf: Kdf = Kdf.Aes(1_000UL, null),
        attachments: List<Pair<Boolean, ByteArray>> = emptyList(),
        cipher: String = AES_CIPHER,
        innerStream: Int = CHACHA20,
        gzip: Boolean = true,
        minor: Int = 0,
        innerStreamKey: ByteArray = freshBytes(if (innerStream == SALSA20) 32 else 64),
    ): ByteArray {
        val dictionary = when (kdf) {
            is Kdf.Aes -> RawDictionary(0x0100, listOf(RawEntry(RawDictionary.BYTES, "\$UUID", uuidBytes(AES_KDF)), RawEntry(RawDictionary.UINT64, "R", u64(kdf.rounds)), RawEntry(RawDictionary.BYTES, "S", kdf.seed ?: freshBytes(32))))
            is Kdf.Argon2 -> RawDictionary(
                0x0100,
                listOfNotNull(
                    RawEntry(RawDictionary.BYTES, "\$UUID", uuidBytes(if (kdf.id) ARGON2ID else ARGON2D)),
                    RawEntry(RawDictionary.BYTES, "S", kdf.salt), RawEntry(RawDictionary.UINT32, "P", u32(kdf.parallelism.toLong())),
                    RawEntry(RawDictionary.UINT64, "M", u64(kdf.memory)), RawEntry(RawDictionary.UINT64, "I", u64(kdf.iterations)),
                    RawEntry(RawDictionary.UINT32, "V", u32(kdf.version.toLong())),
                    kdf.secret?.let { RawEntry(RawDictionary.BYTES, "K", it) }, kdf.associated?.let { RawEntry(RawDictionary.BYTES, "A", it) },
                ),
            )
            Kdf.Unreadable -> error("a new vault needs readable KDF settings")
        }
        val header = RawKdbx(
            signature = byteArrayOf(0x03, 0xD9.toByte(), 0xA2.toByte(), 0x9A.toByte(), 0x67, 0xFB.toByte(), 0x4B, 0xB5.toByte()),
            minor = minor, major = 4,
            fields = listOf(
                RawField(RawKdbx.CIPHER_ID, uuidBytes(cipher)),
                RawField(RawKdbx.COMPRESSION, le32(if (gzip) 1 else 0)),
                RawField(RawKdbx.MASTER_SEED, freshBytes(32)),
                RawField(RawKdbx.ENCRYPTION_IV, freshBytes(if (cipher == AES_CIPHER) 16 else 12)),
                RawField(RawKdbx.KDF_PARAMETERS, dictionary.toBytes()),
                RawField(RawKdbx.END_OF_HEADER, byteArrayOf(0x0D, 0x0A, 0x0D, 0x0A)),
            ),
            rest = ByteArray(0),
        )
        val inner = listOf(
            RawField(INNER_STREAM_ID, le32(innerStream)),
            RawField(INNER_STREAM_KEY, innerStreamKey),
        ) + attachments.map { (protected, data) -> RawField(INNER_BINARY, byteArrayOf(if (protected) 1 else 0) + data) } +
            RawField(INNER_END, ByteArray(0))
        return build(Layers(key = key, header = header, inner = inner, xml = xml, protectedValues = protectedValues.orEmpty(), keepProtectedCiphertext = protectedValues == null))
    }

    /**
     * Writes a KDBX 3.1 vault: header fields 2 to 10 and the end field with 2-byte lengths,
     * AES-256, gzip, AES-KDF at [rounds] from fields 5 and 6, a Salsa20 inner stream (fields 8 and
     * 10), then the 32 stream start bytes and [xml] in a hashed block stream, padded with PKCS#7
     * and encrypted with AES-CBC. A `<Meta>` in [xml] gets the header's SHA-256 as its first
     * child, HeaderHash, which a KDBX 3.1 reader checks when present. [xml] must hold no protected
     * value.
     */
    fun newVault3(xml: ByteArray, key: Key, rounds: ULong = 6_000UL): ByteArray {
        val masterSeed = freshBytes(32)
        val transformSeed = freshBytes(32)
        val iv = freshBytes(16)
        val startBytes = freshBytes(32)
        val header = ByteArrayOutputStream()
        header.write(byteArrayOf(0x03, 0xD9.toByte(), 0xA2.toByte(), 0x9A.toByte(), 0x67, 0xFB.toByte(), 0x4B, 0xB5.toByte()))
        header.write(byteArrayOf(1, 0, 3, 0))
        fun field(id: Int, data: ByteArray) {
            header.write(id)
            header.write(byteArrayOf((data.size and 0xFF).toByte(), (data.size shr 8).toByte()))
            header.write(data)
        }
        field(RawKdbx.CIPHER_ID, uuidBytes(AES_CIPHER))
        field(RawKdbx.COMPRESSION, le32(1))
        field(RawKdbx.MASTER_SEED, masterSeed)
        field(RawKdbx.TRANSFORM_SEED, transformSeed)
        field(RawKdbx.TRANSFORM_ROUNDS, u64(rounds))
        field(RawKdbx.ENCRYPTION_IV, iv)
        field(RawKdbx.PROTECTED_STREAM_KEY, freshBytes(32))
        field(RawKdbx.STREAM_START_BYTES, startBytes)
        field(RawKdbx.INNER_RANDOM_STREAM_ID, le32(SALSA20))
        field(RawKdbx.END_OF_HEADER, byteArrayOf(0x0D, 0x0A, 0x0D, 0x0A))
        val headerHash = java.util.Base64.getEncoder().encodeToString(sha256(header.toByteArray()))
        val text = String(xml, Charsets.UTF_8).replaceFirst("<Meta>", "<Meta><HeaderHash>$headerHash</HeaderHash>")
        val blocks = ByteArrayOutputStream()
        val data = Gzip.compress(text.toByteArray(Charsets.UTF_8))
        blocks.write(le32(0))
        blocks.write(sha256(data))
        blocks.write(le32(data.size))
        blocks.write(data)
        blocks.write(le32(1))
        blocks.write(ByteArray(32))
        blocks.write(le32(0))
        val transformed = derive(Kdf.Aes(rounds, transformSeed), key)
        val cipherKey = sha256(masterSeed + transformed)
        val ciphertext = Cipher.getInstance("AES/CBC/NoPadding")
            .apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(cipherKey, "AES"), IvParameterSpec(iv)) }
            .doFinal(pad(startBytes + blocks.toByteArray()))
        return header.toByteArray() + ciphertext
    }

    private val random = SecureRandom()

    private fun freshBytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }

    /** The block and header MACs of [layers]' file, for tests that hand-build blocks. */
    fun macs(layers: Layers): Macs = macs(effective(layers.header), derive(effective(layers.kdfHeader ?: layers.header).kdf, layers.key))

    /** Folds the header fields in file order into the settings a reader uses. */
    fun effective(header: RawKdbx): Effective {
        var cipher = uuidBytes(AES_CIPHER)
        var gzip = true
        var kdf: Kdf = Kdf.Aes(600_000UL, null)
        var seed: ByteArray? = null
        var iv: ByteArray? = null
        var streamKey: ByteArray? = null
        var streamId: Int? = null
        for (f in header.fields) when (f.id) {
            RawKdbx.CIPHER_ID -> cipher = f.data
            RawKdbx.COMPRESSION -> gzip = f.data.any { it.toInt() != 0 }
            RawKdbx.MASTER_SEED -> seed = f.data
            RawKdbx.TRANSFORM_SEED -> kdf = ((kdf as? Kdf.Aes) ?: Kdf.Aes(600_000UL, null)).copy(seed = f.data)
            RawKdbx.TRANSFORM_ROUNDS -> kdf = if (f.data.size != 8) Kdf.Unreadable else ((kdf as? Kdf.Aes) ?: Kdf.Aes(600_000UL, null)).copy(rounds = readLe64(f.data))
            RawKdbx.ENCRYPTION_IV -> iv = f.data
            RawKdbx.PROTECTED_STREAM_KEY -> streamKey = f.data
            RawKdbx.INNER_RANDOM_STREAM_ID -> streamId = if (f.data.size >= 4) readLe32(f.data) else null
            RawKdbx.KDF_PARAMETERS -> kdf = runCatching { kdfOf(RawDictionary.parse(f.data)) }.getOrDefault(Kdf.Unreadable)
        }
        return Effective(cipher, gzip, kdf, seed, iv, streamKey, streamId)
    }

    private fun kdfOf(d: RawDictionary): Kdf {
        // The last entry for a name wins, and an entry of another type than the one requested reads
        // as absent.
        val last = d.entries.associateBy { it.key }
        fun bytes(name: String) = last[name]?.takeIf { it.type == RawDictionary.BYTES }?.value
        fun u32(name: String) = last[name]?.takeIf { it.type == RawDictionary.UINT32 && it.value.size == 4 }?.let { readLe32(it.value).toUInt() }
        fun u64(name: String) = last[name]?.takeIf { it.type == RawDictionary.UINT64 && it.value.size == 8 }?.let { readLe64(it.value) }
        val uuid = bytes("\$UUID")?.takeIf { it.size == 16 }?.let { java.util.UUID(ByteBuffer.wrap(it).long, ByteBuffer.wrap(it, 8, 8).long).toString() }
        return when (uuid) {
            AES_KDF -> Kdf.Aes(u64("R") ?: error("AES-KDF without rounds"), bytes("S"))
            ARGON2D, ARGON2ID -> Kdf.Argon2(
                id = uuid == ARGON2ID, salt = bytes("S") ?: error("Argon2 without a salt"),
                parallelism = u32("P") ?: error("no P"), memory = u64("M") ?: error("no M"),
                iterations = u64("I") ?: error("no I"), version = u32("V") ?: error("no V"),
                secret = bytes("K"), associated = bytes("A"),
            )
            else -> error("unknown KDF $uuid")
        }
    }

    private val derived = ConcurrentHashMap<String, ByteArray>()

    /** The transformed key derived from [kdf] and [key]; cached per settings and key. */
    fun derive(kdf: Kdf, key: Key): ByteArray {
        val composite = key.composite()
        val cacheKey = describe(kdf) + "/" + composite.joinToString("") { "%02x".format(it) }
        return derived.getOrPut(cacheKey) {
            when (kdf) {
                Kdf.Unreadable -> error("no reader derives a key from these KDF settings; give Layers.kdfHeader")
                is Kdf.Aes -> aesKdf(composite, kdf)
                is Kdf.Argon2 -> KdfEngine().derive(
                    KdfParameters.Argon2(
                        if (kdf.id) Argon2Type.ARGON2ID else Argon2Type.ARGON2D, kdf.salt, kdf.parallelism, kdf.memory, kdf.iterations,
                        kdf.version, kdf.secret, kdf.associated,
                    ),
                    composite,
                )
            }
        }.copyOf()
    }

    private fun describe(kdf: Kdf): String = when (kdf) {
        Kdf.Unreadable -> "unreadable"
        is Kdf.Aes -> "aes ${kdf.rounds} ${kdf.seed?.toList()}"
        is Kdf.Argon2 -> "argon2 ${kdf.id} ${kdf.salt.toList()} ${kdf.parallelism} ${kdf.memory} ${kdf.iterations} ${kdf.version} ${kdf.secret?.toList()} ${kdf.associated?.toList()}"
    }

    private fun aesKdf(composite: ByteArray, kdf: Kdf.Aes): ByteArray {
        val seed = kdf.seed ?: error("AES-KDF without a seed")
        val aesKey = if (seed.size == 32) seed else sha256(seed)
        val cipher = Cipher.getInstance("AES/ECB/NoPadding").apply { init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES")) }
        var block = composite.copyOf()
        var round = 0UL
        while (round < kdf.rounds) {
            block = cipher.doFinal(block)
            round++
        }
        return sha256(block)
    }

    private fun macs(effective: Effective, transformed: ByteArray): Macs =
        Macs(sha512((effective.seed ?: error("no master seed")) + transformed + byteArrayOf(1)))

    private fun isAes(effective: Effective) = effective.cipher.contentEquals(uuidBytes(AES_CIPHER))

    private fun cipherKey(effective: Effective, transformed: ByteArray) = sha256((effective.seed ?: error("no master seed")) + transformed)

    private fun encrypt(effective: Effective, transformed: ByteArray, plain: ByteArray): ByteArray = outer(Cipher.ENCRYPT_MODE, effective, transformed, plain)

    private fun decrypt(effective: Effective, transformed: ByteArray, data: ByteArray): ByteArray = outer(Cipher.DECRYPT_MODE, effective, transformed, data)

    private fun outer(mode: Int, effective: Effective, transformed: ByteArray, data: ByteArray): ByteArray {
        val key = SecretKeySpec(cipherKey(effective, transformed), if (isAes(effective)) "AES" else "ChaCha20")
        val iv = effective.iv ?: error("no IV")
        return if (isAes(effective)) {
            Cipher.getInstance("AES/CBC/NoPadding").apply { init(mode, key, IvParameterSpec(iv)) }.doFinal(data)
        } else {
            Cipher.getInstance("ChaCha20", JDK_PROVIDER).apply { init(mode, key, ChaCha20ParameterSpec(iv, 0)) }.doFinal(data)
        }
    }

    /** PKCS#7 padding to the AES block size. */
    fun pad(data: ByteArray): ByteArray {
        val n = 16 - data.size % 16
        return data + ByteArray(n) { n.toByte() }
    }

    private fun unpad(data: ByteArray): ByteArray {
        val n = data.last().toInt() and 0xFF
        check(n in 1..16 && data.size >= n && (1..n).all { data[data.size - it].toInt() and 0xFF == n }) { "bad padding" }
        return data.copyOf(data.size - n)
    }

    private fun parseInner(content: ByteArray): Pair<List<RawField>, Int> {
        val buf = ByteBuffer.wrap(content).order(ByteOrder.LITTLE_ENDIAN)
        val fields = mutableListOf<RawField>()
        while (true) {
            val id = buf.get().toInt() and 0xFF
            val data = ByteArray(buf.int).also { buf.get(it) }
            fields += RawField(id, data)
            if (id == INNER_END) break
        }
        return fields to buf.position()
    }

    /** Serializes inner header fields as given (id, declared length, data). */
    fun innerBytes(fields: List<RawField>): ByteArray {
        val out = ByteArrayOutputStream()
        for (f in fields) {
            out.write(f.id)
            out.write(le32(f.declaredLength))
            out.write(f.data)
        }
        return out.toByteArray()
    }

    /** The inner stream set up from [inner], falling back to the outer fields. */
    fun innerStream(inner: List<RawField>, effective: Effective): InnerStream {
        val id = inner.lastOrNull { it.id == INNER_STREAM_ID && it.data.size >= 4 }?.let { readLe32(it.data) } ?: effective.outerStreamId ?: ARCFOUR_VARIANT
        val key = inner.lastOrNull { it.id == INNER_STREAM_KEY }?.data ?: effective.outerStreamKey ?: error("no inner stream key")
        return InnerStream.create(id, key)
    }

    // Base64 of each element marked Protected="True" (string values, binaries, unknown elements),
    // in document order: every one of them takes its length of the inner stream.
    private val PROTECTED = Regex("<([A-Za-z]+)( [^<>]*)? Protected=\"True\"( [^<>]*)?>([^<]*)</\\1>")

    // Comments, processing instructions (the XML declaration included) and CDATA sections hold no
    // element, so no protected value is read inside them.
    private val NOT_MARKUP = Regex("""<!--.*?-->|<\?.*?\?>|<!\[CDATA\[.*?]]>""", RegexOption.DOT_MATCHES_ALL)

    // The protected elements of [text], found on a copy with every comment, processing
    // instruction and CDATA section blanked to spaces of the same length, so offsets match.
    private fun protectedMatches(text: String): List<MatchResult> {
        val markup = NOT_MARKUP.replace(text) { " ".repeat(it.value.length) }
        return PROTECTED.findAll(markup).toList()
    }

    /** The number of protected elements in [xml] that start before [offset]. */
    fun protectedCountBefore(xml: ByteArray, offset: Int): Int =
        protectedMatches(String(xml, Charsets.ISO_8859_1)).count { it.range.first < offset }

    private fun protectedValues(xml: ByteArray): List<String> {
        val text = String(xml, Charsets.ISO_8859_1)
        return protectedMatches(text).map { m -> text.substring(m.groups[4]!!.range.first, m.groups[4]!!.range.last + 1) }
    }

    /** The stored (encrypted) bytes of every protected element in [xml], in document order. */
    fun protectedCiphertexts(xml: ByteArray): List<ByteArray> =
        protectedValues(xml).map { java.util.Base64.getDecoder().decode(it) }

    private fun reencrypt(xml: ByteArray, values: List<ByteArray>, stream: InnerStream): ByteArray {
        val text = String(xml, Charsets.ISO_8859_1)
        val matches = protectedMatches(text)
        check(matches.size == values.size) { "the XML holds ${matches.size} protected values, ${values.size} given" }
        val out = StringBuilder(text.length)
        var at = 0
        for ((m, plain) in matches.zip(values)) {
            val content = m.groups[4]!!.range
            out.append(text, at, content.first).append(java.util.Base64.getEncoder().encodeToString(stream.process(plain)))
            at = content.last + 1
        }
        return out.append(text, at, text.length).toString().toByteArray(Charsets.ISO_8859_1)
    }

    /** Replaces the block at [index] of the built list (-1 is the end block) with [edit] of it. */
    fun Layers.editBlock(index: Int, edit: (Block) -> Block): Layers = copy(
        editBlocks = { _, b ->
            val at = if (index < 0) b.size + index else index
            b.toMutableList().also { it[at] = edit(b[at]) }
        },
    )

    /** Inserts [field] before the end field of an inner header. */
    fun List<RawField>.beforeEnd(field: RawField): List<RawField> = dropLast(1) + field + last()

    /** Replaces the data of the first field with [id]. */
    fun List<RawField>.replaceFirst(id: Int, data: ByteArray): List<RawField> =
        toMutableList().also { val i = indexOfFirst { f -> f.id == id }; it[i] = RawField(id, data) }

    /**
     * Replaces the inner stream id and key fields with [id] and [key] (protected values follow on
     * build).
     */
    fun withInnerStream(layers: Layers, id: Int, key: ByteArray): Layers = layers.copy(
        inner = layers.inner.map {
            when (it.id) {
                INNER_STREAM_ID -> RawField(INNER_STREAM_ID, le32(id))
                INNER_STREAM_KEY -> RawField(INNER_STREAM_KEY, key)
                else -> it
            }
        },
    )

    private fun readLe32(b: ByteArray): Int = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).int

    private fun readLe64(b: ByteArray): ULong = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).long.toULong()

    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    fun sha512(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(b)

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)
}

/** Gzip framing as RFC 1952 lays it out: a 10-byte header, raw deflate data, CRC-32, ISIZE. */
object Gzip {

    /** The header .NET's GZipStream writes: no flags, no time, XFL 4, OS 0. */
    val HEADER: ByteArray = byteArrayOf(0x1f, 0x8b.toByte(), 8, 0, 0, 0, 0, 0, 4, 0)

    /** One member holding [content] with a valid trailer. */
    fun compress(content: ByteArray): ByteArray = compressStream(sequenceOf(content))

    /**
     * One member over the concatenation of [parts], compressed as it streams, so content larger
     * than the heap never exists as one array.
     */
    fun compressStream(parts: Sequence<ByteArray>): ByteArray {
        val deflater = Deflater(Deflater.DEFAULT_COMPRESSION, true)
        val crc = CRC32()
        var size = 0L
        val out = ByteArrayOutputStream()
        out.write(HEADER)
        val buf = ByteArray(64 * 1024)
        for (part in parts) {
            crc.update(part)
            size += part.size
            deflater.setInput(part)
            while (!deflater.needsInput()) out.write(buf, 0, deflater.deflate(buf))
        }
        deflater.finish()
        while (!deflater.finished()) out.write(buf, 0, deflater.deflate(buf))
        deflater.end()
        out.write(le32(crc.value.toInt()))
        out.write(le32(size.toInt()))
        return out.toByteArray()
    }

    /**
     * Inflates the first member of [data], which must have no FEXTRA, FNAME or FCOMMENT.
     */
    fun decompress(data: ByteArray): ByteArray {
        check(data.size >= 18 && data[0] == 0x1f.toByte() && data[1] == 0x8b.toByte() && data[3].toInt() == 0) { "not a plain gzip member" }
        val inflater = Inflater(true)
        inflater.setInput(data, 10, data.size - 10)
        val out = ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        while (!inflater.finished()) {
            val n = inflater.inflate(buf)
            check(n > 0 || !inflater.needsInput()) { "gzip data cut" }
            out.write(buf, 0, n)
        }
        inflater.end()
        return out.toByteArray()
    }
}

/**
 * A KDBX inner random stream; [process] XORs its keystream.
 */
abstract class InnerStream {
    abstract fun process(data: ByteArray): ByteArray

    companion object {
        /**
         * The stream for [id] (1 ArcFour variant, 2 Salsa20, 3 ChaCha20) and [key].
         */
        fun create(id: Int, key: ByteArray): InnerStream {
            require(key.isNotEmpty()) { "empty inner stream key" }
            return when (id) {
                KdbxToolkit.ARCFOUR_VARIANT -> ArcFourVariant(key)
                KdbxToolkit.SALSA20 -> Salsa20(KdbxToolkit.sha256(key), byteArrayOf(0xE8.toByte(), 0x30, 0x09, 0x4B, 0x97.toByte(), 0x20, 0x5D, 0x2A))
                KdbxToolkit.CHACHA20 -> {
                    val hash = KdbxToolkit.sha512(key)
                    val cipher = Cipher.getInstance("ChaCha20", KdbxToolkit.JDK_PROVIDER).apply {
                        init(Cipher.ENCRYPT_MODE, SecretKeySpec(hash.copyOf(32), "ChaCha20"), ChaCha20ParameterSpec(hash.copyOfRange(32, 44), 0))
                    }
                    object : InnerStream() {
                        override fun process(data: ByteArray): ByteArray = cipher.update(data) ?: ByteArray(0)
                    }
                }
                else -> error("unknown inner stream id $id")
            }
        }
    }

    // The KDBX ArcFour variant: the key is used raw, the key setup swaps with entry 0, and the
    // first 512 bytes of keystream are dropped.
    private class ArcFourVariant(key: ByteArray) : InnerStream() {
        private val s = ByteArray(256) { it.toByte() }
        private var i = 0
        private var j = 0

        init {
            var jj = 0
            var k = 0
            for (w in 0 until 256) {
                jj = (jj + (s[w].toInt() and 0xFF) + (key[k].toInt() and 0xFF)) and 0xFF
                val t = s[0]; s[0] = s[jj]; s[jj] = t
                if (++k >= key.size) k = 0
            }
            process(ByteArray(512))
        }

        override fun process(data: ByteArray): ByteArray = ByteArray(data.size) { w ->
            i = (i + 1) and 0xFF
            j = (j + (s[i].toInt() and 0xFF)) and 0xFF
            val t = s[i]; s[i] = s[j]; s[j] = t
            (data[w].toInt() xor s[((s[i].toInt() and 0xFF) + (s[j].toInt() and 0xFF)) and 0xFF].toInt()).toByte()
        }
    }

    // Salsa20/20 with a 64-bit block counter starting at 0 (eSTREAM).
    private class Salsa20(key: ByteArray, nonce: ByteArray) : InnerStream() {
        private val state = IntArray(16)
        private val block = ByteArray(64)
        private var used = 64

        init {
            val k = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN)
            val n = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN)
            state[0] = 0x61707865; state[5] = 0x3320646e; state[10] = 0x79622d32; state[15] = 0x6b206574
            for (x in 0 until 4) state[1 + x] = k.getInt(4 * x)
            for (x in 0 until 4) state[11 + x] = k.getInt(16 + 4 * x)
            state[6] = n.getInt(0); state[7] = n.getInt(4)
        }

        override fun process(data: ByteArray): ByteArray = ByteArray(data.size) { w ->
            if (used == 64) next()
            (data[w].toInt() xor block[used++].toInt()).toByte()
        }

        private fun next() {
            val x = state.copyOf()
            fun qr(a: Int, b: Int, c: Int, d: Int) {
                x[b] = x[b] xor Integer.rotateLeft(x[a] + x[d], 7)
                x[c] = x[c] xor Integer.rotateLeft(x[b] + x[a], 9)
                x[d] = x[d] xor Integer.rotateLeft(x[c] + x[b], 13)
                x[a] = x[a] xor Integer.rotateLeft(x[d] + x[c], 18)
            }
            repeat(10) {
                qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11)
                qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14)
            }
            val out = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
            for (z in 0 until 16) out.putInt(4 * z, x[z] + state[z])
            if (++state[8] == 0) state[9]++
            used = 0
        }
    }
}
