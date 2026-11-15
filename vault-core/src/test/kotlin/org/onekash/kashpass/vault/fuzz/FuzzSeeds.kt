package org.onekash.kashpass.vault.fuzz

import kotlin.random.Random
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.kdbx.DecoderRig
import org.onekash.kashpass.vault.testing.Gzip
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawKdbx

/**
 * The seed inputs of each fuzz target: derived from the corrupted corpus, and for the encode
 * targets from the fixtures' XML and fixed random choices.
 */
internal object FuzzSeeds {

    /** Every corpus file, whole. */
    val files: List<ByteArray> by lazy { Corpus.all.map { it.bytes } }

    // The payload of every corpus case whose MACs are valid for the toolkit's key, with its
    // compression.
    private val payloads: List<Pair<ByteArray, Boolean>> by lazy {
        Corpus.all.mapNotNull { c ->
            runCatching {
                val raw = RawKdbx.parse(c.bytes)
                val effective = KdbxToolkit.effective(raw)
                KdbxToolkit.payload(c.bytes, DecoderRig.key(c.file())) to effective.gzip
            }.getOrNull()
        }.distinctBy { it.first.contentHashCode() to it.second }
    }

    /** Inputs for the body and cross-decode targets. */
    val bodies: List<ByteArray> by lazy { payloads.map { (p, gzip) -> FuzzTargets.bodyInput(p, gzip) } }

    /**
     * The XML of every fixture and of every corpus case about the XML layer, dates and
     * Meta/Binaries.
     */
    val xml: List<ByteArray> by lazy {
        val fixtures = Fixtures.kdbx4Opening.map { Fixtures.file(it) }
        val cases = Corpus.all.filter { c -> listOf("xml-", "spec-date-", "spec-meta-binary-", "spec-inner-", "attachment-").any { c.name.startsWith(it) } }.map { it.file() }
        (fixtures + cases).mapNotNull { f -> runCatching { KdbxToolkit.open(f.bytes, DecoderRig.key(f)).layers.xml }.getOrNull() }
            .distinctBy { it.contentHashCode() }
    }

    /** Inner headers followed by their XML. */
    val innerHeaders: List<ByteArray> by lazy {
        payloads.mapNotNull { (p, gzip) -> if (gzip) runCatching { Gzip.decompress(p) }.getOrNull()?.takeIf { it.size <= 4 * 1024 * 1024 } else p }
            .distinctBy { it.contentHashCode() }
    }

    /** The KDF parameters and public custom data of every corpus header that parses. */
    val dictionaries: List<ByteArray> by lazy {
        Corpus.all.flatMap { c ->
            runCatching { RawKdbx.parse(c.bytes).fields.filter { it.id == RawKdbx.KDF_PARAMETERS || it.id == RawKdbx.PUBLIC_CUSTOM_DATA }.map { it.data } }.getOrDefault(emptyList())
        }.distinctBy { it.contentHashCode() }
    }

    /**
     * Inputs for the round-trip target: every combination of the first byte's settings bits,
     * followed by fixed random choices of attachments, protected values and edits.
     */
    val roundTrips: List<ByteArray> by lazy {
        (0 until 64).map { i -> byteArrayOf(i.toByte()) + Random(i).nextBytes(48 + i * 11) }
    }

    /** Inputs for the cross-encode target: each XML seed after a byte choosing its settings. */
    val crossEncodes: List<ByteArray> by lazy { xml.mapIndexed { i, x -> byteArrayOf((i * 7 % 64).toByte()) + x } }
}
