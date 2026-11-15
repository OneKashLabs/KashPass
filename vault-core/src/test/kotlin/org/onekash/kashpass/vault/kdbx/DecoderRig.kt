package org.onekash.kashpass.vault.kdbx

import org.onekash.kashpass.vault.corpus.CorpusCase
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawKdbx

/**
 * Runs KashPass's header reader and decoder on a file with the transformed key the test toolkit
 * derives, so decoder tests don't depend on KashPass's KDF.
 */
internal object DecoderRig {

    const val LIMIT = 16 * 1024 * 1024

    fun key(file: VaultFile) = KdbxToolkit.Key(TestFiles.password(file.mode), TestFiles.keyFilePart(file))

    /** The toolkit's transformed key for [bytes], or null when the toolkit can't derive one. */
    fun transformed(bytes: ByteArray, key: KdbxToolkit.Key): ByteArray? = try {
        KdbxToolkit.derive(KdbxToolkit.effective(RawKdbx.parse(bytes)).kdf, key)
    } catch (e: Exception) {
        null
    }

    /**
     * The decoder's result for [bytes] with [transformed] as the KDF's output, or the header
     * reader's refusal.
     */
    fun decode(
        bytes: ByteArray,
        transformed: () -> ByteArray,
        buffers: Buffers = Buffers.Default,
        step: (KdbxDecoder.Step) -> Unit = {},
        limit: Int = LIMIT,
    ): KdbxResult = when (val read = KdbxHeaderReader.read(bytes)) {
        is KdbxHeaderReader.Read.Invalid -> read.result
        is KdbxHeaderReader.Read.Valid -> KdbxDecoder.decode(bytes, read.header, ByteArray(32), { _, _ -> transformed() }, limit, buffers, step)
    }

    /** [decode] for a corpus case, or null when no key can be derived for it. */
    fun decode(case: CorpusCase): KdbxResult? {
        val read = KdbxHeaderReader.read(case.bytes)
        if (read is KdbxHeaderReader.Read.Invalid) return read.result
        val t = transformed(case.bytes, key(case.file())) ?: return null
        return decode(case.bytes, { t.copyOf() })
    }
}
