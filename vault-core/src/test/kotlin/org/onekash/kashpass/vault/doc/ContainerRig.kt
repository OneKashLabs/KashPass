package org.onekash.kashpass.vault.doc

import java.util.concurrent.ConcurrentHashMap
import org.onekash.kashpass.vault.corpus.CorpusCase
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.kdbx.Buffers
import org.onekash.kashpass.vault.kdbx.KdfParameters
import org.onekash.kashpass.vault.testing.KdbxToolkit

/** Opens test vaults through [ContainerDecode] with their throwaway credentials. */
internal object ContainerRig {

    /** The limits the corpus outcomes assume: 16 MiB of decompressed content. */
    val LIMITS = VaultXmlCodec.Limits(open = 16 * 1024 * 1024, save = 8L * 1024 * 1024)

    /**
     * The heap the corpus outcomes assume where a case names none ([CorpusCase.heapBytes]): the
     * header dictionaries are read within its budget, and Argon2 memory above half of it is not
     * enough memory.
     */
    const val HEAP = 1L shl 30

    private val engine = KdfEngine()
    private val derived = ConcurrentHashMap<String, ByteArray>()

    /** KdfEngine's derivation, kept per parameters and key so the corpus derives each once. */
    val derive: (KdfParameters, ByteArray) -> ByteArray = { p, composite ->
        val id = describe(p) + "/" + composite.joinToString("") { "%02x".format(it) }
        derived.getOrPut(id) { engine.derive(p, composite) }.copyOf()
    }

    private fun describe(p: KdfParameters): String = when (p) {
        is KdfParameters.Aes -> "aes ${p.rounds} ${p.seed.toList()}"
        is KdfParameters.Argon2 -> "argon2 ${p.type} ${p.salt.toList()} ${p.parallelism} ${p.memoryBytes} ${p.iterations} ${p.version} ${p.secretKey?.toList()} ${p.associatedData?.toList()}"
    }

    fun passwordHash(file: VaultFile): ByteArray? =
        TestFiles.password(file.mode)?.let { KdbxToolkit.sha256(it.encodeToByteArray()) }

    fun open(
        file: VaultFile,
        limits: VaultXmlCodec.Limits = LIMITS,
        buffers: Buffers = Buffers.Default,
        maxHeapBytes: Long = HEAP,
        onXml: (ByteArray, Int, Int) -> Unit = { _, _, _ -> },
    ): ContainerDecode.Result =
        ContainerDecode.decode(
            file.bytes, passwordHash(file), TestFiles.keyFilePart(file), limits, Int.MAX_VALUE,
            maxHeapBytes = maxHeapBytes, derive = derive, buffers = buffers, onXml = onXml,
        )

    fun open(case: CorpusCase): ContainerDecode.Result = open(case.file(), maxHeapBytes = case.heapBytes ?: HEAP)
}
