package org.onekash.kashpass.vault.corpus

import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.Saveability
import org.onekash.kashpass.vault.doc.toSettings
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.policy.KdfPolicy
import org.onekash.kashpass.vault.testing.KdbxToolkit

/**
 * KashPass's decoder gives every corpus case its exact outcome: the [Spec] class, the damage layer
 * of a damaged case, and for an opened case whether it can be saved. Where the test toolkit opens
 * an opened case too, both decrypt the same XML bytes.
 */
class OwnedCorpusTest {

    private fun outcome(c: CorpusCase): String = when (val r = ContainerRig.open(c)) {
        is ContainerDecode.Result.Opened -> {
            val document = VaultXmlCodec.document(r.read, TestFiles.credentials(c.file()), ContainerRig.LIMITS)
            if (document.saveability == Saveability.Saveable) "OPENS" else "OPENS_READ_ONLY"
        }
        is ContainerDecode.Result.Refused -> "REFUSED_BY_POLICY"
        is ContainerDecode.Result.Failed -> when (val f = r.result) {
            KdbxResult.WrongKey -> "WRONG_KEY"
            is KdbxResult.Damaged -> "DAMAGED ${f.reason.name}"
            is KdbxResult.Unsupported -> "UNSUPPORTED"
            is KdbxResult.NotEnoughMemory -> "NOT_ENOUGH_MEMORY"
            is KdbxResult.TooLarge, is KdbxResult.Failed, is KdbxResult.Opened -> f.toString()
        }
    }

    private fun expected(c: CorpusCase): String = if (c.spec == Spec.DAMAGED) "DAMAGED ${c.damage}" else c.spec.name

    @Test
    fun `every corpus case gets its exact outcome`() {
        val wrong = Corpus.all.mapNotNull { c -> outcome(c).takeIf { it != expected(c) }?.let { "${c.name}: $it, expected ${expected(c)}" } }
        assertTrue(wrong.isEmpty(), "${wrong.size} cases:\n" + wrong.joinToString("\n"))
    }

    @Test
    fun `every policy refusal is refused by the header reader and KdfPolicy under its exception`() {
        val cases = Corpus.all.filter { it.spec == Spec.REFUSED_BY_POLICY }
        assertTrue(cases.isNotEmpty())
        val wrong = cases.filterNot { c ->
            val header = (KdbxHeaderReader.read(c.bytes) as? KdbxHeaderReader.Read.Valid)?.header
            when (c.policyException) {
                1 -> header != null && KdfPolicy.checkBounds(header.kdf.toSettings()) != null
                else -> false
            }
        }
        assertTrue(wrong.isEmpty(), wrong.joinToString { "${it.name} (exception ${it.policyException})" })
    }

    // KdbxToolkit shares no container code with KashPass's decoder; it throws on a file it can't
    // read, which leaves that case out.
    @Test
    fun `where the toolkit opens a case too, both decrypt the same XML bytes`() {
        var compared = 0
        val wrong = Corpus.all.filter { it.spec == Spec.OPENS || it.spec == Spec.OPENS_READ_ONLY }.mapNotNull { c ->
            val file = c.file()
            var ours: ByteArray? = null
            ContainerRig.open(file, maxHeapBytes = c.heapBytes ?: ContainerRig.HEAP, onXml = { b, off, len -> ours = b.copyOfRange(off, off + len) })
            val theirs = runCatching { KdbxToolkit.open(file.bytes, KdbxToolkit.Key(TestFiles.password(file.mode), TestFiles.keyFilePart(file))).layers.xml }.getOrNull()
            val mine = ours
            if (mine == null || theirs == null) return@mapNotNull null
            compared++
            if (mine.contentEquals(theirs)) null else c.name
        }
        assertTrue(compared >= 120, "$compared compared")
        assertTrue(wrong.isEmpty(), wrong.joinToString())
    }
}
