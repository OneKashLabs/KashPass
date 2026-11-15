package org.onekash.kashpass.vault.keepass2

import java.security.SecureRandom
import kotlin.test.assertTrue
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.Seen
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.KdbxHeaderWriter
import org.onekash.kashpass.vault.kdbx.SaveSettings
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawDictionary
import org.onekash.kashpass.vault.testing.RawKdbx

/**
 * KashPass's header writer writes the outer header KeePass 2 writes when it opens a file and
 * saves it again: the same signature, the same field ids in the same order with the same sizes,
 * the same KDF dictionary bytes but for the fresh salt or seed, and the same public custom data.
 * The master seed, the IV and the salt are random in both and are compared by size. The files are
 * every fixture and every corpus case KashPass opens editable and KeePass 2 opens. Runs with
 * -Pkashpass.keepass2 only.
 *
 * The inner header of KashPass's save of each file is KeePass 2's: inner stream id 3 with a
 * 64-byte key, and the same attachment pool, each item's protection flag and SHA-256 in pool
 * order. The accepted differences are [AllowedPoolDifference].
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2HeaderParityTest {

    @Test
    fun `KashPass writes the outer header KeePass 2 writes when it saves the same file`() {
        val cases = Corpus.all.filter { it.spec == Spec.OPENS && it.keepass2 == Seen.OPEN }
        assertTrue(cases.size > 50, "only ${cases.size} corpus cases")
        val files = Fixtures.kdbx4Opening.map { Fixtures.file(it) } + cases.map { it.file() }
        val resaved = KeePass2Run.keepass2Resave(files)
        val problems = files.flatMap { f ->
            val saved = resaved.getValue(f.name)
            val theirs = saved.bytes ?: return@flatMap listOf("${f.name}: KeePass 2 did not save it: ${saved.refusal}")
            differences(f, RawKdbx.parse(theirs)).map { "${f.name}: $it" }
        }
        if (problems.isNotEmpty()) fail("${problems.size} differences:\n" + problems.joinToString("\n"))
    }

    @Test
    fun `KashPass writes the inner header and attachment pool KeePass 2 writes when it saves the same file`() {
        val cases = Corpus.all.filter { it.spec == Spec.OPENS && it.keepass2 == Seen.OPEN }
        val files = Fixtures.kdbx4Opening.map { Fixtures.file(it) } + cases.map { it.file() }
        val resaved = KeePass2Run.keepass2Resave(files)
        val allowed = mutableListOf<String>()
        val problems = files.flatMap { f ->
            val theirs = resaved.getValue(f.name).bytes ?: return@flatMap listOf("${f.name}: KeePass 2 did not save it")
            innerDifferences(f, theirs, allowed).map { "${f.name}: $it" }
        }
        System.err.println("accepted pool differences:\n" + allowed.joinToString("\n"))
        if (problems.isNotEmpty()) fail("${problems.size} differences:\n" + problems.joinToString("\n"))
    }

    /** Why KashPass's pool can differ from KeePass 2's for the same file. */
    enum class AllowedPoolDifference {
        /** Inside one entry KashPass orders attachments by ordinal name, KeePass 2 by culture. */
        NAME_ORDER,

        /** KeePass 2 trims each entry's history on load. */
        HISTORY_TRIMMED,

        /** KeePass 2 moves an inline attachment value into the pool; KashPass keeps it inline. */
        INLINE_VALUE,

        /** KeePass 2 keeps only the last of two Binary elements with one key in an entry. */
        REPEATED_KEY,
    }

    private class Inner(val streamId: Int, val keySize: Int, val pool: List<String>)

    private fun inner(file: VaultFile): Inner? {
        val read = (ContainerRig.open(file) as? ContainerDecode.Result.Opened)?.read ?: return null
        val inner = read.container.inner
        return Inner(inner.streamId, inner.streamKey.size, inner.attachments.map { "${if (it.protected) "P" else "-"} ${KdbxToolkit.sha256(it.data).joinToString("") { b -> "%02x".format(b) }}" })
            .also { read.zeroFill() }
    }

    // What differs between KeePass 2's save [theirBytes] of [file] and KashPass's; an accepted
    // difference is added to [allowed] instead.
    private fun innerDifferences(file: VaultFile, theirBytes: ByteArray, allowed: MutableList<String>): List<String> {
        val read = (ContainerRig.open(file) as? ContainerDecode.Result.Opened)?.read ?: return listOf("KashPass does not open it")
        val document = VaultXmlCodec.document(read, TestFiles.credentials(file), ContainerRig.LIMITS)
        val ours = inner(VaultFile(file.name, VaultXmlCodec.encodeBytes(document), file.mode, file.keyFileName, file.keyFile))
            ?: return listOf("KashPass's save does not open")
        val theirs = inner(VaultFile(file.name, theirBytes, file.mode, file.keyFileName, file.keyFile)) ?: return listOf("KeePass 2's save does not open")
        val out = mutableListOf<String>()
        if (ours.streamId != theirs.streamId) out += "inner stream ${theirs.streamId}, KashPass ${ours.streamId}"
        if (ours.keySize != theirs.keySize) out += "inner stream key ${theirs.keySize} bytes, KashPass ${ours.keySize}"
        if (ours.pool == theirs.pool) return out
        val reasons = reasons(document)
        val explained = when {
            ours.pool.sorted() == theirs.pool.sorted() -> AllowedPoolDifference.NAME_ORDER.takeIf { it in reasons }
            theirs.pool.containsAll(ours.pool) -> AllowedPoolDifference.INLINE_VALUE.takeIf { it in reasons }
            ours.pool.containsAll(theirs.pool) -> listOf(AllowedPoolDifference.HISTORY_TRIMMED, AllowedPoolDifference.REPEATED_KEY).firstOrNull { it in reasons }
            else -> null
        }
        if (explained != null) allowed += "${file.name}: $explained" else out += "pool ${theirs.pool}, KashPass ${ours.pool}"
        return out
    }

    // The accepted differences [document]'s content can cause.
    private fun reasons(document: VaultDocument): Set<AllowedPoolDifference> {
        val out = HashSet<AllowedPoolDifference>()
        val maxItems = document.xml.root.child("Meta")?.child("HistoryMaxItems")?.text()?.trim()?.toIntOrNull() ?: 10
        fun walk(e: org.onekash.kashpass.vault.xml.XmlElement) {
            if (e.name == "Entry") {
                val keys = e.children("Binary").map { it.child("Key")?.text().orEmpty() }
                if (keys.sorted() != keys.sortedWith(String.CASE_INSENSITIVE_ORDER.thenBy { it })) out += AllowedPoolDifference.NAME_ORDER
                if (keys.size > 1 && keys.any { k -> k.any { it.code > 0x7F || !it.isLetterOrDigit() } }) out += AllowedPoolDifference.NAME_ORDER
                if (keys.toSet().size < keys.size) out += AllowedPoolDifference.REPEATED_KEY
                if (e.children("Binary").any { it.child("Value")?.attribute("Ref") == null }) out += AllowedPoolDifference.INLINE_VALUE
                val history = e.child("History")?.children("Entry").orEmpty()
                if (maxItems >= 0 && history.size > maxItems) out += AllowedPoolDifference.HISTORY_TRIMMED
            }
            e.elements().forEach(::walk)
        }
        walk(document.xml.root)
        return out
    }

    // What differs between KeePass 2's re-saved header [theirs] and the header KashPass writes
    // for [file].
    private fun differences(file: VaultFile, theirs: RawKdbx): List<String> {
        val opened = (KdbxHeaderReader.read(file.bytes) as? KdbxHeaderReader.Read.Valid)?.header ?: return listOf("KashPass does not read the header")
        // The minimum version the content needs is not the header writer's to compute, so this
        // takes KeePass 2's and applies KashPass's never-lower rule: the opened minor, capped at 1.
        val minor = maxOf(theirs.minor, minOf(opened.minorVersion, 1))
        val written = KdbxHeaderWriter.write(SaveSettings.from(opened), minor, SecureRandom())
        val ours = RawKdbx.parse((written as? KdbxHeaderWriter.Write.Written)?.bytes ?: return listOf("KashPass's header does not read back"))
        val out = mutableListOf<String>()
        if (!theirs.signature.contentEquals(ours.signature)) out += "signature"
        if (theirs.major != ours.major) out += "major version ${theirs.major}, KashPass ${ours.major}"
        // The one allowed difference: a file opened as 4.1 or later saves as 4.1 where KeePass 2
        // saves 4.0 for content without 4.1 features.
        val neverLower = ours.minor == 1 && theirs.minor == 0 && opened.minorVersion >= 1
        if (theirs.minor != ours.minor && !neverLower) out += "minor version ${theirs.minor}, KashPass ${ours.minor}"
        val theirIds = theirs.fields.map { it.id }
        val ourIds = ours.fields.map { it.id }
        if (theirIds != ourIds) return out + "field ids $theirIds, KashPass $ourIds"
        for ((t, o) in theirs.fields.zip(ours.fields)) {
            when (t.id) {
                RawKdbx.MASTER_SEED, RawKdbx.ENCRYPTION_IV -> if (t.data.size != o.data.size) out += "field ${t.id}: ${t.data.size} bytes, KashPass ${o.data.size}"
                RawKdbx.KDF_PARAMETERS -> out += kdfDifferences(t.data, o.data)
                else -> if (!t.data.contentEquals(o.data)) out += "field ${t.id} differs"
            }
        }
        return out
    }

    // Entry names, types and values must match, the salt or seed only in size; then the whole
    // dictionary must be KeePass 2's bytes once our salt is swapped for theirs.
    private fun kdfDifferences(theirBytes: ByteArray, ourBytes: ByteArray): List<String> {
        val theirs = RawDictionary.parse(theirBytes)
        val ours = RawDictionary.parse(ourBytes)
        val theirEntries = theirs.entries.map { it.key to it.type }
        val ourEntries = ours.entries.map { it.key to it.type }
        if (theirEntries != ourEntries) return listOf("KDF entries $theirEntries, KashPass $ourEntries")
        val out = mutableListOf<String>()
        for ((t, o) in theirs.entries.zip(ours.entries)) {
            if (t.key == "S") {
                if (t.value.size != o.value.size) out += "KDF S: ${t.value.size} bytes, KashPass ${o.value.size}"
            } else if (!t.value.contentEquals(o.value)) {
                out += "KDF ${t.key} differs"
            }
        }
        val theirSalt = theirs.entries.single { it.key == "S" }.value
        val swapped = ours.with("S", RawDictionary.BYTES, theirSalt).toBytes()
        if (out.isEmpty() && !swapped.contentEquals(theirBytes)) out += "KDF dictionary bytes differ"
        return out
    }
}
