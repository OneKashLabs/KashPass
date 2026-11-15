package org.onekash.kashpass.vault.keepass2

import java.io.File
import kotlin.test.fail
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.CorpusCase
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.doc.InteropRoundTrip
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.Kdbx3Vaults
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile

/** The files the KeePass 2 tests hand to KeePass 2. */
object KeePass2Files {

    /** Returns every KDBX 4 fixture with its credentials. */
    fun fixtures(): List<VaultFile> = Fixtures.kdbx4.map { Fixtures.file(it) }

    /** Returns the KDBX 3.1 vaults built in code, with their key file. */
    fun kdbx3(): List<VaultFile> = Kdbx3Vaults.files

    /**
     * The bytes each interop round trip saved last, named after the fixture it started from;
     * computed once per JVM.
     */
    val interopSaves: List<VaultFile> by lazy {
        InteropRoundTrip.passwordFixtures.map { name ->
            Fixtures.file(Fixtures.named(name), "saved-$name", InteropRoundTrip.run(name, TestFiles.password, null))
        } + InteropRoundTrip.keyFileFixtures.map { (name, withPassword, key) ->
            Fixtures.file(Fixtures.named(name), "saved-$name", InteropRoundTrip.run(name, if (withPassword) TestFiles.password else "", key))
        }
    }

    /**
     * The folder for gated reports: vault-core/build/reports/keepass2, or keepass2-<v> when
     * `-Pkashpass.keepass=<v>` names a version, so a named run never replaces the pinned run's
     * reports.
     */
    val reportDir: File get() = File(TestFiles.root, "vault-core/build/reports/" + (KeePass2Run.namedVersion?.let { "keepass2-$it" } ?: "keepass2"))

    /** Writes the gated report [name] to [reportDir]. */
    fun writeReport(name: String, text: String) {
        reportDir.apply { mkdirs() }.resolve(name).writeText(text)
    }

    /**
     * The files KashPass saves for the save tests: every fixture that opens and every editable
     * corpus case, except a truncated one and an entry with an empty UUID, which KeePass 2 gives a
     * new random UUID on every read, so two reads never compare equal.
     */
    val saveSources: List<VaultFile> by lazy { Fixtures.kdbx4Opening.map { Fixtures.file(it) } + saveCases.map { it.file() } }

    /** The editable corpus cases in [saveSources]. */
    val saveCases: List<CorpusCase> by lazy { Corpus.all.filter { it.spec == Spec.OPENS && !it.name.startsWith("truncated") && it.name != "xml-uuid-empty" } }

    /**
     * Returns KashPass's save of [f] with no edit, as the save tests hand it to KeePass 2: opened
     * by KashPass's container and encoded again; named [name], with [f]'s credentials.
     */
    fun kashPassSave(f: VaultFile, name: String = "saved-${f.name}"): VaultFile {
        val read = (ContainerRig.open(f) as? ContainerDecode.Result.Opened)?.read ?: fail("${f.name} does not open")
        val bytes = VaultXmlCodec.encodeBytes(VaultXmlCodec.document(read, TestFiles.credentials(f), ContainerRig.LIMITS))
        return VaultFile(name, bytes, f.mode, f.keyFileName, f.keyFile)
    }

    /** Returns [items] as a Markdown bullet list. */
    fun bullets(items: List<String>): String = items.joinToString("\n") { "- $it" }

    /** Returns the performance vault, generated locally and never committed; null when absent. */
    fun performance(): VaultFile? =
        File(TestFiles.root, "build/fixtures/keepass2-performance.kdbx").takeIf { it.isFile }?.let { VaultFile(it.name, it.readBytes()) }
}
