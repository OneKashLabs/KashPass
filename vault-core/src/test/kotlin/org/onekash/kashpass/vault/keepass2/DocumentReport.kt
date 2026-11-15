package org.onekash.kashpass.vault.keepass2

import java.util.Base64
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.parseInt32Invariant
import org.onekash.kashpass.vault.kdbx.Attachment
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.kdbx.Compression
import org.onekash.kashpass.vault.kdbx.KdfParameters
import org.onekash.kashpass.vault.kdbx.OuterCipher
import org.onekash.kashpass.vault.keepass2.KeePass2Report.Companion.escape
import org.onekash.kashpass.vault.keepass2.KeePass2Report.Companion.mac
import org.onekash.kashpass.vault.testing.Gzip
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawKdbx
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * Builds the report KeePass 2's report mode writes, from what KashPass's own container opens
 * ([ContainerDecode]) or from a document a save writes, so the gated tests compare KashPass's
 * reading and save with KeePass 2's reading. The tree is read as KeePass 2 builds it:
 * the last root group, an entry's last String or Binary of a name with its last Key and Value,
 * the entries of every History block as one history, an attachment from the pool item its Ref
 * named when read or from its inline value.
 */
object DocumentReport {

    /** Opens [file] with its throwaway credentials and reports it, or why it was refused. */
    fun of(file: VaultFile, key: ByteArray): KeePass2Report = when (val r = ContainerRig.open(file)) {
        is ContainerDecode.Result.Opened -> {
            val raw = RawKdbx.parse(file.bytes)
            val h = r.read.container.header
            KeePass2Report.Opened(lines(Tree(r.read.xml.root, r.read.protectedValues, r.read.references::get), "${raw.major}.${raw.minor}", h.cipher, h.kdf, h.compression, key))
        }
        is ContainerDecode.Result.Refused -> KeePass2Report.Refused("refused by policy: ${r.rejection}")
        is ContainerDecode.Result.Failed -> KeePass2Report.Refused(r.result.toString())
    }

    /**
     * Reports [document] as a save of it is read: the minor version the save writes, the cipher,
     * KDF and compression of its save settings, and each entry attachment `Ref` n naming
     * attachment n of the document.
     */
    fun of(document: VaultDocument, key: ByteArray): KeePass2Report {
        val pooled = { value: XmlElement -> value.attribute("Ref")?.let { parseInt32Invariant(it) }?.let { document.attachments.getOrNull(it) } }
        val s = document.settings
        return KeePass2Report.Opened(lines(Tree(document.xml.root, document.protectedValues, pooled), "4.${document.savedMinor()}", s.cipher, s.kdf, s.compression, key))
    }

    // The XML tree, its protected values and the attachment each entry attachment value names.
    private class Tree(val root: XmlElement, val protectedValues: Map<XmlElement, ProtectedText>, val pooled: (XmlElement) -> Attachment?)

    private fun lines(read: Tree, version: String, cipher: OuterCipher, kdf: KdfParameters, compression: Compression, key: ByteArray): List<String> {
        val out = mutableListOf<String>()
        out += "version $version"
        out += "cipher ${hex(cipher)}"
        out += "kdf " + when (kdf) {
            is KdfParameters.Aes -> KdbxToolkit.AES_KDF
            is KdfParameters.Argon2 ->
                if (kdf.type == org.onekash.kashpass.vault.kdbx.Argon2Type.ARGON2D) KdbxToolkit.ARGON2D else KdbxToolkit.ARGON2ID
        }.replace("-", "")
        out += "compression " + if (compression == Compression.GZIP) "gzip" else "none"
        val root = read.root
        out += "name ${escape(root.children("Meta").flatMap { it.children("DatabaseName") }.lastOrNull()?.let { text(read, it) }.orEmpty())}"
        val group = root.children("Root").flatMap { it.children("Group") }.lastOrNull() ?: error("no root group")
        group(out, read, group, 0, key)
        return out
    }

    private fun group(out: MutableList<String>, read: Tree, g: XmlElement, depth: Int, key: ByteArray) {
        out += "group $depth ${escape(last(read, g, "Name"))} tags=${tags(last(read, g, "Tags"))}"
        for (e in g.children("Entry")) {
            val history = e.children("History").flatMap { it.children("Entry") }
            val quality = last(read, e, "QualityCheck") != "False"
            // A self-closing Entry has no end, so KeePass 2 keeps its zero UUID.
            val id = if (e.selfClosing) "0".repeat(32) else uuid(last(read, e, "UUID"))
            out += "entry ${depth + 1} $id qualityCheck=${if (quality) "on" else "off"} " +
                "tags=${tags(last(read, e, "Tags"))} history=${history.size}"
            entry(out, read, e, key)
            history.forEachIndexed { i, h ->
                out += "history $i"
                entry(out, read, h, key)
            }
        }
        for (sub in g.children("Group")) group(out, read, sub, depth + 1, key)
    }

    private fun entry(out: MutableList<String>, read: Tree, e: XmlElement, key: ByteArray) {
        val fields = sortedMapOf<String, String>(Comparator { a, b -> ordinal(a, b) })
        for (s in e.children("String")) {
            val value = s.children("Value").lastOrNull() ?: continue
            val protected = read.protectedValues[value] != null
            fields[last(read, s, "Key")] = "${if (protected) "*" else "-"} ${mac(key, text(read, value).toByteArray(Charsets.UTF_8))}"
        }
        for ((name, line) in fields) out += "field ${escape(name)} $line"
        val attachments = sortedMapOf<String, String>(Comparator { a, b -> ordinal(a, b) })
        for (b in e.children("Binary")) {
            val value = b.children("Value").lastOrNull() ?: continue
            val pooled = read.pooled(value)
            val inlineProtected = read.protectedValues[value]
            val (protected, data) = when {
                pooled != null -> pooled.protected to pooled.data
                inlineProtected != null -> true to inlineProtected.utf8()
                else -> {
                    val raw = Base64.getMimeDecoder().decode(value.text())
                    false to if (raw.isNotEmpty() && value.attribute("Compressed") == "True") Gzip.decompress(raw) else raw
                }
            }
            attachments[last(read, b, "Key")] = "${if (protected) "*" else "-"} ${data.size} ${mac(key, data)}"
        }
        for ((name, line) in attachments) out += "attachment ${escape(name)} $line"
    }

    // Ordinal order over UTF-16 code units, the order the KeePass 2 report sorts by.
    private fun ordinal(a: String, b: String): Int = a.compareTo(b)

    // The text KeePass 2 reads for the last child [name] of [e]: a protected one decrypted, and
    // decoded as UTF-8, an invalid sequence replaced with U+FFFD.
    private fun last(read: Tree, e: XmlElement, name: String): String = e.children(name).lastOrNull()?.let { text(read, it) }.orEmpty()

    private fun text(read: Tree, e: XmlElement): String = read.protectedValues[e]?.utf8()?.let { String(it, Charsets.UTF_8) } ?: e.text()

    // Tags: split on ',' and ';', trimmed, no empty or repeated tag, sorted.
    private fun tags(text: String): String =
        text.split(',', ';').map { it.trim() }.filter { it.isNotEmpty() }.distinct().sorted().joinToString(",") { escape(it) }

    private fun uuid(base64: String): String {
        val bytes = runCatching { Base64.getDecoder().decode(base64.trim()) }.getOrDefault(ByteArray(0))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun hex(cipher: OuterCipher) = cipher.uuid.toString().replace("-", "")
}
