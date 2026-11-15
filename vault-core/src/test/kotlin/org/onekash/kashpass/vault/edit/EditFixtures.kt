package org.onekash.kashpass.vault.edit

import java.time.Instant
import org.onekash.kashpass.vault.doc.KdbxTime
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.doc.VaultXmlCodecTest
import org.onekash.kashpass.vault.index.VaultIndex
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.xml.XmlBytes
import org.onekash.kashpass.vault.xml.XmlElement

/** Builders and probes shared by the edit tests. */
internal object EditFixtures {

    val T0: Instant = Instant.parse("2020-01-02T03:04:05Z")
    val NOW: Instant = Instant.parse("2026-10-20T12:00:00Z")

    fun t(instant: Instant) = KdbxTime.format(instant)

    fun uuid(n: Int) = org.onekash.kashpass.vault.doc.Uuids.format(java.util.UUID(0, n.toLong()))

    fun times(at: Instant = T0, usage: Int = 3) =
        "<Times><CreationTime>${t(at)}</CreationTime><LastModificationTime>${t(at)}</LastModificationTime>" +
            "<LastAccessTime>${t(at)}</LastAccessTime><ExpiryTime>${t(at)}</ExpiryTime><Expires>False</Expires>" +
            "<UsageCount>$usage</UsageCount><LocationChanged>${t(at)}</LocationChanged></Times>"

    fun string(key: String, value: String, protected: Boolean = false) =
        if (protected) "<String><Key>$key</Key><Value Protected=\"True\">{{p:$value}}</Value></String>"
        else "<String><Key>$key</Key><Value>$value</Value></String>"

    fun entry(n: Int, title: String, extra: String = "", at: Instant = T0, history: String = "") =
        "<Entry><UUID>${uuid(n)}</UUID><IconID>0</IconID>${times(at)}${string("Title", title)}${string("UserName", "user$n")}" +
            "${string("Password", "pass$n", protected = true)}$extra<AutoType><Enabled>True</Enabled></AutoType>" +
            (if (history.isEmpty()) "<History />" else "<History>$history</History>") + "</Entry>"

    fun group(n: Int, name: String, content: String, icon: Int = 48) =
        "<Group><UUID>${uuid(n)}</UUID><Name>$name</Name><IconID>$icon</IconID>${times()}$content</Group>"

    fun doc(entries: String, meta: String = "<Generator>test</Generator>", attachments: List<ByteArray> = emptyList(), minor: Int = 0): VaultDocument =
        VaultXmlCodecTest.decode(TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entries, meta = meta), attachments, minor), TestVaults.PASSWORD)

    fun id(n: Int) = java.util.UUID(0, n.toLong()).toString()

    /** Encodes and decodes [document], as a save followed by an unlock would. */
    fun reopened(document: VaultDocument) = VaultXmlCodecTest.decode(VaultXmlCodec.encodeBytes(document), TestVaults.PASSWORD)

    fun index(document: VaultDocument) = VaultIndex.from(document)

    fun entryElement(document: VaultDocument, n: Int): XmlElement {
        fun find(e: XmlElement): XmlElement? {
            if (e.name == "Entry" && e.parent?.name == "Group" && e.child("UUID")?.text() == uuid(n)) return e
            return e.elements().firstNotNullOfOrNull(::find)
        }
        return find(document.xml.root)!!
    }

    fun time(element: XmlElement, name: String): Instant? = element.child("Times")?.child(name)?.text()?.let(KdbxTime::parse)

    /** The document's XML with protected values shown as plaintext and [omit] entries left out. */
    fun xml(document: VaultDocument, omit: (XmlElement) -> Boolean = { false }): String = XmlBytes.text(
        document.xml,
        object : XmlBytes.TextHooks() {
            override fun omit(element: XmlElement) = omit(element)
            override fun text(element: XmlElement) =
                if (element.attribute("Protected") == "True") "[" + document.protectedValues[element]?.reveal() + "]" else null
        },
    )
}
