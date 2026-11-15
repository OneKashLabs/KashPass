package org.onekash.kashpass.vault.doc

import kotlin.test.assertEquals
import kotlin.test.assertIs
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.onekash.kashpass.vault.doc.KdbxXmlContext.Action
import org.onekash.kashpass.vault.doc.KdbxXmlContext.Context
import org.onekash.kashpass.vault.doc.KdbxXmlContext.Value
import org.onekash.kashpass.vault.doc.VaultXmlCodecTest.Companion.credentials
import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * KashPass's XML walk refuses a malformed value only where a KDBX 4 reader context
 * ([KdbxXmlContext]) reads the element, and opens the rest.
 */
class KdbxXmlContextTest {

    private val limits = VaultXmlCodec.Limits(1 shl 24, 1L shl 24)

    private fun open(xml: String, attachments: List<ByteArray> = emptyList()): Decoded =
        VaultXmlCodec.decode(TestVaults.rawXmlVault(xml, attachments), credentials(TestVaults.PASSWORD), limits)

    private fun entries(entries: String) = open(TestVaults.keePassXml(entries = entries))

    private fun meta(meta: String) = open(TestVaults.keePassXml(meta = "<Generator>t</Generator>$meta"))

    private val damaged = Decoded.Damaged(DamageReason.XML)

    private fun entry(inner: String) = "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>$inner</Entry>"

    private fun string(key: String, value: String) = "<String><Key>$key</Key><Value>$value</Value></String>"

    @Test
    fun `the action table follows ReadXmlElement for the contexts KeePass 2 writes`() {
        assertEquals(Action.Switch(Context.KEEPASS_FILE), KdbxXmlContext.action(Context.NULL, "KeePassFile", false, false))
        assertEquals(Action.Unknown, KdbxXmlContext.action(Context.NULL, "Other", false, false))
        assertEquals(Action.Read(Value.UUID), KdbxXmlContext.action(Context.GROUP, "UUID", false, false))
        assertEquals(Action.Read(Value.COLOR), KdbxXmlContext.action(Context.ENTRY, "ForegroundColor", false, false))
        assertEquals(Action.Unknown, KdbxXmlContext.action(Context.ENTRY, "Name", false, false))
        assertEquals(Action.Switch(Context.ENTRY_HISTORY), KdbxXmlContext.action(Context.ENTRY, "History", false, false))
        assertEquals(Action.Unknown, KdbxXmlContext.action(Context.ENTRY, "History", true, false))
        assertEquals(Action.Read(Value.META_BINARY), KdbxXmlContext.action(Context.BINARIES, "Binary", false, true))
        assertEquals(Action.Unknown, KdbxXmlContext.action(Context.BINARIES, "Binary", false, false))
        assertEquals(Action.Read(Value.TEXT), KdbxXmlContext.action(Context.GROUP_CUSTOM_DATA_ITEM, "Value", false, false))
        assertEquals(Action.Unknown, KdbxXmlContext.action(Context.GROUP_CUSTOM_DATA_ITEM, "LastModificationTime", false, false))
        assertEquals(Action.Read(Value.TIME), KdbxXmlContext.action(Context.CUSTOM_DATA_ITEM, "LastModificationTime", false, false))
        assertEquals(Action.Unknown, KdbxXmlContext.action(Context.KEEPASS_FILE, "Group", false, false))
    }

    @ParameterizedTest
    @ValueSource(strings = ["not*base64", "AAAA", "AAAAAAAAAAAAAAAAAAAAAAA="])
    fun `a UUID KeePass 2 reads that is not Base64 of 16 bytes is refused`(uuid: String) {
        assertEquals(damaged, entries(entry("").replace("AAAAAAAAAAAAAAAAAAAAAg==", uuid)))
        assertEquals(damaged, meta("<RecycleBinUUID>$uuid</RecycleBinUUID>"))
        assertEquals(damaged, open(TestVaults.keePassXml().replace("<DeletedObjects />", "<DeletedObjects><DeletedObject><UUID>$uuid</UUID></DeletedObject></DeletedObjects>")))
        assertEquals(damaged, meta("<CustomIcons><Icon><UUID>$uuid</UUID><Data>AAAA</Data></Icon></CustomIcons>"))
        assertEquals(damaged, entries(entry("<UUID Protected=\"True\">{{p:$uuid}}</UUID>")))
    }

    @Test
    fun `an empty UUID, or a bad one where KeePass 2 doesn't read it, opens`() {
        assertIs<Decoded.Opened>(entries(entry("").replace("AAAAAAAAAAAAAAAAAAAAAg==", "")))
        assertIs<Decoded.Opened>(entries(entry("<Unknown><UUID>not*base64</UUID></Unknown>")))
        assertIs<Decoded.Opened>(meta("<Unknown><RecycleBinUUID>AAAA</RecycleBinUUID></Unknown>"))
    }

    @Test
    fun `a value element with a child element is refused, an unknown one is skipped`() {
        assertEquals(damaged, entries(entry("<Tags>a<b/></Tags>")))
        assertEquals(damaged, entries(entry("<IconID><x/></IconID>")))
        assertEquals(damaged, meta("<DatabaseName>a<b/></DatabaseName>"))
        assertEquals(damaged, entries(entry("<String><Key>a<b/></Key><Value>v</Value></String>")))
        assertIs<Decoded.Opened>(entries(entry("<Unknown><Tags>a<b/></Tags></Unknown>")))
        assertIs<Decoded.Opened>(entries(entry("<Name>a<b/></Name>")))
    }

    @Test
    fun `a protected element where ProcessNode runs and that holds elements is refused`() {
        assertEquals(damaged, entries(entry("<Unknown Protected=\"True\"><b/></Unknown>")))
        assertEquals(damaged, entries(entry("<Unknown><Inner Protected=\"True\"><b/></Inner></Unknown>")))
        // A self-closing unknown element is skipped before its protected flag is checked.
        assertIs<Decoded.Opened>(entries(entry("<Unknown Protected=\"True\" />")))
    }

    @ParameterizedTest
    @ValueSource(strings = ["#zzzzzz", "#ggg", "notacolor", "1,2", "256,0,0", "1,2,3,4,5", "#1234567890"])
    fun `a color ColorTranslator FromHtml refuses is refused`(color: String) {
        assertEquals(damaged, meta("<Color>$color</Color>"))
        assertEquals(damaged, entries(entry("<ForegroundColor>$color</ForegroundColor>")))
        assertEquals(damaged, entries(entry("<BackgroundColor>$color</BackgroundColor>")))
    }

    @ParameterizedTest
    @ValueSource(strings = ["", "#FF0000", "#f00", "Red", "lightgrey", "buttonface", "'any name'", "10,20,30", "#12345", "0x00FF00", "  "])
    fun `a color ColorTranslator FromHtml accepts, or an empty one, opens`(color: String) {
        assertIs<Decoded.Opened>(meta("<Color>$color</Color>"), color)
        assertIs<Decoded.Opened>(entries(entry("<BackgroundColor>$color</BackgroundColor>")), color)
    }

    @Test
    fun `a header hash of white space reads as empty and is skipped, a protected one is checked`() {
        assertIs<Decoded.Opened>(meta("<HeaderHash>  \n </HeaderHash>"))
        assertEquals(Decoded.Damaged(DamageReason.XML_HEADER_HASH), meta("<HeaderHash Protected=\"True\">{{p:  }}</HeaderHash>"))
    }

    @Test
    fun `custom icon data that is not Base64 is refused, empty data is skipped`() {
        assertEquals(damaged, meta("<CustomIcons><Icon><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID><Data>not*base64</Data></Icon></CustomIcons>"))
        assertIs<Decoded.Opened>(meta("<CustomIcons><Icon><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID><Data></Data></Icon></CustomIcons>"))
    }

    @Test
    fun `an entry String or Binary needs a Key and a Value when its end runs`() {
        assertEquals(damaged, entries(entry("<String><Value>v</Value></String>")))
        assertEquals(damaged, entries(entry("<String><Key>k</Key></String>")))
        assertEquals(damaged, entries(entry("<String></String>")))
        assertEquals(damaged, entries(entry("<History>${entry("<String><Key>k</Key></String>")}</History>")))
        assertEquals(damaged, entries(entry("<Binary><Value>AAAA</Value></Binary>")))
        assertEquals(damaged, entries(entry("<Binary><Key>a.txt</Key></Binary>")))
        assertIs<Decoded.Opened>(entries(entry("<String />")))
        assertIs<Decoded.Opened>(entries(entry("<String><Key></Key><Value>v</Value></String>")))
        assertIs<Decoded.Opened>(entries(entry("<String><Key /><Value /></String>")))
    }

    @Test
    fun `an auto-type Association needs a Window and a KeystrokeSequence`() {
        fun autoType(inner: String) = entries(entry("<AutoType><Enabled>True</Enabled>$inner</AutoType>"))
        assertEquals(damaged, autoType("<Association><Window>w</Window></Association>"))
        assertEquals(damaged, autoType("<Association><KeystrokeSequence>s</KeystrokeSequence></Association>"))
        assertIs<Decoded.Opened>(autoType("<Association><Window>w</Window><KeystrokeSequence></KeystrokeSequence></Association>"))
        assertIs<Decoded.Opened>(autoType("<Association />"))
    }

    @Test
    fun `an attachment value that names no pool item must be Base64 and inflate`() {
        fun binary(value: String) = open(TestVaults.keePassXml(entries = entry("<Binary><Key>a.txt</Key>$value</Binary>")), listOf("a".toByteArray()))
        assertEquals(damaged, binary("<Value>not*base64</Value>"))
        assertEquals(damaged, binary("<Value Ref=\"9\">not*base64</Value>"))
        assertEquals(damaged, binary("<Value Compressed=\"True\">AAAA</Value>"))
        assertEquals(damaged, binary("<Value Ref=\"0\"><x/></Value>"))
        assertIs<Decoded.Opened>(binary("<Value>AAAA</Value>"))
        assertIs<Decoded.Opened>(binary("<Value Ref=\"0\" />"))
    }

    @Test
    fun `a self-closing Group leaves the group stack one deeper, so KeePass 2's end tags don't match`() {
        assertEquals(damaged, entries("<Group />"))
        assertEquals(damaged, open(TestVaults.keePassXml().replace("<Root>", "<Root><Group />")))
        assertIs<Decoded.Opened>(entries("<Group></Group>"))
        assertIs<Decoded.Opened>(entries("<Entry />"))
        assertIs<Decoded.Opened>(entries(entry("<History />")))
    }

    @Test
    fun `the last Group KeePass 2 reads in any Root is the root group`() {
        val xml = TestVaults.keePassXml(entries = entry(string("Title", "kept"))).replace("<KeePassFile>", "<KeePassFile><Root></Root>")
        val document = assertIs<Decoded.Opened>(open(xml)).document
        assertEquals("Root", document.rootGroup.name)
        assertEquals(damaged, open(TestVaults.keePassXml().replace("<Root>", "<Root></Root><Root2>").replace("</Root>\n</KeePassFile>", "</Root2>\n</KeePassFile>")))
    }

    @Test
    fun `Protected on an element that switches context takes no inner stream`() {
        val plain = entry("<String><Key>A</Key><Value Protected=\"True\">{{p:first}}</Value></String>") +
            entry("<String><Key>B</Key><Value Protected=\"True\">{{p:second}}</Value></String>")
        val marked = plain.replaceFirst("<String>", "<String Protected=\"True\">").replaceFirst("<Entry>", "<Entry Protected=\"True\">")
        for (xml in listOf(plain, marked)) {
            val document = assertIs<Decoded.Opened>(entries(xml)).document
            assertEquals(listOf("first", "second"), protectedInOrder(document).map { it.reveal() })
        }
        val doc = assertIs<Decoded.Opened>(entries(marked)).document
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.PROTECTED_CONTAINER), doc.saveability)
    }

    @Test
    fun `a protected value inside an unknown element takes the inner stream in document order`() {
        val xml = entry("<Unknown><Inner Protected=\"True\">{{p:skipped}}</Inner></Unknown><String><Key>P</Key><Value Protected=\"True\">{{p:read}}</Value></String>")
        val document = assertIs<Decoded.Opened>(entries(xml)).document
        assertEquals(listOf("skipped", "read"), protectedInOrder(document).map { it.reveal() })
    }

    private fun protectedInOrder(doc: VaultDocument): List<ProtectedText> {
        val out = mutableListOf<ProtectedText>()
        fun walk(e: XmlElement) {
            doc.protectedValues[e]?.let(out::add)
            e.elements().forEach(::walk)
        }
        walk(doc.xml.root)
        return out
    }
}
