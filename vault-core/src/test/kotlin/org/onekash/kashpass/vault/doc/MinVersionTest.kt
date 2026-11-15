package org.onekash.kashpass.vault.doc

import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.TestVaults

class MinVersionTest {

    private val icon = "<UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Data>iVBORw0KGgo=</Data>"
    private val time = "<LastModificationTime>AAAAAAAAAAA=</LastModificationTime>"

    private fun entry(extra: String = "", history: String = "") =
        "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><String><Key>Title</Key><Value>t</Value></String>$extra<History>$history</History></Entry>"

    private fun of(entries: String = entry(), meta: String = "<Generator>x</Generator>", groupExtra: String = ""): Int {
        val xml = TestVaults.keePassXml(entries = entries, meta = meta).let { if (groupExtra.isEmpty()) it else it.replaceFirst("<Name>", "$groupExtra<Name>") }
        val document = VaultXmlCodecTest.decode(TestVaults.rawXmlVault(xml), TestVaults.PASSWORD)
        return MinVersion.of(document.xml.root, document.protectedValues)
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(
        delimiter = '|',
        value = [
            "plain content | 0",
            "group tags | 1",
            "group tags of separators and blanks | 0",
            "subgroup tags | 1",
            "QualityCheck False | 1",
            "QualityCheck false | 0",
            "QualityCheck False with spaces | 0",
            "QualityCheck True | 0",
            "QualityCheck False only in history | 0",
            "protected QualityCheck False | 1",
            "protected group tags | 1",
            "icon with a name | 1",
            "icon with a blank name | 0",
            "icon with a modification time | 1",
            "icon without data | 0",
            "icon with a zero UUID | 0",
            "plain icon | 0",
            "custom data with a modification time | 1",
            "custom data without one | 0",
            "custom data whose last item for the key has none | 0",
            "custom data without a value | 0",
        ],
    )
    fun `the minimum version follows KeePass 2's GetMinKdbxVersion`(case: String, expected: Int) {
        val sub = "<Group><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID><Name>s</Name><Tags>a</Tags></Group>"
        val actual = when (case) {
            "plain content" -> of()
            "group tags" -> of(groupExtra = "<Tags>work</Tags>")
            "group tags of separators and blanks" -> of(groupExtra = "<Tags> ,; ,</Tags>")
            "subgroup tags" -> of(entries = entry() + sub)
            "QualityCheck False" -> of(entries = entry("<QualityCheck>False</QualityCheck>"))
            "QualityCheck false" -> of(entries = entry("<QualityCheck>false</QualityCheck>"))
            "QualityCheck False with spaces" -> of(entries = entry("<QualityCheck> False </QualityCheck>"))
            "QualityCheck True" -> of(entries = entry("<QualityCheck>True</QualityCheck>"))
            "QualityCheck False only in history" -> of(entries = entry(history = entry("<QualityCheck>False</QualityCheck>")))
            "protected QualityCheck False" -> of(entries = entry("<QualityCheck Protected=\"True\">{{p:False}}</QualityCheck>"))
            "protected group tags" -> of(groupExtra = "<Tags Protected=\"True\">{{p:work}}</Tags>")
            "icon with a name" -> of(meta = "<CustomIcons><Icon>$icon<Name>n</Name></Icon></CustomIcons>")
            "icon with a blank name" -> of(meta = "<CustomIcons><Icon>$icon<Name> </Name></Icon></CustomIcons>")
            "icon with a modification time" -> of(meta = "<CustomIcons><Icon>$icon$time</Icon></CustomIcons>")
            "icon without data" -> of(meta = "<CustomIcons><Icon><UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Name>n</Name></Icon></CustomIcons>")
            "icon with a zero UUID" -> of(meta = "<CustomIcons><Icon><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Data>iVBORw0KGgo=</Data><Name>n</Name></Icon></CustomIcons>")
            "plain icon" -> of(meta = "<CustomIcons><Icon>$icon</Icon></CustomIcons>")
            "custom data with a modification time" -> of(meta = "<CustomData><Item><Key>k</Key><Value>v</Value>$time</Item></CustomData>")
            "custom data without one" -> of(meta = "<CustomData><Item><Key>k</Key><Value>v</Value></Item></CustomData>")
            "custom data whose last item for the key has none" ->
                of(meta = "<CustomData><Item><Key>k</Key><Value>v</Value>$time</Item><Item><Key>k</Key><Value>w</Value></Item></CustomData>")
            "custom data without a value" -> of(meta = "<CustomData><Item><Key>k</Key>$time</Item></CustomData>")
            else -> error(case)
        }
        assertEquals(expected, actual, case)
    }

    @Test
    fun `the KeePass 2 fixtures give the version KeePass 2 wrote`() {
        for (fixture in Fixtures.kdbx4Opening) {
            val file = Fixtures.file(fixture)
            val document = VaultXmlCodec.open(file.bytes, TestFiles.credentials(file), ContainerRig.LIMITS)
            val expected = if (fixture.name in setOf("keepass2-kdbx41-tags.kdbx", Fixtures.PLUGIN_DATA)) 1 else 0
            assertEquals(expected, MinVersion.of(document.xml.root, document.protectedValues), fixture.name)
        }
    }
}
