package org.onekash.kashpass.vault.doc

import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.testing.TestVaults

class NewestChangeTest {

    private val now = Instant.parse("2026-10-20T12:00:00Z")

    private fun document(entries: String = "", meta: String = "<Generator>test</Generator>", deleted: String = ""): VaultDocument {
        var xml = TestVaults.keePassXml(entries, meta)
        if (deleted.isNotEmpty()) xml = xml.replace("<DeletedObjects />", "<DeletedObjects>$deleted</DeletedObjects>")
        // KDBX 4 stores times as Base64 seconds; ISO text there does not open.
        xml = ISO_TIME.replace(xml) { KdbxTime.format(Instant.parse(it.value)) }
        return runBlocking { TestVaults.unlock(TestVaults.rawXmlVault(xml)) }.session.opened.document
    }

    private fun entry(modified: String, extra: String = "") =
        "\t\t\t<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><Times><LastModificationTime>$modified</LastModificationTime>" +
            "<LocationChanged>2020-01-01T00:00:00Z</LocationChanged></Times>$extra</Entry>\n"

    @Test
    fun `the newest entry or history time wins`() {
        val history = "<History><Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><Times><LastModificationTime>2026-03-01T00:00:00Z</LastModificationTime></Times></Entry></History>"
        assertEquals(Instant.parse("2026-03-01T00:00:00Z"), NewestChange.of(document(entry("2025-05-01T00:00:00Z", history)), now))
        assertEquals(Instant.parse("2025-05-01T00:00:00Z"), NewestChange.of(document(entry("2025-05-01T00:00:00Z")), now))
    }

    @Test
    fun `deletions, Meta change times and custom data times count`() {
        val deleted = "<DeletedObject><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID><DeletionTime>2026-04-01T00:00:00Z</DeletionTime></DeletedObject>"
        assertEquals(Instant.parse("2026-04-01T00:00:00Z"), NewestChange.of(document(entry("2025-01-01T00:00:00Z"), deleted = deleted), now))
        val meta = "<Generator>t</Generator><SettingsChanged>2026-05-01T00:00:00Z</SettingsChanged>"
        assertEquals(Instant.parse("2026-05-01T00:00:00Z"), NewestChange.of(document(entry("2025-01-01T00:00:00Z"), meta = meta), now))
        val custom = "<CustomData><Item><Key>k</Key><Value>v</Value><LastModificationTime>2026-06-01T00:00:00Z</LastModificationTime></Item></CustomData>"
        assertEquals(Instant.parse("2026-06-01T00:00:00Z"), NewestChange.of(document(entry("2025-01-01T00:00:00Z", custom)), now))
    }

    // AAAA is 3 bytes, a time near 0001-01-01 when zero-padded to 8; KdbxTime.parse reads only
    // 8 bytes.
    @Test
    fun `a time more than a day in the future or shorter than 8 bytes is ignored`() {
        val meta = "<Generator>t</Generator><SettingsChanged>2099-01-01T00:00:00Z</SettingsChanged><MasterKeyChanged>AAAA</MasterKeyChanged>"
        assertEquals(Instant.parse("2025-01-01T00:00:00Z"), NewestChange.of(document(entry("2025-01-01T00:00:00Z"), meta = meta), now))
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "SettingsChanged", "DatabaseNameChanged", "DatabaseDescriptionChanged", "DefaultUserNameChanged",
            "MasterKeyChanged", "RecycleBinChanged", "EntryTemplatesGroupChanged",
        ],
    )
    fun `each Meta change time counts`(element: String) {
        val meta = "<Generator>t</Generator><$element>2026-07-01T00:00:00Z</$element>"
        assertEquals(Instant.parse("2026-07-01T00:00:00Z"), NewestChange.of(document(entry("2025-01-01T00:00:00Z"), meta = meta), now))
    }

    @Test
    fun `group times, a move, Meta custom data and custom icons count`() {
        val group = "\t\t\t<Group><UUID>AAAAAAAAAAAAAAAAAAAABA==</UUID><Name>G</Name><Times><LastModificationTime>2026-08-01T00:00:00Z</LastModificationTime></Times></Group>\n"
        assertEquals(Instant.parse("2026-08-01T00:00:00Z"), NewestChange.of(document(entry("2025-01-01T00:00:00Z") + group), now))
        val moved = "\t\t\t<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><Times><LastModificationTime>2025-01-01T00:00:00Z</LastModificationTime>" +
            "<LocationChanged>2026-08-02T00:00:00Z</LocationChanged></Times></Entry>\n"
        assertEquals(Instant.parse("2026-08-02T00:00:00Z"), NewestChange.of(document(moved), now))
        val metaData = "<Generator>t</Generator><CustomData><Item><Key>k</Key><Value>v</Value><LastModificationTime>2026-08-03T00:00:00Z</LastModificationTime></Item></CustomData>"
        assertEquals(Instant.parse("2026-08-03T00:00:00Z"), NewestChange.of(document(entry("2025-01-01T00:00:00Z"), meta = metaData), now))
        val icons = "<Generator>t</Generator><CustomIcons><Icon><UUID>AAAAAAAAAAAAAAAAAAAABQ==</UUID><Data>AA==</Data><LastModificationTime>2026-08-04T00:00:00Z</LastModificationTime></Icon></CustomIcons>"
        assertEquals(Instant.parse("2026-08-04T00:00:00Z"), NewestChange.of(document(entry("2025-01-01T00:00:00Z"), meta = icons), now))
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "keepass2-default-aeskdf.kdbx", "keepass2-argon2id.kdbx", "keepass2-chacha20-argon2d.kdbx",
            "keepass2-kdbx41-tags.kdbx", "keepass2-weak-aeskdf-6000.kdbx", "keepass2-desktop-new-database.kdbx",
        ],
    )
    fun `every KeePass 2 fixture has a newest change`(name: String) {
        val document = VaultXmlCodecTest.decode(VaultXmlCodecTest.fixture(name), VaultXmlCodecTest.fixturePassword)
        val newest = assertNotNull(NewestChange.of(document, Instant.parse("2030-01-01T00:00:00Z")))
        // These fixtures were written in 2026.
        assertEquals(2026, newest.atZone(java.time.ZoneOffset.UTC).year)
    }

    @Test
    fun `only the root group KeePass 2 keeps counts, the one a later Root replaces does not`() {
        val discarded = "<Root><Group><UUID>AAAAAAAAAAAAAAAAAAAABQ==</UUID><Name>Old</Name><Times><LastModificationTime>2026-09-01T00:00:00Z</LastModificationTime></Times></Group></Root>"
        var xml = TestVaults.keePassXml(entry("2025-01-01T00:00:00Z")).replace("<KeePassFile>", "<KeePassFile>$discarded")
        xml = ISO_TIME.replace(xml) { KdbxTime.format(Instant.parse(it.value)) }
        val document = runBlocking { TestVaults.unlock(TestVaults.rawXmlVault(xml)) }.session.opened.document
        assertEquals(Instant.parse("2025-01-01T00:00:00Z"), NewestChange.of(document, now))
    }

    private companion object {
        val ISO_TIME = Regex("""\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ""")
    }
}
