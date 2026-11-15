package org.onekash.kashpass.vault.keepass2

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.open
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * KeePass 2's hashed export (`keepass2-read.sh --export`) is the same for two reads of one file and
 * carries no value in clear: every leaf text the exporter does not keep by name is a 64-character
 * hash, and no value KashPass reads from the fixture (protected values revealed, attachment text
 * included) is the whole text of such a leaf or of a hashed attribute. Runs with
 * -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2XmlExportSmokeTest {

    @Test
    fun `KeePass 2's hashed export is stable and holds no value in clear`() {
        val names = listOf("keepass2-default-aeskdf.kdbx", Fixtures.PLUGIN_DATA)
        val files = names.map { Fixtures.file(Fixtures.named(it)) }
        val again = Fixtures.file(Fixtures.named(names[0]), "again-${names[0]}", files[0].bytes)
        val exports = KeePass2Run.keepass2XmlOpened(files + again, KeePass2Run.newKey())
        assertEquals(emptyList(), KeePassXml.diff(exports.getValue(names[0]).flat(), exports.getValue(again.name).flat()))

        for (f in files) {
            val xml = exports.getValue(f.name)
            val document = VaultXmlCodec.open(f.bytes, TestFiles.credentials(f), ContainerRig.LIMITS)
            val known = HashSet<String>()
            fun collect(e: XmlElement) {
                if (e.elements().isEmpty()) {
                    val text = document.protectedValues[e]?.reveal() ?: e.text()
                    if (text.isNotBlank() && !keptByName(e)) known += text.trim()
                }
                e.elements().forEach(::collect)
            }
            collect(document.xml.root)
            document.attachments.forEach { a -> String(a.data, Charsets.UTF_8).takeIf { it.isNotBlank() }?.let { known += it } }
            assertTrue(known.size > 10, "${f.name}: only ${known.size} values to look for")

            val problems = mutableListOf<String>()
            fun check(e: XmlElement, path: String) {
                for (a in e.attributes) {
                    if (a.name !in KEPT_ATTRIBUTES && !HEX64.matches(a.value)) problems += "$path/@${a.name} is not a hash"
                    if (a.name !in KEPT_ATTRIBUTES && a.value in known) problems += "$path/@${a.name} holds a value in clear"
                }
                if (e.elements().isEmpty()) {
                    val text = e.text().trim()
                    if (!keptByName(e)) {
                        if (!HEX64.matches(text)) problems += "$path is not a hash"
                        if (text in known) problems += "$path holds a value in clear"
                    }
                }
                e.elements().forEach { check(it, "$path/${it.name}") }
            }
            check(xml.root, xml.root.name)
            assertEquals(emptyList(), problems, f.name)
        }
    }

    private companion object {
        val HEX64 = Regex("[0-9a-f]{64}")

        // The names the exporter keeps in clear (ReadVault.cs HashedExport), mirrored here so a
        // name added there without a matching review here fails this test.
        val KEPT = setOf(
            "UUID", "CustomIconUUID", "PreviousParentGroup", "LastTopVisibleEntry", "LastTopVisibleGroup",
            "LastSelectedGroup", "RecycleBinUUID", "EntryTemplatesGroup",
            "IconID", "UsageCount", "Expires", "IsExpanded", "EnableAutoType", "EnableSearching",
            "DataTransferObfuscation", "QualityCheck", "RecycleBinEnabled", "HistoryMaxItems", "HistoryMaxSize",
            "MaintenanceHistoryDays", "MasterKeyChangeRec", "MasterKeyChangeForce", "MasterKeyChangeForceOnce",
            "ForegroundColor", "BackgroundColor", "Color",
            "SettingsChanged", "DatabaseNameChanged", "DatabaseDescriptionChanged", "DefaultUserNameChanged",
            "RecycleBinChanged", "EntryTemplatesGroupChanged", "MasterKeyChanged", "DeletionTime",
        )
        val KEPT_UNDER = mapOf(
            "String" to setOf("Key"),
            "Binary" to setOf("Key"),
            "Item" to setOf("Key", "LastModificationTime"),
            "Icon" to setOf("LastModificationTime"),
            "AutoType" to setOf("Enabled"),
        )
        val KEPT_ATTRIBUTES = setOf("ID", "Ref", "Compressed", "Protected", "ProtectInMemory")

        fun keptByName(e: XmlElement): Boolean {
            if (e.name in KEPT) return true
            val parent = e.parent?.name ?: return false
            if (parent == "Times" || parent == "MemoryProtection") return true
            return KEPT_UNDER[parent]?.contains(e.name) == true
        }
    }
}
