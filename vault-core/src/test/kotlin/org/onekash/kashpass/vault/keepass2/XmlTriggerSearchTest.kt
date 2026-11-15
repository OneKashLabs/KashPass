package org.onekash.kashpass.vault.keepass2

import java.io.File
import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.Spec
import org.onekash.kashpass.vault.doc.KdbxXmlContext.Context
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.testing.KdbxToolkit

/**
 * KashPass's own container reads XML as KeePass 2 does: for every fixture, every corpus case
 * and a grid of placements (every element name KeePass 2 recognises, in every context of its
 * reader, self-closing, empty, with text, with a child element and protected), it opens exactly
 * the files KeePass 2 opens, with the same content. Writes
 * build/reports/keepass2/xml-trigger-search.md.
 * Runs with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class XmlTriggerSearchTest {

    private val weak by lazy { KdbxToolkit.open(Fixtures.bytes("keepass2-weak-aeskdf-6000.kdbx"), KdbxToolkit.Key(TestFiles.password)) }

    // Every element name ReadXmlElement compares against, and one it doesn't recognise.
    private val names = listOf(
        "KeePassFile", "Meta", "Root", "Group", "Entry", "Generator", "HeaderHash", "SettingsChanged", "DatabaseName",
        "DatabaseNameChanged", "DatabaseDescription", "DatabaseDescriptionChanged", "DefaultUserName", "DefaultUserNameChanged",
        "MaintenanceHistoryDays", "Color", "MasterKeyChanged", "MasterKeyChangeRec", "MasterKeyChangeForce", "MasterKeyChangeForceOnce",
        "MemoryProtection", "CustomIcons", "RecycleBinEnabled", "RecycleBinUUID", "RecycleBinChanged", "EntryTemplatesGroup",
        "EntryTemplatesGroupChanged", "HistoryMaxItems", "HistoryMaxSize", "LastSelectedGroup", "LastTopVisibleGroup", "Binaries",
        "CustomData", "ProtectTitle", "ProtectUserName", "ProtectPassword", "ProtectURL", "ProtectNotes", "Icon", "UUID", "Data",
        "Name", "LastModificationTime", "Binary", "Item", "Key", "Value", "DeletedObjects", "Notes", "IconID", "CustomIconUUID",
        "Times", "IsExpanded", "DefaultAutoTypeSequence", "EnableAutoType", "EnableSearching", "LastTopVisibleEntry",
        "PreviousParentGroup", "Tags", "ForegroundColor", "BackgroundColor", "OverrideURL", "QualityCheck", "String", "AutoType",
        "History", "CreationTime", "LastAccessTime", "ExpiryTime", "Expires", "UsageCount", "LocationChanged", "Enabled",
        "DataTransferObfuscation", "DefaultSequence", "Association", "Window", "KeystrokeSequence", "DeletedObject", "DeletionTime",
        "KashPassUnknown",
    )

    // Where an element lands in each context: the text to replace in the weak fixture's XML and
    // its replacement around the placed element (written as @).
    private val places: Map<String, Pair<String, String>> = linkedMapOf(
        "KEEPASS_FILE" to ("<KeePassFile>\n" to "<KeePassFile>\n@\n"),
        "META" to ("<Meta>\n" to "<Meta>\n@\n"),
        "MEMORY_PROTECTION" to ("<MemoryProtection>\n" to "<MemoryProtection>\n@\n"),
        "CUSTOM_ICONS" to ("\t\t<CustomData />\n\t</Meta>" to "\t\t<CustomIcons>@</CustomIcons>\n\t\t<CustomData />\n\t</Meta>"),
        "CUSTOM_ICON" to ("\t\t<CustomData />\n\t</Meta>" to "\t\t<CustomIcons><Icon><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID><Data>AAAA</Data>@</Icon></CustomIcons>\n\t\t<CustomData />\n\t</Meta>"),
        "BINARIES" to ("\t\t<CustomData />\n\t</Meta>" to "\t\t<Binaries>@</Binaries>\n\t\t<CustomData />\n\t</Meta>"),
        "CUSTOM_DATA" to ("\t\t<CustomData />\n\t</Meta>" to "\t\t<CustomData>@</CustomData>\n\t</Meta>"),
        "CUSTOM_DATA_ITEM" to ("\t\t<CustomData />\n\t</Meta>" to "\t\t<CustomData><Item><Key>k</Key><Value>v</Value>@</Item></CustomData>\n\t</Meta>"),
        "ROOT" to ("<Root>\n" to "<Root>\n@\n"),
        "GROUP" to ("<IconID>49</IconID>\n" to "<IconID>49</IconID>\n@\n"),
        "GROUP_TIMES" to ("<IconID>49</IconID>\n\t\t\t<Times>\n" to "<IconID>49</IconID>\n\t\t\t<Times>\n@\n"),
        "GROUP_CUSTOM_DATA" to ("<IconID>49</IconID>\n" to "<IconID>49</IconID>\n<CustomData>@</CustomData>\n"),
        "GROUP_CUSTOM_DATA_ITEM" to ("<IconID>49</IconID>\n" to "<IconID>49</IconID>\n<CustomData><Item><Key>k</Key><Value>v</Value>@</Item></CustomData>\n"),
        "ENTRY" to ("<Tags></Tags>\n" to "<Tags></Tags>\n@\n"),
        "ENTRY_TIMES" to ("<Tags></Tags>\n\t\t\t\t<Times>\n" to "<Tags></Tags>\n\t\t\t\t<Times>\n@\n"),
        "ENTRY_STRING" to ("<Key>Title</Key>\n" to "<Key>Title</Key>\n@\n"),
        "ENTRY_BINARY" to ("<Key>recovery-codes.txt</Key>\n" to "<Key>recovery-codes.txt</Key>\n@\n"),
        "ENTRY_AUTO_TYPE" to ("<DataTransferObfuscation>0</DataTransferObfuscation>\n" to "<DataTransferObfuscation>0</DataTransferObfuscation>\n@\n"),
        "ENTRY_AUTO_TYPE_ITEM" to ("<DataTransferObfuscation>0</DataTransferObfuscation>\n" to
            "<DataTransferObfuscation>0</DataTransferObfuscation>\n<Association><Window>w</Window><KeystrokeSequence>s</KeystrokeSequence>@</Association>\n"),
        "ENTRY_CUSTOM_DATA" to ("<Tags></Tags>\n" to "<Tags></Tags>\n<CustomData>@</CustomData>\n"),
        "ENTRY_CUSTOM_DATA_ITEM" to ("<Tags></Tags>\n" to "<Tags></Tags>\n<CustomData><Item><Key>k</Key><Value>v</Value>@</Item></CustomData>\n"),
        "ENTRY_HISTORY" to ("<History>\n" to "<History>\n@\n"),
        "ENTRY_IN_HISTORY" to ("<History>\n\t\t\t\t\t\t<Entry>\n" to "<History>\n\t\t\t\t\t\t<Entry>\n@\n"),
        "ROOT_DELETED_OBJECTS" to ("<DeletedObjects />" to "<DeletedObjects>@</DeletedObjects>"),
        "DELETED_OBJECT" to ("<DeletedObjects />" to "<DeletedObjects><DeletedObject><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID><DeletionTime>835n4g4AAAA=</DeletionTime>@</DeletedObject></DeletedObjects>"),
    )

    private class Candidate(val name: String, val file: VaultFile)

    private fun candidates(): List<Candidate> {
        check(places.keys.filter { it != "ENTRY_IN_HISTORY" }.toSet() == Context.entries.map { it.name }.toSet() - "NULL") { "a context has no place" }
        val l = weak.layers
        val xml = String(l.xml, Charsets.ISO_8859_1)
        val out = mutableListOf<Candidate>()
        for ((context, place) in places) {
            val (old, around) = place
            val at = xml.indexOf(old)
            check(at >= 0) { "$context: no $old" }
            for (name in names) {
                val bodies = listOf(
                    "self-closing" to "<$name />",
                    "empty" to "<$name></$name>",
                    "text" to "<$name>x</$name>",
                    "child" to "<$name><KashPassChild /></$name>",
                    "protected" to "<$name Protected=\"True\">PROTECTED</$name>",
                )
                for ((label, element) in bodies) {
                    val edited = xml.substring(0, at) + around.replace("@", element) + xml.substring(at + old.length)
                    val bytes = edited.toByteArray(Charsets.ISO_8859_1)
                    val values = if (label == "protected") {
                        val index = KdbxToolkit.protectedCountBefore(bytes, edited.indexOf("<$name Protected=\"True\">PROTECTED"))
                        l.protectedValues.toMutableList().also { it.add(index, "placed".toByteArray()) }
                    } else {
                        l.protectedValues
                    }
                    val id = "search-${context.lowercase()}-$name-$label"
                    out += Candidate(id, VaultFile("$id.kdbx", KdbxToolkit.build(l.copy(xml = bytes, protectedValues = values))))
                }
            }
        }
        return out
    }

    @Test
    fun `KashPass's container opens what KeePass 2 opens, with its content`() {
        // Truncated cases, cases KashPass refuses by policy or for memory, and cases it reads as
        // KeePass 2 on Windows does are KeePass2CorpusTest's.
        val corpus = Corpus.all.filter { !it.name.startsWith("truncated") && it.windows == null && it.spec != Spec.REFUSED_BY_POLICY && it.spec != Spec.NOT_ENOUGH_MEMORY }
        val files = Fixtures.kdbx4Opening.map { Fixtures.file(it) } + corpus.map { it.file() }
        val search = candidates()
        val key = KeePass2Run.newKey()
        val all = files + search.map { it.file }
        val kp2 = all.chunked(2000).flatMap { KeePass2Run.keepass2(it, key).entries }.associate { it.key to it.value }
        val problems = mutableListOf<String>()
        var opened = 0
        var refused = 0
        for (f in all) {
            val theirs = kp2.getValue(f.name)
            val ours = DocumentReport.of(f, key)
            if (theirs is KeePass2Report.Opened) opened++ else refused++
            val diff = KeePass2Report.diff(theirs, ours)
            if (diff.isNotEmpty() && f.name.removeSuffix(".kdbx") !in ACCEPTED) {
                problems += "${f.name}: KeePass 2 ${if (theirs is KeePass2Report.Opened) "opens" else "refuses (${(theirs as KeePass2Report.Refused).reason})"}, " +
                    "KashPass ${if (ours is KeePass2Report.Opened) "opens" else "refuses (${(ours as KeePass2Report.Refused).reason})"}\n  " + diff.take(6).joinToString("\n  ")
            }
        }
        val report = StringBuilder("# XML trigger search\n\n")
            .append("${search.size} placements, ${files.size} fixtures and corpus cases; KeePass 2 opened $opened and refused $refused.\n\n")
            .append(if (problems.isEmpty()) "No difference.\n" else problems.joinToString("\n\n") { "```\n$it\n```" })
        KeePass2Files.writeReport("xml-trigger-search.md", report.toString())
        if (problems.isNotEmpty()) fail("${problems.size} differences, see ${java.io.File(KeePass2Files.reportDir, "xml-trigger-search.md")}:\n" + problems.take(30).joinToString("\n"))
    }

    private companion object {
        const val RANDOM_UUID = "KeePass 2 gives an entry whose UUID is empty a new random one when its end runs, on every read"

        // Files KeePass 2 opens with content that differs on every read or in a way the report
        // can't compare, each with the reason.
        val ACCEPTED = mapOf(
            "xml-uuid-empty" to RANDOM_UUID,
            "search-group-Entry-empty" to RANDOM_UUID,
            "search-group-Entry-text" to RANDOM_UUID,
            "search-group-Entry-child" to RANDOM_UUID,
            "search-group-Entry-protected" to RANDOM_UUID,
            "search-entry-UUID-self-closing" to RANDOM_UUID,
            "search-entry-UUID-empty" to RANDOM_UUID,
        )
    }
}
