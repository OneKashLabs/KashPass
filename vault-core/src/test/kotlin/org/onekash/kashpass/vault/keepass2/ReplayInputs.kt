package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import java.util.Base64
import org.onekash.kashpass.vault.doc.KdbxTime
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.testing.TestVaults

/**
 * The generated inputs of the differential editing test: one vault shape with Meta settings
 * varied. Every input holds the top-level entry "Main" with an attachment in its current version
 * and in each history item (one shared pool item), "Other" in the folder-icon group, groups with a
 * folder, a mailbox and a custom icon, a templates group with a subgroup, and (when the bin is
 * present) a bin holding "Binned". Times are fixed, history items differ in title and
 * LastModificationTime. The test has KeePass 2 save each input once before use, so both sides
 * start from a tree KeePass 2 loaded and trimmed.
 */
internal object ReplayInputs {

    enum class Bin { PRESENT, MISSING, DANGLING, OFF }

    /** One input: its [name], the settings it was built with and the file. */
    class Input(val name: String, val maxItems: Int, val maxSize: Long, val bin: Bin, val defaultUser: String, val kdbx41: Boolean, val historyItems: Int, val file: VaultFile)

    // 16-byte UUIDs spelled out as text, in Base64 as a KDBX file stores them.
    fun uuid(label: String): String = Base64.getEncoder().encodeToString(label.padEnd(16, '-').take(16).encodeToByteArray())

    val ROOT = uuid("ROOT")
    val MAIN = uuid("MAIN")
    val OTHER = uuid("OTHER")
    val BINNED = uuid("BINNED")
    val FOLDER = uuid("FOLDER")
    val MAILBOX = uuid("MAILBOX")
    val CUSTOM = uuid("CUSTOM")
    val TEMPLATES = uuid("TEMPLATES")
    val TEMPLATES_SUB = uuid("TEMPLATES-SUB")
    val BIN = uuid("BIN")
    val ICON = uuid("ICON")
    val DANGLING = uuid("NO-SUCH-GROUP")

    // A 1x1 PNG, the image format of custom icon data.
    private const val PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

    val all: List<Input> by lazy {
        listOf(
            input("history-10-at-limit", maxItems = 10, historyItems = 10),
            input("history-0", maxItems = 0, historyItems = 2),
            input("history-unlimited", maxItems = -1, historyItems = 12),
            input("history-size-small", maxSize = 100, historyItems = 1),
            input("bin-missing", bin = Bin.MISSING),
            input("bin-dangling", bin = Bin.DANGLING),
            input("bin-off", bin = Bin.OFF),
            input("default-user-empty", defaultUser = ""),
            input("kdbx41", kdbx41 = true),
        )
    }

    /** The input every case without a special need runs on. */
    val base: Input get() = all.first()

    fun named(name: String): Input = all.single { it.name == name }

    private fun input(
        name: String,
        maxItems: Int = 10,
        maxSize: Long = 6L * 1024 * 1024,
        bin: Bin = Bin.PRESENT,
        defaultUser: String = "default-user",
        kdbx41: Boolean = false,
        historyItems: Int = 3,
    ): Input {
        val xml = xml(maxItems, maxSize, bin, defaultUser, kdbx41, historyItems)
        val bytes = TestVaults.rawXmlVault(xml, attachments = listOf("attachment in every version\n".encodeToByteArray()), minor = if (kdbx41) 1 else 0)
        return Input(name, maxItems, maxSize, bin, defaultUser, kdbx41, historyItems, VaultFile("replay-$name.kdbx", bytes))
    }

    // KDBX 4 stores times as Base64 seconds since year 1 (KdbxTime).
    private fun t(day: Int, hour: Int = 0) = KdbxTime.format(Instant.parse("2026-01-%02dT%02d:00:00Z".format(day, hour)))

    private fun times(day: Int, hour: Int = 0, usage: Int = 2) =
        "<Times><CreationTime>${t(1)}</CreationTime><LastModificationTime>${t(day, hour)}</LastModificationTime>" +
            "<LastAccessTime>${t(day, hour)}</LastAccessTime><ExpiryTime>${t(28)}</ExpiryTime><Expires>False</Expires>" +
            "<UsageCount>$usage</UsageCount><LocationChanged>${t(1)}</LocationChanged></Times>"

    private fun string(key: String, value: String, protected: Boolean = false) =
        if (protected) "<String><Key>$key</Key><Value Protected=\"True\">{{p:$value}}</Value></String>"
        else "<String><Key>$key</Key><Value>$value</Value></String>"

    private fun entry(uuid: String, title: String, day: Int, hour: Int = 0, history: String? = null, attachment: Boolean = false) =
        "<Entry><UUID>$uuid</UUID><IconID>0</IconID><ForegroundColor /><BackgroundColor /><OverrideURL /><Tags />${times(day, hour)}" +
            string("Title", title) + string("UserName", "user-$title") + string("Password", "pass-$title", protected = true) +
            string("URL", "https://$title.test") + string("Notes", "notes of $title") +
            (if (attachment) "<Binary><Key>doc.txt</Key><Value Ref=\"0\" /></Binary>" else "") +
            "<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation></AutoType>" +
            (history?.let { "<History>$it</History>" } ?: "") + "</Entry>"

    private fun group(uuid: String, name: String, icon: Int, content: String = "", extra: String = "") =
        "<Group><UUID>$uuid</UUID><Name>$name</Name><Notes /><IconID>$icon</IconID>$extra${times(1)}<IsExpanded>True</IsExpanded>" +
            "<DefaultAutoTypeSequence /><EnableAutoType>null</EnableAutoType><EnableSearching>null</EnableSearching>" +
            "<LastTopVisibleEntry>${KeePassXml.ZERO_UUID}</LastTopVisibleEntry>$content</Group>"

    private fun xml(maxItems: Int, maxSize: Long, bin: Bin, defaultUser: String, kdbx41: Boolean, historyItems: Int): String {
        // History items: hour h of day 2, oldest first, each with its own title.
        val history = (0 until historyItems).joinToString("") { h -> entry(MAIN, "main-v$h", day = 2, hour = h, attachment = true) }
        val binUuid = when (bin) {
            Bin.PRESENT -> BIN
            Bin.DANGLING -> DANGLING
            Bin.MISSING, Bin.OFF -> KeePassXml.ZERO_UUID
        }
        val meta = "<Generator>KashPass test</Generator><DatabaseName>Replay input</DatabaseName><DefaultUserName>$defaultUser</DefaultUserName>" +
            "<CustomIcons><Icon><UUID>$ICON</UUID><Data>$PNG</Data></Icon></CustomIcons>" +
            "<RecycleBinEnabled>${if (bin == Bin.OFF) "False" else "True"}</RecycleBinEnabled><RecycleBinUUID>$binUuid</RecycleBinUUID>" +
            "<EntryTemplatesGroup>$TEMPLATES</EntryTemplatesGroup><HistoryMaxItems>$maxItems</HistoryMaxItems><HistoryMaxSize>$maxSize</HistoryMaxSize>"
        val tags = if (kdbx41) "<Tags>tagged</Tags>" else ""
        val groups = group(FOLDER, "Folder", 48, entry(OTHER, "other", day = 3), extra = "") +
            group(MAILBOX, "Mailbox", 25) +
            group(CUSTOM, "Custom", 0, extra = "<CustomIconUUID>$ICON</CustomIconUUID>") +
            group(TEMPLATES, "Templates", 48, group(TEMPLATES_SUB, "Sub", 48)) +
            (if (bin == Bin.PRESENT) group(BIN, "Recycle Bin", 43, entry(BINNED, "binned", day = 4)) else "")
        val root = group(ROOT, "Root", 48, entry(MAIN, "main", day = 3, history = history, attachment = true) + groups, extra = tags)
        return "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile><Meta>$meta</Meta><Root>$root<DeletedObjects /></Root></KeePassFile>"
    }
}
