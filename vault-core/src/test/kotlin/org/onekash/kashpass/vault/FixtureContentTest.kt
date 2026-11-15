package org.onekash.kashpass.vault

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRead
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.fixtures.CredentialMode
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.kdbx.Argon2Type
import org.onekash.kashpass.vault.kdbx.Bytes
import org.onekash.kashpass.vault.kdbx.Compression
import org.onekash.kashpass.vault.kdbx.KdbxHeaderReader
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.kdbx.KdfParameters
import org.onekash.kashpass.vault.kdbx.OuterCipher
import org.onekash.kashpass.vault.kdbx.VariantDictionary
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * Pins what KashPass's own container reads from each vault KeePass 2 wrote: header settings,
 * groups, entries, history, custom fields, tags, attachments, and which keys open each one. The
 * gated KeePass 2 tests compare the same reading with KeePass 2's own; this test keeps the values
 * fixed in the default suite.
 */
class FixtureContentTest {

    // Opens fixture [name] with the password (hashed here) and key-file part given, by default
    // its own.
    private fun decode(
        name: String,
        password: String? = TestFiles.password(Fixtures.named(name).mode),
        keyPart: ByteArray? = TestFiles.keyFilePart(Fixtures.file(Fixtures.named(name))),
    ): ContainerDecode.Result = ContainerDecode.decode(
        Fixtures.bytes(name), password?.let { KdbxToolkit.sha256(it.encodeToByteArray()) }, keyPart, ContainerRig.LIMITS, Int.MAX_VALUE,
        maxHeapBytes = ContainerRig.HEAP, derive = ContainerRig.derive,
    )

    private fun open(name: String, password: String? = TestFiles.password(Fixtures.named(name).mode)): ContainerRead =
        assertIs<ContainerDecode.Result.Opened>(decode(name, password), name).read

    private fun wrongKey(result: ContainerDecode.Result, what: String) =
        assertEquals(KdbxResult.WrongKey, assertIs<ContainerDecode.Result.Failed>(result, what).result, what)

    private fun ContainerRead.text(e: XmlElement): String = protectedValues[e]?.reveal() ?: e.text()

    private fun ContainerRead.last(e: XmlElement, name: String): String = e.children(name).lastOrNull()?.let { text(it) }.orEmpty()

    private fun ContainerRead.field(entry: XmlElement, key: String): String? =
        entry.children("String").lastOrNull { last(it, "Key") == key }?.children("Value")?.lastOrNull()?.let { text(it) }

    private fun ContainerRead.rootGroup(): XmlElement = xml.root.children("Root").single().children("Group").single()

    // Every entry with the group holding it, in document order, history excluded.
    private fun ContainerRead.entries(group: XmlElement = rootGroup()): List<Pair<XmlElement, XmlElement>> =
        group.children("Entry").map { group to it } + group.children("Group").flatMap { entries(it) }

    private fun ContainerRead.entry(title: String): XmlElement = entries().map { it.second }.single { field(it, "Title") == title }

    private fun ContainerRead.groupOf(title: String): String = last(entries().single { field(it.second, "Title") == title }.first, "Name")

    private fun ContainerRead.history(entry: XmlElement): List<XmlElement> = entry.children("History").flatMap { it.children("Entry") }

    // "name protection size sha256" of each attachment of [entry], protection "*" or "-".
    private fun ContainerRead.attachments(entry: XmlElement): List<String> = entry.children("Binary").map { b ->
        val a = references[b.children("Value").last()] ?: error("${last(b, "Key")}: no attachment")
        "${last(b, "Key")} ${if (a.protected) "*" else "-"} ${a.data.size} ${hex(KdbxToolkit.sha256(a.data))}"
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun aes(read: ContainerRead) = assertIs<KdfParameters.Aes>(read.container.header.kdf)

    private fun argon2(read: ContainerRead) = assertIs<KdfParameters.Argon2>(read.container.header.kdf)

    @Test
    fun `the default KeePass 2 vault is KDBX 4_0 with AES-256 and AES-KDF at 600,000 rounds`() {
        val read = open("keepass2-default-aeskdf.kdbx")
        val h = read.container.header
        assertEquals(4 to 0, h.majorVersion to h.minorVersion)
        assertEquals(OuterCipher.AES_256, h.cipher)
        assertEquals(600_000UL, aes(read).rounds)
    }

    @Test
    fun `the Argon2id vault carries KeePass 2's defaults of 2 iterations, 64 MiB and 2 lanes at version 0x13`() {
        val kdf = argon2(open("keepass2-argon2id.kdbx"))
        assertEquals(Argon2Type.ARGON2ID, kdf.type)
        assertEquals(listOf(2UL, 64UL * 1024UL * 1024UL, 2UL, 0x13UL), listOf(kdf.iterations, kdf.memoryBytes, kdf.parallelism.toULong(), kdf.version.toULong()))
    }

    @Test
    fun `the ChaCha20 vault uses ChaCha20 with Argon2d`() {
        val read = open("keepass2-chacha20-argon2d.kdbx")
        assertEquals(OuterCipher.CHACHA20, read.container.header.cipher)
        val kdf = argon2(read)
        assertEquals(Argon2Type.ARGON2D, kdf.type)
        assertEquals(listOf(2UL, 64UL * 1024UL * 1024UL, 2UL), listOf(kdf.iterations, kdf.memoryBytes, kdf.parallelism.toULong()))
    }

    @Test
    fun `the KDBX 4_1 vault keeps group tags, entry tags and the disabled quality check`() {
        val read = open("keepass2-kdbx41-tags.kdbx")
        assertEquals(1, read.container.header.minorVersion)
        val (group, bank) = read.entries().single { read.field(it.second, "Title") == "Example Bank" }
        assertEquals("money", read.last(group, "Tags"))
        assertEquals(listOf("finance", "important"), read.last(bank, "Tags").split(',', ';').map { it.trim() })
        assertEquals("False", read.last(bank, "QualityCheck"))
    }

    @Test
    fun `the weak vault has AES-KDF at 6,000 rounds`() {
        assertEquals(6_000UL, aes(open("keepass2-weak-aeskdf-6000.kdbx")).rounds)
    }

    @Test
    fun `entries, history, custom fields and attachments read back as KeePass 2 wrote them`() {
        val names = Fixtures.kdbx4Opening.filter { it.mode == CredentialMode.PASSWORD && it.sampleContent }.map { it.name }
        assertTrue(names.size >= 10, "$names")
        for (name in names) {
            val read = open(name)
            val mail = read.entry("Example Mail")
            assertEquals("alice@example.test", read.field(mail, "UserName"), name)
            assertEquals("current-password", read.field(mail, "Password"), name)
            assertEquals("Line one\nLine two with ünïcödé", read.field(mail, "Notes"), name)
            assertEquals(listOf("first-password", "second-password"), read.history(mail).map { read.field(it, "Password") }, name)

            val bank = read.entry("Example Bank")
            assertEquals("b@nk-p4ss", read.field(bank, "Password"), name)
            assertEquals("Banking", read.groupOf("Example Bank"), name)
            assertEquals("Email", read.groupOf("Example Mail"), name)
            assertTrue(read.field(bank, "otp").orEmpty().startsWith("otpauth://totp/"), name)
            assertEquals("12-3456-7890", read.field(bank, "Account number"), name)
            assertEquals(listOf("recovery-codes.txt"), bank.children("Binary").map { read.last(it, "Key") }, name)

            assertEquals("bob", read.field(read.entry("No password entry"), "UserName"), name)
        }
    }

    @Test
    fun `the plugin-data vault keeps plugin custom data, auto-type and the Meta settings KeePass 2 wrote`() {
        val read = open(Fixtures.PLUGIN_DATA)
        assertEquals(1, read.container.header.minorVersion)
        val public = read.container.header.publicCustomData!!
        assertEquals("public value", public["PluginA_Name"]!!.value.decodeToString())
        assertEquals(VariantDictionary.UINT64, public["PluginA_Count"]!!.type)
        assertEquals(42L, Bytes.readLe64(public["PluginA_Count"]!!.value, 0))
        assertContentEquals(byteArrayOf(1, 2, 3, 4), public.bytes("PluginA_Bytes"))

        val meta = read.xml.root.child("Meta")!!
        val metaValues = listOf(
            "DatabaseName", "DatabaseDescription", "DefaultUserName", "Color", "MaintenanceHistoryDays", "MasterKeyChangeRec",
            "MasterKeyChangeForce", "MasterKeyChangeForceOnce", "HistoryMaxItems", "HistoryMaxSize", "RecycleBinEnabled",
        ).map { read.last(meta, it) }
        assertEquals(
            listOf("KashPass plugin data", "Plugin data, auto-type and Meta settings", "default-user", "#336699", "30", "180", "365", "True", "3", "12288", "True"),
            metaValues,
        )
        for (name in listOf("DatabaseNameChanged", "DatabaseDescriptionChanged", "DefaultUserNameChanged", "MasterKeyChanged", "SettingsChanged", "RecycleBinChanged", "EntryTemplatesGroupChanged")) {
            assertTrue(read.last(meta, name).isNotEmpty(), name)
        }
        val protection = meta.child("MemoryProtection")!!
        assertEquals(listOf("False", "True", "True", "True", "False"), listOf("ProtectTitle", "ProtectUserName", "ProtectPassword", "ProtectURL", "ProtectNotes").map { read.last(protection, it) })
        val metaData = meta.child("CustomData")!!.children("Item").associate { read.last(it, "Key") to (read.last(it, "Value") to read.last(it, "LastModificationTime")) }
        assertEquals(mapOf("PluginA_Setting" to ("True" to ""), "PluginB_Timed" to ("1234" to metaData.getValue("PluginB_Timed").second)), metaData)
        assertTrue(metaData.getValue("PluginB_Timed").second.isNotEmpty())
        val icons = meta.child("CustomIcons")!!.children("Icon")
        assertEquals(listOf("Plugin icon", "Timed icon"), icons.map { read.last(it, "Name") })
        assertEquals(listOf(false, true), icons.map { read.last(it, "LastModificationTime").isNotEmpty() })

        val groups = read.rootGroup().children("Group").associateBy { read.last(it, "Name") }
        assertEquals(listOf("Email", "Banking", "Plugins", "Templates", "Recycle Bin"), groups.keys.toList())
        assertEquals(read.last(groups.getValue("Recycle Bin"), "UUID"), read.last(meta, "RecycleBinUUID"))
        assertEquals(read.last(groups.getValue("Templates"), "UUID"), read.last(meta, "EntryTemplatesGroup"))
        assertEquals(read.last(groups.getValue("Plugins"), "UUID"), read.last(meta, "LastSelectedGroup"))
        assertEquals(read.last(read.rootGroup(), "UUID"), read.last(meta, "LastTopVisibleGroup"))
        val plugins = groups.getValue("Plugins")
        assertEquals(read.last(icons[0], "UUID"), read.last(plugins, "CustomIconUUID"))
        assertEquals("{USERNAME}{TAB}{PASSWORD}{ENTER}", read.last(plugins, "DefaultAutoTypeSequence"))
        assertEquals("AAECAwQFBgcICQoLDA0ODw== 2026-01-05T06:07:08Z", read.last(plugins, "Notes"))
        assertEquals(mapOf("PluginA_Group" to "group value"), plugins.child("CustomData")!!.children("Item").associate { read.last(it, "Key") to read.last(it, "Value") })
        assertEquals(listOf("false", "false"), listOf("EnableSearching", "EnableAutoType").map { read.last(groups.getValue("Templates"), it).lowercase() })

        val three = read.entry("Three backups")
        assertEquals(3, read.history(three).size)
        assertEquals(listOf("three-0", "three-1", "three-2"), read.history(three).map { read.field(it, "Password") })
        assertEquals("1234", read.field(three, "Count"))
        assertEquals(mapOf("PluginA_Entry" to "entry value", "PluginB_Flag" to "True"), three.child("CustomData")!!.children("Item").associate { read.last(it, "Key") to read.last(it, "Value") })
        assertEquals(listOf("", ""), three.child("CustomData")!!.children("Item").map { read.last(it, "LastModificationTime") })
        assertEquals(read.last(icons[1], "UUID"), read.last(three, "CustomIconUUID"))
        assertEquals(listOf("#AA0000", "#EEEEFF", "cmd://example-override"), listOf("ForegroundColor", "BackgroundColor", "OverrideURL").map { read.last(three, it) })
        assertEquals("True", read.last(three.child("Times")!!, "Expires"))
        assertEquals(listOf("plugin", "styled"), read.last(three, "Tags").split(',', ';').map { it.trim() })
        val autoType = three.child("AutoType")!!
        assertEquals("{TITLE}{TAB}{PASSWORD}", read.last(autoType, "DefaultSequence"))
        assertEquals(listOf("Example Window*" to "{USERNAME}{ENTER}", "Other Window" to ""), autoType.children("Association").map { read.last(it, "Window") to read.last(it, "KeystrokeSequence") })

        val size = read.entry("Size limit")
        assertEquals(1, read.history(size).size)
        assertEquals(read.attachments(size), read.attachments(read.history(size).single()))
        assertEquals(8192, read.attachments(size).single().split(' ')[2].toInt())

        assertEquals("Templates", read.groupOf("Login template"))
        assertEquals("Recycle Bin", read.groupOf("Deleted entry"))
        assertEquals(read.last(read.rootGroup(), "UUID"), read.last(read.entry("Deleted entry"), "PreviousParentGroup"))
    }

    @Test
    fun `the vault made by the KeePass 2 desktop app opens with its new-database defaults`() {
        val read = open(Fixtures.DESKTOP)
        val h = read.container.header
        assertEquals(4 to 0, h.majorVersion to h.minorVersion)
        assertEquals(OuterCipher.AES_256, h.cipher)
        assertEquals(600_000UL, aes(read).rounds)
        val root = read.rootGroup()
        assertEquals(listOf("General", "Windows", "Network", "Internet", "eMail", "Homebanking"), root.children("Group").map { read.last(it, "Name") })
        assertEquals(listOf("Sample Entry", "Sample Entry #2"), root.children("Entry").map { read.field(it, "Title") })
        assertEquals("True", read.last(read.xml.root.children("Meta").single(), "RecycleBinEnabled"))
    }

    @Test
    fun `the no-compression vault stores its payload without gzip`() {
        assertEquals(Compression.NONE, open("keepass2-compression-none.kdbx").container.header.compression)
    }

    @Test
    fun `the multi-block vault holds a 1_2 MiB attachment, so its ciphertext spans two data blocks`() {
        val name = "keepass2-multiblock-attachment.kdbx"
        val read = open(name)
        assertEquals(1_258_291, read.references[read.entry("Large attachment").children("Binary").single().children("Value").single()]!!.data.size)
        // Two data blocks and the end block, as stored.
        assertEquals(3, KdbxToolkit.split(Fixtures.bytes(name)).blocks.size)
    }

    @Test
    fun `KeePass 2 writes one pool item for attachments with equal bytes, in entries and history`() {
        val name = "keepass2-shared-attachments.kdbx"
        val read = open(name)
        val one = read.entry("Shared one")
        val two = read.entry("Shared two")
        val shared = read.references[one.children("Binary").single().children("Value").single()]!!
        assertTrue(shared === read.references[two.children("Binary").single().children("Value").single()], "both entries name the same item")
        assertTrue(shared === read.references[read.history(one).single().children("Binary").single().children("Value").single()], "and so does the history entry")
        assertEquals(300, shared.data.size)
        assertEquals(4, read.pool.size, "recovery-codes.txt, shared, empty and protected, as written")
        assertEquals(4, KdbxToolkit.open(Fixtures.bytes(name), KdbxToolkit.Key(TestFiles.password)).layers.inner.count { it.id == KdbxToolkit.INNER_BINARY })
    }

    @Test
    fun `each container-shape fixture has KeePass 2's header and attachment bytes`() {
        val recovery = "Example Bank recovery-codes.txt - 20 e694ccdf81a3d5f2a59a89ddd7fc7082867af9a4c46f043d58641f91989f2158"
        val expected = mapOf(
            "keepass2-compression-none.kdbx" to Shape(Compression.NONE, "Aes", listOf(recovery)),
            "keepass2-multiblock-attachment.kdbx" to Shape(
                Compression.GZIP, "Aes",
                listOf("Large attachment noise.bin - 1258291 a087d845203a973c62d5ca219fd3e22efad094ae9105c834f75b4ce59ff5e64f", recovery),
            ),
            "keepass2-shared-attachments.kdbx" to Shape(
                Compression.GZIP, "Aes",
                listOf(
                    "Shared one shared.bin - 300 a3c913071a42a95d726b4d6b10b6ba76d4d80f2ce2f81509ebdcf02e40fcf83c",
                    "Shared two copy-of-shared.bin - 300 a3c913071a42a95d726b4d6b10b6ba76d4d80f2ce2f81509ebdcf02e40fcf83c",
                    "Empty attachment empty.txt - 0 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "Protected attachment secret.bin * 64 e9b85e7e93a6459297492abb0d5b14b1dc3f4f02e8c6d2e875d108990e91fd8f",
                    recovery,
                ),
            ),
            "keepass2-empty-password.kdbx" to Shape(Compression.GZIP, "Aes", listOf(recovery)),
            "keepass2-argon2-low-memory.kdbx" to Shape(Compression.GZIP, "Argon2", listOf(recovery)),
            "keepass2-argon2-secret-and-data.kdbx" to Shape(Compression.GZIP, "Argon2", listOf(recovery)),
            "keepass2-argon2-version-0x10.kdbx" to Shape(Compression.GZIP, "Argon2", listOf(recovery)),
        )
        for ((name, shape) in expected) {
            val read = open(name)
            val h = read.container.header
            assertEquals("4.0 ${OuterCipher.AES_256} ${shape.compression} ${shape.kdf}", "${h.majorVersion}.${h.minorVersion} ${h.cipher} ${h.compression} ${h.kdf::class.simpleName}", name)
            val attachments = read.entries().map { it.second }.flatMap { e -> read.attachments(e).map { "${read.field(e, "Title")} $it" } }
            assertEquals(shape.attachments.sorted(), attachments.sorted(), name)
        }
    }

    private class Shape(val compression: Compression, val kdf: String, val attachments: List<String>)

    @Test
    fun `the Argon2 version fixtures keep the header settings they were written with`() {
        for (name in listOf("keepass2-argon2-version-0x10.kdbx", "keepass2-argon2-version-0x12.kdbx")) {
            val bytes = Fixtures.bytes(name)
            val header = assertIs<KdbxHeaderReader.Read.Valid>(KdbxHeaderReader.read(bytes), name).header
            val kdf = assertIs<KdfParameters.Argon2>(header.kdf, name)
            assertEquals(if (name.endsWith("0x10.kdbx")) 0x10U else 0x12U, kdf.version, name)
            assertEquals(Argon2Type.ARGON2ID, kdf.type, name)
            assertEquals(1024UL * 1024UL, kdf.memoryBytes, name)
            assertEquals(2U, kdf.parallelism, name)
        }
    }

    @Test
    fun `the 0x12 vault is refused by the KDF policy before any key is derived`() {
        val result = assertIs<ContainerDecode.Result.Refused>(decode("keepass2-argon2-version-0x12.kdbx"))
        assertIs<KdfRejection.OutOfBounds>(result.rejection)
    }

    @Test
    fun `the low-memory Argon2 vault has 8 KiB for 4 lanes and opens, derived as KeePass 2 does`() {
        val read = open("keepass2-argon2-low-memory.kdbx")
        val kdf = argon2(read)
        assertEquals(Argon2Type.ARGON2ID, kdf.type)
        assertEquals(8UL * 1024UL, kdf.memoryBytes)
        assertEquals(4U, kdf.parallelism)
        assertEquals("Email", read.groupOf("Example Mail"))
    }

    @Test
    fun `the Argon2 secret-key vault carries K and A`() {
        val kdf = argon2(open("keepass2-argon2-secret-and-data.kdbx"))
        assertEquals(Argon2Type.ARGON2D, kdf.type)
        assertEquals(32, kdf.secretKey?.size)
        assertEquals(16, kdf.associatedData?.size)
    }

    @Test
    fun `the empty-password vault opens with an empty password and not with the fixture password`() {
        assertEquals("Email", open("keepass2-empty-password.kdbx", password = "").groupOf("Example Mail"))
        wrongKey(decode("keepass2-empty-password.kdbx", password = TestFiles.password), "fixture password")
    }

    @Test
    fun `every fixture that opens refuses a wrong password`() {
        for (f in Fixtures.kdbx4Opening) {
            val wrong = if (f.mode == CredentialMode.KEY_FILE_ONLY) "wrong" else TestFiles.password(f.mode) + "x"
            wrongKey(decode(f.name, password = wrong), f.name)
        }
    }

    @Test
    fun `the password and key file vault needs both`() {
        val name = "keepass2-password-keyfile-v2.kdbx"
        assertEquals("Email", open(name).groupOf("Example Mail"))
        wrongKey(decode(name, keyPart = null), "password alone")
        wrongKey(decode(name, password = null), "key file alone")
        val other = TestFiles.keyFilePart(Fixtures.file(Fixtures.named("keepass2-keyfile-only-raw32.kdbx")))
        wrongKey(decode(name, keyPart = other), "another fixture's key file")
    }

    @Test
    fun `each key-file-only vault opens with its own key file and not with another's`() {
        val vaults = Fixtures.kdbx4.filter { it.mode == CredentialMode.KEY_FILE_ONLY }
        assertEquals(5, vaults.size)
        for (f in vaults) {
            assertEquals("Email", open(f.name).groupOf("Example Mail"), f.name)
            val other = vaults.first { it.keyFile != f.keyFile }
            wrongKey(decode(f.name, keyPart = TestFiles.keyFilePart(Fixtures.file(other))), "${f.name} with ${other.keyFile}")
        }
    }
}
