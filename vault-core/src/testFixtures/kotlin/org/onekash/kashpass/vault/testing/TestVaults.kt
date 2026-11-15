package org.onekash.kashpass.vault.testing

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import org.onekash.kashpass.vault.doc.FileAccess
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.testing.VaultModel.Doc
import org.onekash.kashpass.vault.testing.VaultModel.Entry
import org.onekash.kashpass.vault.testing.VaultModel.Group
import org.onekash.kashpass.vault.testing.VaultModel.Value

/**
 * Generates KDBX 4 vaults in code for tests that must not depend on the fixture files, such as
 * app tests. Every vault is written by [KdbxToolkit.newVault] ([VaultModel.write] for the
 * structured ones), test code that shares no container code with the KashPass decoder under test.
 * Vaults use AES-KDF, so unlocking stays fast, and a ChaCha20 inner stream unless named otherwise.
 */
object TestVaults {

    /** Password of every generated vault; a throwaway, never a real password. */
    const val PASSWORD = "kashpass-test"

    /** A test entry: title, user name, password. */
    data class TestEntry(val title: String, val userName: String = "", val password: String = "")

    /** Key part of [KEY_FILE]; a throwaway, never a real key. */
    val KEY_FILE_PART: ByteArray get() = ByteArray(32) { (it * 11 + 5).toByte() }

    /** A throwaway XML version 2 key file holding [KEY_FILE_PART]. */
    val KEY_FILE: ByteArray get() = keyFileFor(KEY_FILE_PART)

    /** Returns an XML version 2 key file holding [part], with its hash. */
    fun keyFileFor(part: ByteArray): ByteArray {
        val hex = part.joinToString("") { "%02X".format(it) }
        val hash = MessageDigest.getInstance("SHA-256").digest(part).copyOf(4).joinToString("") { "%02X".format(it) }
        val lines = hex.chunked(32).joinToString("") { line -> "\t\t\t" + line.chunked(8).joinToString(" ") + "\n" }
        return ("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n" +
            "\t<Key>\n\t\t<Data Hash=\"$hash\">\n$lines\t\t</Data>\n\t</Key>\n</KeyFile>").toByteArray(Charsets.UTF_8)
    }

    /**
     * Returns the bytes of a vault holding [entries] in a group named [groupName]. [password] null
     * leaves the password out of the composite key; [keyPart] adds a key-file part, combined by
     * [KdbxToolkit.Key] so the vault doesn't depend on KashPass's key code.
     */
    fun bytes(
        entries: List<TestEntry> = listOf(TestEntry("Example Mail", "alice", "mail-pass"), TestEntry("Example Bank", "bob", "bank-pass")),
        groupName: String = "General",
        aesRounds: ULong = 600_000UL,
        password: String? = PASSWORD,
        keyPart: ByteArray? = null,
    ): ByteArray = encoded(Doc(root = Group("Root", groups = listOf(Group(groupName, entries = entries.map(::entry))))), aesRounds, password, keyPart)

    /**
     * Returns the bytes of a vault that exercises the browser:
     * - root group "Root" holds "Router" (user admin) directly
     * - "Email" holds "Example Mail" (alice): URL, notes with non-ASCII text, tag "personal",
     *   custom field "Account ID" = "A-1234", protected custom field "otp", one history version
     * - "Banking" holds "Example Bank" (bob) with attachment "recovery-codes.txt", and an entry
     *   without a title (user "nobody")
     * - "Work" holds a second group named "Email" with "Work Mail" (carol)
     * - the enabled recycle bin "Recycle Bin" holds "Old Bank" (dave)
     */
    fun browserVault(aesRounds: ULong = 600_000UL): ByteArray {
        val mail = Entry(
            listOf(
                "Title" to Value.Plain("Example Mail"), "UserName" to Value.Plain("alice"), "Password" to Value.Protected("mail-pass"),
                "URL" to Value.Plain("https://mail.example.com"), "Notes" to Value.Plain("Recovery hint: ünïcödé"), "Account ID" to Value.Plain("A-1234"),
                "otp" to Value.Protected("otpauth://totp/mail?secret=JBSWY3DPEHPK3PXP"),
            ),
            tags = listOf("personal"),
            history = listOf(entry(TestEntry("Example Mail (old)", "alice-old", "old-mail-pass"))),
        )
        val bank = entry(TestEntry("Example Bank", "bob", "bank-pass")).copy(binaries = listOf("recovery-codes.txt" to 0))
        val bin = Group("Recycle Bin", entries = listOf(entry(TestEntry("Old Bank", "dave", "old-bank-pass"))))
        val root = Group(
            "Root",
            entries = listOf(entry(TestEntry("Router", "admin", "router-pass"))),
            groups = listOf(
                Group("Email", entries = listOf(mail)),
                Group("Banking", entries = listOf(bank, entry(TestEntry("", "nobody")))),
                Group("Work", groups = listOf(Group("Email", entries = listOf(entry(TestEntry("Work Mail", "carol")))))),
                bin,
            ),
        )
        return encoded(Doc(root, recycleBin = bin.uuid, attachments = listOf("1111 2222".toByteArray())), aesRounds)
    }

    /**
     * Returns the bytes of a vault whose two groups share one UUID and whose two entries ("First"
     * with user "first-user", "Second" with user "second-user") share another, as a damaged file
     * can.
     */
    fun repeatedIdsVault(): ByteArray {
        val entryId = UUID.randomUUID()
        val groupId = UUID.randomUUID()
        val first = entry(TestEntry("First", "first-user")).copy(uuid = entryId)
        val second = entry(TestEntry("Second", "second-user")).copy(uuid = entryId)
        val root = Group("Root", groups = listOf(Group("Alpha", entries = listOf(first), uuid = groupId), Group("Beta", entries = listOf(second), uuid = groupId)))
        return encoded(Doc(root))
    }

    /**
     * Returns the bytes of a vault with one entry whose title "Secret bank" is protected and whose
     * plain notes say "bank login", plus a plain "Other" entry. A protected title is shown and
     * searched, so "bank" matches the title first.
     */
    fun protectedTitleVault(): ByteArray {
        val hidden = Entry(listOf("Title" to Value.Protected("Secret bank"), "UserName" to Value.Plain("eve"), "Notes" to Value.Plain("bank login")))
        return encoded(Doc(Group("Root", groups = listOf(Group("General", entries = listOf(hidden, entry(TestEntry("Other", "frank"))))))))
    }

    /**
     * Returns the bytes of a vault whose Meta protects user names, URLs and notes (older desktop
     * releases offered this in Database Settings). Entry "Meta Protected" (user "eve") stores its
     * user name, URL "https://meta.example" and notes "meta notes" protected, its password
     * "plain-pass" in clear, a protected custom field "PIN" = "4711" and a plain one "Floor" =
     * "third". Entry "Ordinary" (user "olga") stores plain fields and a protected password
     * "ordinary-pass".
     */
    fun metaProtectedVault(): ByteArray = rawXmlVault(keePassXml(entries = META_PROTECTED_ENTRIES, meta = META_PROTECTED_META))

    /** The Meta of [metaProtectedVault]. */
    const val META_PROTECTED_META = "<Generator>test</Generator><MemoryProtection><ProtectTitle>False</ProtectTitle>" +
        "<ProtectUserName>True</ProtectUserName><ProtectPassword>True</ProtectPassword><ProtectURL>True</ProtectURL>" +
        "<ProtectNotes>True</ProtectNotes></MemoryProtection>"

    private const val META_PROTECTED_ENTRIES = "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>" +
        "<String><Key>Title</Key><Value>Meta Protected</Value></String>" +
        "<String><Key>UserName</Key><Value Protected=\"True\">{{p:eve}}</Value></String>" +
        "<String><Key>Password</Key><Value>plain-pass</Value></String>" +
        "<String><Key>URL</Key><Value Protected=\"True\">{{p:https://meta.example}}</Value></String>" +
        "<String><Key>Notes</Key><Value Protected=\"True\">{{p:meta notes}}</Value></String>" +
        "<String><Key>PIN</Key><Value Protected=\"True\">{{p:4711}}</Value></String>" +
        "<String><Key>Floor</Key><Value>third</Value></String></Entry>" +
        "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID>" +
        "<String><Key>Title</Key><Value>Ordinary</Value></String>" +
        "<String><Key>UserName</Key><Value>olga</Value></String>" +
        "<String><Key>Password</Key><Value Protected=\"True\">{{p:ordinary-pass}}</Value></String></Entry>"

    /**
     * Returns the bytes of a vault holding KeePass 2 field references of every kind, for the
     * reference resolver and its KeePass 2 check. Entry n has the UUID [refUuid] (n), written in a
     * reference as [refHex] (n). In XML order the root group holds group Email, entry 2, groups
     * Banking, Chains and Targets, then the recycle bin, so tree order (a group's entries before
     * its groups) differs from XML order:
     * - 2 "Example Root", user "rootuser".
     * - Email: 10 "Example Mail", user "alice@example.test", password "mail-pass", URL
     *   "https://mail.example.test", notes "webmail login", custom "Account" = "12345", protected
     *   custom "PIN" = "4711".
     * - Banking: 11 "Example Bank", user "bob", password "bank-pass", a history version titled
     *   "Ancient Bank"; 12 "Example Mail", user "second-mail"; 13 "Café Noir", user "cafeuser";
     *   14 "Reference Holder" with user `{REF:U@T:Example Bank}`, password `{REF:P@I:<11>}`
     *   stored in clear, URL `https://{REF:U@T:Example Bank}.example`, notes
     *   `pw {REF:P@T:Example Bank} and {S:Account}`, custom "Account" = "H-1" and "Hint" =
     *   `see {S:Missing}`; 15 "Nested", user `{REF:P@I:<14>}`;
     *   16 "Loop A" and 17 "Loop B" whose passwords refer to each other; 18 "Self" whose password
     *   refers to itself; 19 with two Title strings, "First Title" then "Second Title".
     * - Chains: 201 to 212 "Chain k", user `{REF:U@I:<k+1>}`, the last one "end".
     * - Targets: 301 to 321 "Target k".
     * - Probes: 30 "Probes", one custom field per reference case in [REFERENCE_PROBES], so a
     *   KeePass 2 check resolves each one as stored.
     * - Recycle bin (Meta's RecycleBinUUID): 20 "Old Login", user "olduser", password "old-pass".
     */
    fun referenceVault(): ByteArray = rawXmlVault(keePassXml(entries = referenceGroups(), meta = "<Generator>test</Generator><RecycleBinEnabled>True</RecycleBinEnabled><RecycleBinUUID>${refUuid(199)}</RecycleBinUUID>"))

    /**
     * The values of [referenceVault]'s entry "Probes": every wanted and search-in code, lower-case
     * codes, words, `-word`, accents, the recycle bin, unknown codes and bad syntax, empty search
     * text, nesting, a loop, the depth limit, the shared cache and the 20-pass limit.
     */
    val REFERENCE_PROBES: List<String> by lazy {
        listOf(
            "{REF:T@U:bob}", "{REF:A@T:Example Mail}", "{REF:N@T:Example Mail}", "{REF:I@U:bob}", "{REF:U@P:bank-pass}",
            "{REF:T@A:mail.example}", "{REF:U@N:webmail}", "{REF:T@O:12345}", "{REF:U@O:4711}", "{ref:u@t:example bank}",
            "{REF:U@T:Bank Example}", "{REF:U@T:Example -root}", "{REF:U@T:cafe}", "{REF:P@T:Old Login}", "{REF:U@T:Second Title}",
            "user: {REF:U@T:Example Bank} end", "{REF:U@T:Example}", "{REF:X@T:Example Bank}", "{REF:O@T:Example Bank}",
            "{REF:T@Z:Example}", "{REF:T@T:nothing like this}", "{REF:U@T:\"Bank Example\"}", "{REF:U@T:Ancient}", "{REF:T@T:}",
            "{REF:TxT:Example}", "{REF:T@TxExample}", "{REF:T@T:Example", "{REF:T@T: }", "{REF:T@T:\"\"}",
            (1..21).joinToString(",") { "{REF:T@I:${refHex(300 + it)}}" },
            "{REF:T@T:zz}".repeat(20) + "{REF:T@I:${refHex(11)}}",
            "{REF:U@I:${refHex(201)}}|{REF:U@I:${refHex(211)}}", "{REF:U@T:Example Bank} {ref:u@t:example bank}",
            "{REF:P@T:Loop A}", "{REF:U@T:Nested}", "{REF:U@I:${refHex(202)}}",
        )
    }

    /** The base64 UUID of [referenceVault]'s entry or group [n]. */
    fun refUuid(n: Int): String = java.util.Base64.getEncoder().encodeToString(java.nio.ByteBuffer.allocate(16).putLong(0).putLong(n.toLong()).array())

    /** The UUID of [referenceVault]'s entry [n] in a reference: 32 upper-case hex digits. */
    fun refHex(n: Int): String = "0000000000000000" + "%016X".format(n.toLong())

    private fun refString(key: String, value: String, protected: Boolean = false) =
        if (protected) "<String><Key>$key</Key><Value Protected=\"True\">{{p:$value}}</Value></String>"
        else "<String><Key>$key</Key><Value>$value</Value></String>"

    private fun refEntry(n: Int, vararg fields: Pair<String, String>, protected: Set<String> = emptySet(), extra: String = "") =
        "<Entry><UUID>${refUuid(n)}</UUID>" + fields.joinToString("") { (k, v) -> refString(k, v, k in protected) } + extra + "</Entry>"

    private fun refGroup(n: Int, name: String, content: String) = "<Group><UUID>${refUuid(n)}</UUID><Name>$name</Name>$content</Group>"

    private fun referenceGroups(): String {
        val email = refGroup(
            100, "Email",
            refEntry(
                10, "Title" to "Example Mail", "UserName" to "alice@example.test", "Password" to "mail-pass",
                "URL" to "https://mail.example.test", "Notes" to "webmail login", "Account" to "12345", "PIN" to "4711",
                protected = setOf("Password", "PIN"),
            ),
        )
        val banking = refGroup(
            101, "Banking",
            refEntry(
                11, "Title" to "Example Bank", "UserName" to "bob", "Password" to "bank-pass", protected = setOf("Password"),
                extra = "<History>" + refEntry(11, "Title" to "Ancient Bank", "UserName" to "ancient") + "</History>",
            ) +
                refEntry(12, "Title" to "Example Mail", "UserName" to "second-mail") +
                refEntry(13, "Title" to "Café Noir", "UserName" to "cafeuser") +
                refEntry(
                    14, "Title" to "Reference Holder", "UserName" to "{REF:U@T:Example Bank}", "Password" to "{REF:P@I:${refHex(11)}}",
                    "URL" to "https://{REF:U@T:Example Bank}.example", "Notes" to "pw {REF:P@T:Example Bank} and {S:Account}",
                    "Account" to "H-1", "Hint" to "see {S:Missing}",
                ) +
                refEntry(15, "Title" to "Nested", "UserName" to "{REF:P@I:${refHex(14)}}") +
                refEntry(16, "Title" to "Loop A", "Password" to "{REF:P@I:${refHex(17)}}") +
                refEntry(17, "Title" to "Loop B", "Password" to "{REF:P@I:${refHex(16)}}") +
                refEntry(18, "Title" to "Self", "Password" to "{REF:P@I:${refHex(18)}}") +
                refEntry(19, "Title" to "First Title", "Title" to "Second Title"),
        )
        val chains = refGroup(102, "Chains", (1..12).joinToString("") { k ->
            refEntry(200 + k, "Title" to "Chain $k", "UserName" to if (k < 12) "{REF:U@I:${refHex(200 + k + 1)}}" else "end")
        })
        val targets = refGroup(103, "Targets", (1..21).joinToString("") { k -> refEntry(300 + k, "Title" to "Target $k") })
        val probes = refGroup(104, "Probes", refEntry(30, "Title" to "Probes", *REFERENCE_PROBES.mapIndexed { i, v -> "Probe %02d".format(i + 1) to v }.toTypedArray()))
        val bin = refGroup(199, "Recycle Bin", refEntry(20, "Title" to "Old Login", "UserName" to "olduser", "Password" to "old-pass", protected = setOf("Password")))
        // keePassXml wraps these in the root group, UUID 1.
        return email + refEntry(2, "Title" to "Example Root", "UserName" to "rootuser") + banking + chains + targets + probes + bin
    }

    /**
     * Returns the bytes of a vault whose decrypted XML is [xml], written as given, so tests can
     * build documents no model writes. Each `{{p:text}}` is replaced, in document order, by `text`
     * encrypted with the inner stream, which is how a Protected="True" value is stored; any other
     * text is written as it is. [attachments] become the inner-header attachments in order, none
     * protected. [minor] is the KDBX 4 minor version. AES-KDF at 1,000 rounds.
     */
    fun rawXmlVault(xml: String, attachments: List<ByteArray> = emptyList(), minor: Int = 0): ByteArray {
        val streamKey = ByteArray(64).also { SecureRandom().nextBytes(it) }
        val stream = InnerStream.create(KdbxToolkit.CHACHA20, streamKey)
        val encrypted = PLACEHOLDER.replace(xml) { Base64.getEncoder().encodeToString(stream.process(it.groupValues[1].toByteArray())) }
        return KdbxToolkit.newVault(
            encrypted.toByteArray(Charsets.UTF_8), null, KdbxToolkit.Key(PASSWORD), KdbxToolkit.Kdf.Aes(1_000UL, null),
            attachments = attachments.map { false to it }, minor = minor, innerStreamKey = streamKey,
        )
    }

    private val PLACEHOLDER = Regex("""\{\{p:([^}]*)}}""")

    /**
     * A minimal KeePass document for [rawXmlVault]: [entries] are raw Entry elements in the root
     * group, [prolog] goes between the XML declaration and the root element.
     */
    fun keePassXml(entries: String = "", meta: String = "<Generator>test</Generator>", prolog: String = ""): String =
        "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n$prolog<KeePassFile>\n\t<Meta>$meta</Meta>\n" +
            "\t<Root>\n\t\t<Group>\n\t\t\t<UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>\n\t\t\t<Name>Root</Name>\n$entries\t\t</Group>\n" +
            "\t\t<DeletedObjects />\n\t</Root>\n</KeePassFile>"

    /**
     * Returns a KDBX 4 vault whose inner stream is Salsa20 with a 32-byte key: a KDBX 4 save uses
     * ChaCha20, and a reader accepts Salsa20 too. Its entries' passwords are protected values.
     * AES-KDF at [aesRounds].
     */
    fun salsa20Vault(entries: List<TestEntry> = listOf(TestEntry("Salsa Mail", "alice", "salsa-pass"), TestEntry("Salsa Bank", "bob", "bänk-päss")), aesRounds: ULong = 6_000UL): ByteArray =
        encoded(Doc(Group("Root", groups = listOf(Group("General", entries = entries.map(::entry))))), aesRounds, innerStream = KdbxToolkit.SALSA20)

    /**
     * Unlocks [bytes] with [password] and [keyFile] through the real [VaultOpener] over a fresh
     * fake storage, holding the file with [access]. The opener's limits come from [maxHeapBytes]
     * when given, else from this JVM's heap.
     */
    suspend fun unlock(
        bytes: ByteArray,
        password: String = PASSWORD,
        keyFile: ByteArray? = null,
        access: FileAccess = FileAccess.READ_WRITE,
        maxHeapBytes: Long? = null,
    ): OpenResult.Unlocked {
        val storage = FakeVaultStorage().apply { put(LOCATION, bytes) }
        val opener = if (maxHeapBytes == null) {
            VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.Default)
        } else {
            VaultOpener(storage, FakeVaultStateStore(), Dispatchers.Default, maxHeapBytes = { maxHeapBytes }) { b, h, c, budget -> VaultXmlCodec.decode(b, h, c, budget) }
        }
        val result = opener.open(LOCATION, password.toCharArray(), keyFile = keyFile, access = access)
        return result as? OpenResult.Unlocked ?: error("test vault did not unlock: $result")
    }

    /** The location [unlock] reads from. */
    const val LOCATION = "content://fake/browser.kdbx"

    private fun encoded(
        doc: Doc,
        aesRounds: ULong = 600_000UL,
        password: String? = PASSWORD,
        keyPart: ByteArray? = null,
        innerStream: Int = KdbxToolkit.CHACHA20,
    ): ByteArray = VaultModel.write(doc, aesRounds, password, keyPart, innerStream)

    private fun entry(e: TestEntry) = Entry(listOf("Title" to Value.Plain(e.title), "UserName" to Value.Plain(e.userName), "Password" to Value.Protected(e.password)))
}
