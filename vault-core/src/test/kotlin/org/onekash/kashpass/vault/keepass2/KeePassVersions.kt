package org.onekash.kashpass.vault.keepass2

import kotlin.test.fail
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawKdbx

/**
 * The KeePass 2 versions the version matrix runs, oldest first, and what each version does with a
 * file, from its source. The scripts' version table (keepass2-versions.tsv) lists the
 * same versions ([KeePassVersionsTest]); a version there without an entry here fails the matrix.
 */
internal object KeePassVersions {

    /** The version every run uses unless one is named (the scripts' KEEPASS_PIN). */
    const val PIN = "2.62"

    /**
     * One version and the support it lacks or has: [argon2id] (Argon2id from 2.47; 2.35 and 2.44
     * know only AES-KDF and Argon2d), [xmlKeyFile2] (XML 2.0 key files from 2.47) and [kdbx41]
     * (group tags, the quality check and the previous parent group from 2.48), and how it picks
     * the format it writes: [chacha20Kdbx4] (ChaCha20 alone means KDBX 4 from 2.44; 2.35 checks
     * only the KDF) and [alwaysKdbx4] (KDBX 4 at least from 2.57; before, AES-KDF with no 4.x
     * feature falls to 3.1).
     */
    data class Version(
        val name: String,
        val argon2id: Boolean,
        val xmlKeyFile2: Boolean,
        val kdbx41: Boolean,
        val chacha20Kdbx4: Boolean,
        val alwaysKdbx4: Boolean,
    )

    val all: List<Version> = listOf(
        Version("2.35", argon2id = false, xmlKeyFile2 = false, kdbx41 = false, chacha20Kdbx4 = false, alwaysKdbx4 = false),
        Version("2.44", argon2id = false, xmlKeyFile2 = false, kdbx41 = false, chacha20Kdbx4 = true, alwaysKdbx4 = false),
        Version("2.47", argon2id = true, xmlKeyFile2 = true, kdbx41 = false, chacha20Kdbx4 = true, alwaysKdbx4 = false),
        Version("2.48", argon2id = true, xmlKeyFile2 = true, kdbx41 = true, chacha20Kdbx4 = true, alwaysKdbx4 = false),
        Version("2.56", argon2id = true, xmlKeyFile2 = true, kdbx41 = true, chacha20Kdbx4 = true, alwaysKdbx4 = false),
        Version("2.57", argon2id = true, xmlKeyFile2 = true, kdbx41 = true, chacha20Kdbx4 = true, alwaysKdbx4 = true),
        Version("2.60", argon2id = true, xmlKeyFile2 = true, kdbx41 = true, chacha20Kdbx4 = true, alwaysKdbx4 = true),
        Version("2.61.1", argon2id = true, xmlKeyFile2 = true, kdbx41 = true, chacha20Kdbx4 = true, alwaysKdbx4 = true),
        Version(PIN, argon2id = true, xmlKeyFile2 = true, kdbx41 = true, chacha20Kdbx4 = true, alwaysKdbx4 = true),
    )

    /** Returns the version [name], failing when the matrix has no expectations for it. */
    fun named(name: String): Version =
        all.singleOrNull { it.name == name } ?: fail("KeePass $name has no expectations in KeePassVersions; write them before running it")

    /**
     * The report tokens a reader before 2.48 leaves out, as its `capabilities` line names them
     * (ReadVault.cs).
     */
    val PRE_KDBX41_UNSEEN = setOf(KeePass2Report.NO_GROUP_TAGS, KeePass2Report.NO_QUALITY_CHECK)

    /**
     * What sets a version's outcome for one file: its KDF, then its key file, then a protected
     * element KeePass 2 does not recognise.
     */
    enum class Kind { ARGON2ID, XML_KEY_FILE_2, PROTECTED_UNKNOWN_ELEMENT, OTHER }

    /** What a version is expected to do with a file. */
    sealed interface Expected {
        /** Opens it, with the content KashPass reads, except the report tokens in [unseen]. */
        data class Opens(val unseen: Set<String>) : Expected

        /**
         * Refuses it with exception [type] and, when [message] is set, a first message line
         * starting with it, as ReadVault.cs writes a refusal ("<type>: <first line>").
         */
        data class Refuses(val type: String, val message: String?) : Expected {
            fun matches(refusal: String): Boolean =
                refusal.substringBefore(": ") == type && (message == null || refusal.substringAfter(": ").startsWith(message))
        }
    }

    /**
     * The kind of [file], in the order a reader meets them: an Argon2id KDF (it fails before the
     * key is checked), an XML 2.0 key file (a wrong key), then an element other than KeePass 2's
     * protected Value and Binary that carries Protected="True" (met while reading the XML).
     */
    fun kindOf(file: VaultFile): Kind {
        val kdf = KdbxToolkit.effective(RawKdbx.parse(file.bytes)).kdf
        if (kdf is KdbxToolkit.Kdf.Argon2 && kdf.id) return Kind.ARGON2ID
        val key = file.keyFile?.toString(Charsets.UTF_8)
        if (key != null && key.contains("<KeyFile>") && Regex("<Version>\\s*2\\.0\\s*</Version>").containsMatchIn(key)) return Kind.XML_KEY_FILE_2
        val read = (ContainerRig.open(file) as? ContainerDecode.Result.Opened)?.read ?: fail("${file.name} does not open")
        if (read.protectedValues.keys.any { it.name != "Value" && it.name != "Binary" }) return Kind.PROTECTED_UNKNOWN_ELEMENT
        return Kind.OTHER
    }

    /**
     * The configurations [version] writes with WriteVault.cs and the file format each gets
     * ("3.1", "4.0" or "4.1"); KashPass opens the KDBX 4 ones and refuses 3.1.
     */
    fun written(version: Version): Map<String, String> = buildMap {
        put("defaults", if (version.alwaysKdbx4) "4.0" else "3.1")
        if (version.kdbx41) put("defaults-group-tags", "4.1")
        put("chacha20-aeskdf", if (version.chacha20Kdbx4) "4.0" else "3.1")
        put("argon2d", "4.0")
        if (version.argon2id) put("argon2id", "4.0")
    }

    /** What [version] does with a file of [kind]. */
    fun expected(version: Version, kind: Kind): Expected = when {
        // The key derivation throws on the unknown KDF before any HMAC check.
        kind == Kind.ARGON2ID && !version.argon2id -> Expected.Refuses("Exception", "Unknown key derivation function!")
        // The hex <Data> of an XML 2.0 key file goes through the Base64 path, or the whole file
        // is hashed, so the key is wrong.
        kind == Kind.XML_KEY_FILE_2 && !version.xmlKeyFile2 -> Expected.Refuses("InvalidCompositeKeyException", null)
        // 2.35 reads an unknown protected element's text and then keeps reading into its
        // siblings, so it refuses the file KashPass opened; 2.44 and later read past the element.
        kind == Kind.PROTECTED_UNKNOWN_ELEMENT && version.name == "2.35" -> Expected.Refuses("FormatException", null)
        else -> Expected.Opens(if (version.kdbx41) emptySet() else PRE_KDBX41_UNSEEN)
    }
}
