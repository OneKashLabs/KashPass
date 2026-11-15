package org.onekash.kashpass.vault.fixtures

import kotlin.test.fail

/**
 * Every vault in the test fixtures folder with how it is unlocked; tests take their lists from
 * here, and [FixturesTest] fails when the folder holds a vault this catalogue does not list.
 */
object Fixtures {

    /**
     * One fixture vault. [sampleContent] marks the vaults holding the generated sample entries
     * ("Example Mail", "Example Bank", "No password entry"); [kdfPolicyRefuses] the ones whose KDF
     * settings `KdfPolicy` refuses.
     */
    data class Fixture(
        val name: String,
        val mode: CredentialMode = CredentialMode.PASSWORD,
        val keyFile: String? = null,
        val sampleContent: Boolean = true,
        val kdfPolicyRefuses: Boolean = false,
    )

    /** Saved by the owner's KeePass 2 desktop app (File, New), not generated. */
    const val DESKTOP = "keepass2-desktop-new-database.kdbx"

    /**
     * Written with plugin custom data, auto-type, a recycle bin, a templates group and every Meta
     * setting KeePass 2 writes set to a non-default value, on top of the sample content.
     */
    const val PLUGIN_DATA = "keepass2-plugin-data.kdbx"

    /** Every KDBX 4 fixture. */
    val kdbx4: List<Fixture> = listOf(
        Fixture("keepass2-default-aeskdf.kdbx"),
        Fixture("keepass2-argon2id.kdbx"),
        Fixture("keepass2-chacha20-argon2d.kdbx"),
        Fixture("keepass2-kdbx41-tags.kdbx"),
        Fixture("keepass2-weak-aeskdf-6000.kdbx"),
        Fixture(DESKTOP, sampleContent = false),
        Fixture("keepass2-compression-none.kdbx"),
        Fixture("keepass2-multiblock-attachment.kdbx"),
        Fixture("keepass2-shared-attachments.kdbx"),
        Fixture("keepass2-empty-password.kdbx", CredentialMode.EMPTY_PASSWORD),
        Fixture("keepass2-argon2-low-memory.kdbx"),
        Fixture("keepass2-argon2-secret-and-data.kdbx"),
        Fixture("keepass2-argon2-version-0x10.kdbx"),
        Fixture("keepass2-argon2-version-0x12.kdbx", kdfPolicyRefuses = true),
        Fixture("keepass2-password-keyfile-v2.kdbx", CredentialMode.PASSWORD_AND_KEY_FILE, "keepass2-keyfile-v2.keyx"),
        Fixture("keepass2-keyfile-only-v2.kdbx", CredentialMode.KEY_FILE_ONLY, "keepass2-keyfile-v2.keyx"),
        Fixture("keepass2-keyfile-only-v1.kdbx", CredentialMode.KEY_FILE_ONLY, "keepass2-keyfile-v1.key"),
        Fixture("keepass2-keyfile-only-raw32.kdbx", CredentialMode.KEY_FILE_ONLY, "keepass2-keyfile-raw32.key"),
        Fixture("keepass2-keyfile-only-hex64.kdbx", CredentialMode.KEY_FILE_ONLY, "keepass2-keyfile-hex64.key"),
        Fixture("keepass2-keyfile-only-other.kdbx", CredentialMode.KEY_FILE_ONLY, "keepass2-keyfile-other.key"),
        Fixture(PLUGIN_DATA),
    )

    /** The KDBX 4 fixtures whose KDF settings `KdfPolicy` accepts, which therefore open. */
    val kdbx4Opening: List<Fixture> get() = kdbx4.filterNot { it.kdfPolicyRefuses }

    /** Returns the fixture named [name]. */
    fun named(name: String): Fixture = kdbx4.singleOrNull { it.name == name } ?: fail("no fixture $name in the catalogue")

    /**
     * System property set by `-Pkashpass.fixturesDir=<dir>`: read the fixtures from that folder,
     * which holds the fixtures a named KeePass 2 version wrote, instead of the test resources.
     * [DESKTOP] is never regenerated, so it always comes from the test resources.
     */
    const val DIR_PROPERTY = "kashpass.fixturesDir"

    /** The folder [DIR_PROPERTY] names, an absolute path or one relative to the repository root. */
    val dir: java.io.File? get() = System.getProperty(DIR_PROPERTY)?.takeIf { it.isNotBlank() }
        ?.let { java.io.File(it).takeIf { f -> f.isAbsolute } ?: java.io.File(TestFiles.root, it) }

    /** Returns the bytes of the fixture file [name] (a vault or a key file). */
    fun bytes(name: String): ByteArray {
        val dir = dir
        if (dir != null && name != DESKTOP) {
            val file = java.io.File(dir, name)
            return if (file.isFile) file.readBytes() else fail("missing fixture $name in $dir")
        }
        return Fixtures::class.java.getResourceAsStream("/fixtures/$name")?.use { it.readBytes() } ?: fail("missing fixture $name in test resources")
    }

    /** Returns [fixture] as a file named [name], holding [bytes] (by default the fixture's own). */
    fun file(fixture: Fixture, name: String = fixture.name, bytes: ByteArray = bytes(fixture.name)): VaultFile =
        VaultFile(name, bytes, fixture.mode, fixture.keyFile, fixture.keyFile?.let { bytes(it) })
}
