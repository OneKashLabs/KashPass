package org.onekash.kashpass.vault.fixtures

import org.onekash.kashpass.vault.testing.KdbxToolkit

/**
 * KDBX 3.1 vaults built in code with the throwaway fixture password, which KashPass refuses as
 * unsupported and the gated KeePass 2 tests open: one of password and key file, one of the key
 * file alone. Both use [KEY_FILE], 64 hex characters and a newline, which is neither a 32-byte
 * nor a 64-hex-character key and so is hashed with SHA-256.
 */
object Kdbx3Vaults {

    /**
     * The key file both vaults use, as [KEY_FILE_NAME]: 65 bytes, a fresh array on each read
     * because the opener zero-fills the key file it is given.
     */
    val KEY_FILE: ByteArray get() = ("0123456789abcdef".repeat(4) + "\n").toByteArray(Charsets.US_ASCII)

    const val KEY_FILE_NAME = "keyfile-65-bytes.keyx"

    /** Title of the one entry each vault holds. */
    const val TITLE = "KDBX 3.1 entry"

    private val XML = (
        "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><KeePassFile><Meta><Generator>Kdbx3Vaults</Generator></Meta>" +
            "<Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Name>Root</Name><Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>" +
            "<String><Key>Title</Key><Value>$TITLE</Value></String></Entry></Group></Root></KeePassFile>"
        ).toByteArray(Charsets.UTF_8)

    /**
     * Both vaults, with their credential mode and a fresh copy of [KEY_FILE] on each read; the
     * vault bytes get new random seeds once per JVM.
     */
    val files: List<VaultFile> get() = built.map { (name, bytes, mode) -> VaultFile(name, bytes, mode, KEY_FILE_NAME, KEY_FILE) }

    private val built: List<Triple<String, ByteArray, CredentialMode>> by lazy {
        val part = KdbxToolkit.sha256(KEY_FILE)
        listOf(
            Triple("kdbx31-password-keyfile.kdbx", KdbxToolkit.newVault3(XML, KdbxToolkit.Key(TestFiles.password, part)), CredentialMode.PASSWORD_AND_KEY_FILE),
            Triple("kdbx31-keyfile-only.kdbx", KdbxToolkit.newVault3(XML, KdbxToolkit.Key(null, part)), CredentialMode.KEY_FILE_ONLY),
        )
    }
}
