package org.onekash.kashpass.vault.fixtures

import java.io.File
import kotlin.test.assertIs
import kotlin.test.fail
import org.onekash.kashpass.vault.doc.KeyFile
import org.onekash.kashpass.vault.doc.KeyFileResult
import org.onekash.kashpass.vault.doc.VaultKey

/** How a test vault is unlocked; every password is the throwaway fixture password. */
enum class CredentialMode(val manifest: String) {
    PASSWORD("password"),
    EMPTY_PASSWORD("empty-password"),
    PASSWORD_AND_KEY_FILE("password+keyfile"),
    KEY_FILE_ONLY("keyfile-only"),
}

/** A test vault as a file: its name, its bytes, and how it is unlocked. */
class VaultFile(
    val name: String,
    val bytes: ByteArray,
    val mode: CredentialMode = CredentialMode.PASSWORD,
    val keyFileName: String? = null,
    val keyFile: ByteArray? = null,
)

/** Shared plumbing for tests that hand test vaults to a reader: credentials and manifests. */
object TestFiles {

    /**
     * Throwaway password of the fixtures, from `kashpass.fixture.password` or the published one.
     */
    val password: String = System.getProperty("kashpass.fixture.password") ?: "kashpass-test"

    /** Root of the repository: the folder holding settings.gradle.kts. */
    val root: File by lazy {
        generateSequence(File("").absoluteFile) { it.parentFile }.firstOrNull { File(it, "settings.gradle.kts").isFile }
            ?: fail("no settings.gradle.kts above ${File("").absolutePath}")
    }

    /** Returns the password a vault unlocked with [mode] takes; null for a key file alone. */
    fun password(mode: CredentialMode): String? = when (mode) {
        CredentialMode.PASSWORD, CredentialMode.PASSWORD_AND_KEY_FILE -> password
        CredentialMode.EMPTY_PASSWORD -> ""
        CredentialMode.KEY_FILE_ONLY -> null
    }

    /** Returns the key-file part of [file]'s key file as KashPass reads it, or null without one. */
    fun keyFilePart(file: VaultFile): ByteArray? =
        file.keyFile?.let { assertIs<KeyFileResult.Key>(KeyFile.parse(it.copyOf()), file.name).part }

    /** Builds the key for [file] as the opener does. */
    internal fun credentials(file: VaultFile): VaultKey {
        val pass = password(file.mode)
        val part = keyFilePart(file)
        return try {
            when {
                part == null -> VaultKey.password(pass?.toCharArray() ?: fail("${file.name}: key-file mode without a key file"))
                pass == null -> VaultKey.keyFile(part)
                else -> VaultKey.password(pass.toCharArray(), part)
            }
        } finally {
            part?.fill(0)
        }
    }

    /**
     * Writes [files], their key files and `keepass2-manifest.tsv` (file, credential mode, key file
     * or "-") into [dir].
     */
    fun writeManifest(dir: File, files: List<VaultFile>) {
        val manifest = StringBuilder()
        for (f in files) {
            require(f.name.none { it == '\t' || it == '\n' || it == '/' }) { f.name }
            File(dir, f.name).writeBytes(f.bytes)
            if (f.keyFileName != null) File(dir, f.keyFileName).writeBytes(f.keyFile ?: fail("${f.name}: no key file bytes"))
            manifest.append(f.name).append('\t').append(f.mode.manifest).append('\t').append(f.keyFileName ?: "-").append('\n')
        }
        File(dir, "keepass2-manifest.tsv").writeText(manifest.toString())
    }

    /** Reads the manifest in [dir] back into files; the vault bytes are left empty. */
    fun readManifest(dir: File): List<VaultFile> =
        File(dir, "keepass2-manifest.tsv").readLines().filter { it.isNotEmpty() }.map { line ->
            val (name, mode, key) = line.split('\t')
            val keyName = key.takeIf { it != "-" }
            VaultFile(name, ByteArray(0), CredentialMode.entries.single { it.manifest == mode }, keyName, keyName?.let { File(dir, it).readBytes() })
        }
}
