package org.onekash.kashpass.vault.keepass2

import java.io.File
import kotlin.test.fail
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile

/**
 * The reader grid: cipher (AES-256, ChaCha20) x KDF (AES-KDF, Argon2d, Argon2id) x KDBX 4.0 or
 * 4.1 x compression (gzip, none) x attachments (none, one, 2 MiB) x credentials (password, empty
 * password, password and key file, key file only), written by KeePass 2 into
 * build/fixtures/grid/keepass2 ([dir]), never committed. [SKIPPED] lists the cells KeePass 2
 * can't produce.
 */
object GridWriters {

    /** Cells KeePass 2 can't produce, with the reason. */
    val SKIPPED = listOf(
        "duplicate attachments: KeePass 2 merges equal attachments on save; the corpus case attachment-identical-pool-items, built by the test toolkit, stands in",
    )

    /**
     * Returns the grid written to [dir] for [writer], without the vault bytes ([load] reads
     * them); fails naming [source] when it is missing.
     */
    fun written(writer: String, source: String): List<VaultFile> {
        val dir = dir(writer)
        if (!File(dir, "keepass2-manifest.tsv").isFile) fail("no grid from $writer in ${dir.path}: run $source")
        return TestFiles.readManifest(dir)
    }

    /** Returns [file] from [dir] for [writer], with its bytes. */
    fun load(writer: String, file: VaultFile): VaultFile =
        VaultFile(file.name, File(dir(writer), file.name).readBytes(), file.mode, file.keyFileName, file.keyFile)

    /**
     * The folder of [writer]'s grid: build/fixtures/grid/[writer], or <dir>/grid/[writer] when
     * [Fixtures.dir] names a version's regenerated fixtures.
     */
    private fun dir(writer: String): File = File(Fixtures.dir ?: File(TestFiles.root, "build/fixtures"), "grid/$writer")
}
