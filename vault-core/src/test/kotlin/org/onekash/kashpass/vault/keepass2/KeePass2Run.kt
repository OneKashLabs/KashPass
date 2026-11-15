package org.onekash.kashpass.vault.keepass2

import java.io.File
import java.util.Base64
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.TimeUnit
import kotlin.test.fail
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.keepass2.KeePass2Report.Companion.toHex

/**
 * Runs KeePass 2 over test vaults in one batch. The gated KeePass 2 tests run only with
 * `-Pkashpass.keepass2`; they need Docker and the local fixture scripts, and fail naming the
 * missing one. The version is the scripts' pin ([KeePassVersions.PIN]) unless a call or
 * `-Pkashpass.keepass=<v>` ([VERSION_PROPERTY]) names another from the scripts' version table
 * ([runTool]).
 */
object KeePass2Run {

    /** System property set by `-Pkashpass.keepass2`. */
    const val PROPERTY = "kashpass.keepass2"

    /** System property set by `-Pkashpass.keepass=<v>`: the KeePass 2 version every run uses. */
    const val VERSION_PROPERTY = "kashpass.keepass"

    /** The version named by [VERSION_PROPERTY], or null for the scripts' pin. */
    val namedVersion: String? get() = System.getProperty(VERSION_PROPERTY)?.takeIf { it.isNotBlank() }

    /** A fresh HMAC key for one run; reports from different runs never compare. */
    fun newKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    /**
     * Opens every file with KeePass 2 ([version], else the selected one) and returns its report per
     * file name.
     */
    fun keepass2(files: List<VaultFile>, key: ByteArray, version: String? = null): Map<String, KeePass2Report> =
        batch("keepass2", "keepass2-read.sh", ".kp2", files, key, version).mapValues { KeePass2Report.parse(it.value) }

    /** KeePass 2's hashed plain-XML export of one file ([KeePassXml]), or its refusal. */
    sealed interface Export {
        /** [millis] is KeePass 2's time to load the file and write the export. */
        class Opened internal constructor(internal val xml: KeePassXml, val millis: Long) : Export

        class Refused(val message: String) : Export {
            override fun toString() = "refused: $message"
        }
    }

    /**
     * Has KeePass 2 open every file and write its plain XML with every value hashed under
     * [key] (`keepass2-read.sh --export`); returns the export per file name.
     */
    fun keepass2Xml(files: List<VaultFile>, key: ByteArray): Map<String, Export> {
        val run = runTool("keepass2-export", "keepass2-read.sh", "--export", files, key)
        val times = File(run.output, "export-times.tsv").takeIf { it.isFile }?.readLines().orEmpty()
            .mapNotNull { line -> line.split('\t').takeIf { it.size == 2 }?.let { it[0] to it[1].toLong() } }.toMap()
        return files.associate { f ->
            val xml = File(run.output, f.name + ".xml")
            val refused = File(run.output, f.name + ".xml.refused")
            f.name to when {
                xml.isFile -> Export.Opened(KeePassXml.parse(xml.readText()), times[f.name] ?: -1)
                refused.isFile -> Export.Refused(refused.readText())
                else -> fail("keepass2-read.sh wrote no export for ${f.name}; log: ${run.log.path}")
            }
        }
    }

    /** One differential case: [ops] replayed on [input] as the KeePass 2 UI does them. */
    class ReplayCase internal constructor(val name: String, val input: VaultFile, internal val ops: List<CompanionOp>)

    /**
     * KeePass 2's result of one [ReplayCase]: the hashed export of the file it saved, the time span
     * of the replayed actions, every time field they set, and the [file] it saved.
     */
    class Replayed internal constructor(internal val xml: KeePassXml, internal val window: KeePassXml.Window, val touched: List<String>, val file: File)

    /**
     * Replays every case in KeePass 2 as its UI changes its model, saves and exports it
     * (`keepass2-read.sh --replay`); returns the result per case name.
     */
    internal fun keepass2Replay(cases: List<ReplayCase>, key: ByteArray): Map<String, Replayed> {
        val inputs = cases.map { it.input }.distinctBy { it.name }
        val run = runTool("keepass2-replay", "keepass2-read.sh", "--replay", inputs, key) { dir ->
            val manifest = StringBuilder()
            for (c in cases) {
                require(c.name.none { it == '\t' || it == '\n' || it == '/' }) { c.name }
                manifest.append(c.name).append('\t').append(c.input.name).append('\t').append(c.input.mode.manifest).append('\t')
                    .append(c.input.keyFileName ?: "-").append('\n')
                File(dir, "${c.name}.ops").writeText(c.ops.joinToString("\n") { it.line } + "\n")
            }
            File(dir, "replay-manifest.tsv").writeText(manifest.toString())
        }
        return cases.associate { c ->
            val xml = File(run.output, "${c.name}.xml")
            if (!xml.isFile) fail("keepass2-read.sh --replay wrote nothing for ${c.name}; log: ${run.log.path}")
            val (start, end) = File(run.output, "${c.name}.window").readLines().map { Instant.parse(it.trim()) }
            val touched = File(run.output, "${c.name}.touched").readLines().filter { it.isNotBlank() }
            c.name to Replayed(KeePassXml.parse(xml.readText()), KeePassXml.Window.of(start, end), touched, File(run.output, "${c.name}.kdbx"))
        }
    }

    /**
     * One merge: [phone] (KashPass's save of [base] after [phoneOps]) and the desktop copy
     * KeePass 2 makes from [base] with [desktopOps]; each side's replayed times are [phoneAt] and
     * [desktopAt].
     */
    class MergeCase internal constructor(
        val name: String,
        val base: VaultFile,
        val phone: VaultFile,
        internal val phoneOps: List<CompanionOp>,
        internal val desktopOps: List<CompanionOp>,
        val phoneAt: Instant,
        val desktopAt: Instant,
    )

    /** One merged result: its hashed export and the file KeePass 2 saved. */
    class Merged internal constructor(internal val xml: KeePassXml, val file: VaultFile)

    /** The four merges of a [MergeCase]: target, then source; A2 is KeePass 2's own phone copy. */
    val MERGES = listOf("D-A", "A-D", "D-A2", "A2-D")

    /**
     * Runs KeePass 2's Synchronize for every case four ways ([MERGES]; `keepass2-read.sh --merge`)
     * and returns each result by case name and merge.
     */
    internal fun keepass2Merge(cases: List<MergeCase>, key: ByteArray): Map<String, Map<String, Merged>> {
        val files = (cases.map { it.base } + cases.map { it.phone }).distinctBy { it.name }
        val run = runTool("keepass2-merge", "keepass2-read.sh", "--merge", files, key) { dir ->
            val manifest = StringBuilder()
            for (c in cases) {
                require(c.name.none { it == '\t' || it == '\n' || it == '/' }) { c.name }
                manifest.append(listOf(c.name, c.base.name, c.base.mode.manifest, c.base.keyFileName ?: "-", c.phone.name, c.phoneAt, c.desktopAt).joinToString("\t")).append('\n')
                File(dir, "${c.name}.phone").writeText(c.phoneOps.joinToString("\n") { it.line } + "\n")
                File(dir, "${c.name}.desktop").writeText(c.desktopOps.joinToString("\n") { it.line } + "\n")
            }
            File(dir, "merge-manifest.tsv").writeText(manifest.toString())
        }
        return cases.associate { c ->
            c.name to MERGES.associateWith { m ->
                val xml = File(run.output, "${c.name}.$m.xml")
                val kdbx = File(run.output, "${c.name}.$m.kdbx")
                if (!xml.isFile || !kdbx.isFile) fail("keepass2-read.sh --merge wrote no $m for ${c.name}; log: ${run.log.path}")
                Merged(KeePassXml.parse(xml.readText()), VaultFile("${c.name}.$m.kdbx", kdbx.readBytes(), c.base.mode, c.base.keyFileName, c.base.keyFile))
            }
        }
    }

    /**
     * Runs KeePass 2's search for each of [queries] over each file, on a copy holding what
     * KashPass searches (`keepass2-read.sh --search`, SearchVault.cs); returns, per file name, the
     * matching entry UUIDs (upper-case hex) per query, failing on a file KeePass 2 refuses.
     */
    internal fun keepass2Search(files: List<VaultFile>, queries: List<String>, key: ByteArray): Map<String, List<Set<String>>> {
        val run = runTool("keepass2-search", "keepass2-read.sh", "--search", files, key) { dir ->
            File(dir, "search-queries.txt").writeText(queries.joinToString("\n") { Base64.getEncoder().encodeToString(it.toByteArray(Charsets.UTF_8)) } + "\n")
        }
        return files.associate { f ->
            val out = File(run.output, f.name + ".search")
            if (!out.isFile) fail("KeePass 2 wrote no search for ${f.name}: ${File(run.output, f.name + ".search.refused").takeIf { it.isFile }?.readText()}; log: ${run.log.path}")
            val byIndex = out.readLines().filter { it.isNotEmpty() }.associate { line ->
                val (i, ids) = line.split('\t', limit = 2)
                i.toInt() to ids.split(',').filter { it.isNotEmpty() }.toSet()
            }
            f.name to queries.indices.map { byIndex[it] ?: fail("${f.name}: no result for query $it") }
        }
    }

    /**
     * KeePass 2's resolution of one field: its HMAC and whether a password reference was resolved.
     */
    data class RefResult(val mac: String, val insertsPassword: Boolean)

    /**
     * Resolves every field of every current entry of each file with KeePass 2's reference rules
     * (`keepass2-read.sh --refs`, SearchVault.cs); returns, per file name, the result per entry
     * UUID (upper-case hex) and field key, failing on a file KeePass 2 refuses.
     */
    internal fun keepass2Refs(files: List<VaultFile>, key: ByteArray): Map<String, Map<Pair<String, String>, RefResult>> {
        val run = runTool("keepass2-refs", "keepass2-read.sh", "--refs", files, key)
        return files.associate { f ->
            val out = File(run.output, f.name + ".refs")
            if (!out.isFile) fail("KeePass 2 wrote no references for ${f.name}: ${File(run.output, f.name + ".refs.refused").takeIf { it.isFile }?.readText()}; log: ${run.log.path}")
            f.name to out.readLines().filter { it.isNotEmpty() }.associate { line ->
                val (uuid, keyB64, mac, p) = line.split('\t')
                (uuid to String(Base64.getDecoder().decode(keyB64), Charsets.UTF_8)) to RefResult(mac, p == "1")
            }
        }
    }

    /** Files per KeePass 2 call, so no call nears the 20-minute timeout. */
    const val BATCH = 40

    /**
     * Runs [keepass2Xml] in calls of [BATCH] files, failing the test on a file KeePass 2 refuses;
     * [timing] receives one line per call.
     */
    internal fun keepass2XmlOpened(files: List<VaultFile>, key: ByteArray, timing: MutableList<String>? = null): Map<String, KeePassXml> {
        val out = LinkedHashMap<String, KeePassXml>()
        for ((i, batch) in files.chunked(BATCH).withIndex()) {
            val t0 = System.nanoTime()
            keepass2Xml(batch, key).forEach { (name, e) -> out[name] = (e as? Export.Opened)?.xml ?: fail("$name: $e") }
            timing?.add("KeePass 2 export ${i + 1}: ${batch.size} files, ${(System.nanoTime() - t0) / 1_000_000_000} s")
        }
        return out
    }

    /**
     * Has KeePass 2 save each file once ([keepass2Resave]) and returns its saves, failing on a
     * refusal.
     */
    fun keepass2ResavedFiles(files: List<VaultFile>): List<VaultFile> = keepass2Resave(files).map { (name, r) ->
        val f = files.single { it.name == name }
        VaultFile(name, r.bytes ?: fail("KeePass 2 refuses $name: ${r.refusal}"), f.mode, f.keyFileName, f.keyFile)
    }

    /** KeePass 2's outcome for one file it saved again: the [bytes] it wrote, or its [refusal]. */
    class Resaved(val bytes: ByteArray?, val refusal: String?)

    /**
     * Has KeePass 2 open every file and save it again as its File, Save does, and returns the
     * outcome per file name.
     */
    fun keepass2Resave(files: List<VaultFile>): Map<String, Resaved> {
        val run = runTool("keepass2-resave", "make-fixtures.sh", "--resave", files, key = null)
        return files.associate { f ->
            val saved = File(run.output, f.name)
            val refused = File(run.output, f.name + ".refused")
            f.name to when {
                saved.isFile -> Resaved(saved.readBytes(), null)
                refused.isFile -> Resaved(null, refused.readText())
                else -> fail("make-fixtures.sh wrote nothing for ${f.name}; log: ${run.log.path}")
            }
        }
    }

    /**
     * Has KeePass 2 [version] write one vault per configuration it has (`keepass2-read.sh --write`,
     * WriteVault.cs) and returns them by configuration, each named kp<version>-<configuration>.kdbx
     * and opened with the fixture password.
     */
    fun keepass2Write(version: String): Map<String, VaultFile> {
        val run = runTool("keepass2-write", "keepass2-read.sh", "--write", emptyList(), newKey(), version)
        val written = File(run.output, "written.tsv").takeIf { it.isFile } ?: fail("keepass2-read.sh --write wrote no written.tsv; log: ${run.log.path}")
        return written.readLines().filter { it.isNotBlank() }.associate { line ->
            val (file, configuration) = line.split('\t')
            configuration to VaultFile("kp$version-$file", File(run.output, file).readBytes())
        }
    }

    /**
     * Writes [files] and the manifest, runs [script] in batch mode, and returns each output by file
     * name. [key] is the report HMAC key, for scripts that hash.
     */
    internal fun batch(tag: String, script: String, suffix: String, files: List<VaultFile>, key: ByteArray?, version: String? = null): Map<String, String> {
        val run = runTool(tag, script, "--batch", files, key, version)
        return files.associate { f ->
            val out = File(run.output, f.name + suffix)
            f.name to (if (out.isFile) out.readText() else fail("$script wrote no report for ${f.name}; log: ${run.log.path}"))
        }
    }

    private class Run(val output: File, val log: File)

    // Writes [files] and the manifest into a fresh input folder, lets [prepare] add the files a
    // mode reads beside the manifest, and runs [script] with [mode], the input folder and the
    // output folder. The one place a KeePass 2 version is chosen: [version], else [namedVersion],
    // else none. The scripts' version variables (KASHPASS_KEEPASS_VERSION, KASHPASS_KEEPASS_TABLE)
    // are never inherited, so with none the scripts' pin applies; a named version gets its own run
    // folder.
    private fun runTool(tag: String, script: String, mode: String, files: List<VaultFile>, key: ByteArray?, version: String? = null, prepare: (File) -> Unit = {}): Run {
        val tool = File(TestFiles.root, "scripts/fixtures/$script")
        if (!tool.canExecute()) fail("KeePass 2 tool missing: ${tool.path} (local tooling, not in git)")
        if (runCatching { ProcessBuilder("docker", "version").redirectErrorStream(true).start().waitFor() }.getOrNull() != 0) {
            fail("KeePass 2 tool missing: docker")
        }
        val selected = version ?: namedVersion
        val dir = File(TestFiles.root, "build/keepass2-runs/" + (selected?.let { "$tag-$it" } ?: tag)).apply { deleteRecursively() }
        val input = File(dir, "in").apply { mkdirs() }
        val output = File(dir, "out").apply { mkdirs() }
        TestFiles.writeManifest(input, files)
        prepare(input)
        val log = File(dir, "run.log")
        val process = ProcessBuilder(tool.path, mode, input.path, output.path)
            .redirectErrorStream(true).redirectOutput(log)
            .apply {
                environment().remove("KASHPASS_KEEPASS_VERSION")
                environment().remove("KASHPASS_KEEPASS_TABLE")
                selected?.let { environment()["KASHPASS_KEEPASS_VERSION"] = it }
                environment()["KASHPASS_VAULT_PASSWORD"] = TestFiles.password
                key?.let { environment()["KASHPASS_REPORT_KEY"] = it.toHex() }
            }
            .start()
        if (!process.waitFor(20, TimeUnit.MINUTES)) {
            // SIGTERM first: the docker client forwards it to the container and the script's trap
            // removes its 0600 secret files; a kill would leave both behind.
            process.descendants().forEach { it.destroy() }
            process.destroy()
            if (!process.waitFor(30, TimeUnit.SECONDS)) process.destroyForcibly()
            fail("$script timed out; log: ${log.path}")
        }
        if (process.exitValue() != 0) fail("$script exited ${process.exitValue()}: ${log.readText().takeLast(2000)}")
        return Run(output, log)
    }
}
