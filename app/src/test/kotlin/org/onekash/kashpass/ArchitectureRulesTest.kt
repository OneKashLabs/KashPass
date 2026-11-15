package org.onekash.kashpass

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.onekash.kashpass.vault.testing.KotlinSourceText

/**
 * Checks the layering and the forbidden APIs in the main sources of both modules, so breaking a
 * rule fails this test. The layering and the Android rule read every name a file
 * uses, by import or written out in code, with comments and string contents blanked
 * ([KotlinSourceText]); a file the reader cannot follow to the end fails, and each file's package
 * is its directory.
 *
 * Layers, from the top: the app root package (Application, Activity, receivers, the object graph)
 * uses anything; `ui.*` uses `session`, `platform`, vault-core (never `vault.xml`) and the
 * shared `ui.theme`, `ui.format`, `ui.input` and `ui.components`, but never the root; `lock`
 * uses `session`; `session` and `platform` use only vault-core. Inside vault-core: `open` over
 * `header`, `policy`, `storage`, `index`, `doc` and `backup`; `save` over `header`, `policy`,
 * `storage`, `doc` and `backup`; `index` and `edit` over `doc` (`edit` also `xml`); `doc` over
 * `xml`; `xml`, `backup`, `generate` and the container `kdbx` (JDK only) stand alone, and only
 * `doc` may use `kdbx`. The exact table is [allowed]. No package reaches itself
 * through its uses. The container package has its own forbidden tokens ([containerForbidden]).
 *
 * A forbidden token is allowed on a line only when the line before it says `// allowed: <reason>`.
 * Every bottom sheet is its own window, so each `ModalBottomSheet(` call sets
 * `SecureFlagPolicy.SecureOn`. Only `OpenLink.kt` sends `ACTION_VIEW`, so every link goes
 * through its http and https check.
 */
class ArchitectureRulesTest {

    private val parsed get() = PARSED
    private val known get() = KNOWN

    private fun short(pkg: String) = pkg.removePrefix(APP).removePrefix(".").ifEmpty { "<root>" }

    // Package -> packages of this project it uses (other than itself).
    private val graph: Map<String, Set<String>> by lazy { parsed.filter { it.scannable }.groupBy { short(it.pkg) }
        .mapValues { (_, files) -> files.flatMap { src -> uses(src.pkg, src.text, known).map { it.second.substringAfter(" -> ") } }.toSet() } }

    @Test
    fun `the sources are found`() {
        assertTrue("no sources under $ROOT", parsed.size > 20)
        assertTrue(graph.keys.containsAll(listOf("<root>", "ui.lock", "ui.browse", "platform", "session", "lock", "vault.open")))
    }

    private val allowed: Map<String, (String) -> Boolean> = mapOf(
        // vault.xml stays inside vault-core: nothing in the app sees XML nodes.
        "ui." to { t -> t == "session" || t == "platform" || (t.startsWith("vault.") && t != "vault.xml") || t in setOf("ui.theme", "ui.format", "ui.input", "ui.components") },
        "lock" to { t -> t == "session" },
        "session" to { t -> t.startsWith("vault.") && t != "vault.xml" },
        "platform" to { t -> t.startsWith("vault.") && t != "vault.xml" },
        "vault.open" to { t -> t in setOf("vault.header", "vault.policy", "vault.storage", "vault.index", "vault.doc", "vault.backup") },
        "vault.index" to { t -> t == "vault.doc" },
        "vault.policy" to { t -> t == "vault.header" },
        "vault.storage" to { t -> t == "vault.header" },
        "vault.header" to { _ -> false },
        "vault.xml" to { _ -> false },
        "vault.generate" to { _ -> false },
        "vault.edit" to { t -> t == "vault.doc" || t == "vault.xml" },
        "vault.backup" to { _ -> false },
        "vault.save" to { t -> t in setOf("vault.header", "vault.policy", "vault.storage", "vault.doc", "vault.backup") },
        "vault.doc" to { t -> t in setOf("vault.xml", "vault.header", "vault.policy", "vault.kdbx") },
        // The container uses only the JDK.
        "vault.kdbx" to { _ -> false },
    )

    // Returns "package -> target" for each edge of [uses] that its layer's rule forbids.
    private fun layeringViolations(uses: Map<String, Set<String>>): List<String> = uses.flatMap { (pkg, targets) ->
        targets.filterNot { allows(pkg, it) }.map { "$pkg -> $it" }
    }.sorted()

    private fun allows(pkg: String, target: String): Boolean {
        val rule = allowed.entries.firstOrNull { pkg == it.key || (it.key.endsWith(".") && pkg.startsWith(it.key)) }
        return pkg == "<root>" || rule == null || rule.value(target)
    }

    // (line, "package -> target") for each project package the file [text] in package [pkg]
    // uses, by import or by a name written out in code; [known] are the packages that exist.
    private fun uses(pkg: String, text: String, known: Set<String>): List<Pair<Int, String>> =
        KotlinSourceText.references(text, PROJECT_NAME).mapNotNull { (line, name) ->
            val target = targetPackage(name, known)
            if (target == null || target == pkg) null else line to target
        }.map { (line, target) -> line to "${short(pkg)} -> ${short(target)}" }

    // The longest package in [known] that [name] equals or continues with '.', or null for the
    // generated R and BuildConfig classes.
    private fun targetPackage(name: String, known: Set<String>): String? {
        val ref = name.removeSuffix(".*")
        val generated = listOf("$APP.R", "$APP.BuildConfig").any { ref == it || ref.startsWith("$it.") }
        return if (generated) null else known.filter { ref == it || ref.startsWith("$it.") }.maxByOrNull { it.length }
    }

    // "File.kt:line package -> target" for each use in the sources that [isViolation] flags.
    private fun hits(isViolation: (String, String) -> Boolean): List<String> = parsed.filter { it.scannable }.flatMap { src ->
        uses(src.pkg, src.text, known).filter { (_, edge) -> edge.split(" -> ").let { isViolation(it[0], it[1]) } }
            .map { (line, edge) -> "${src.file.name}:$line $edge" }
    }

    private val plantedKnown = setOf(APP, "$APP.ui.lock", "$APP.vault.xml", "$APP.vault.kdbx", "$APP.vault.open", "$APP.vault.doc")

    private fun plantedEdges(pkg: String, text: String) = layeringViolations(mapOf(short(pkg) to uses(pkg, text, plantedKnown).map { it.second.substringAfter(" -> ") }.toSet()))

    @Test
    fun `the layering check finds a container use of another package`() {
        assertEquals(listOf("vault.kdbx -> vault.header"), layeringViolations(mapOf("vault.kdbx" to setOf("vault.header"))))
    }

    @Test
    fun `the layering check sees names written out in code and ignores comments and strings`() {
        val ui = "$APP.ui.lock"
        assertEquals(listOf("ui.lock -> vault.xml"), plantedEdges(ui, "package $ui\nval x: org.onekash.kashpass.vault.xml.XmlElement? = null"))
        assertEquals(listOf("ui.lock -> vault.xml"), plantedEdges(ui, "package $ui\nimport org.onekash.kashpass.vault.xml.*"))
        assertEquals(listOf("ui.lock -> vault.xml"), plantedEdges(ui, "package $ui\nimport a.B; import org.onekash.kashpass.vault.xml.X"))
        assertEquals(listOf("ui.lock -> vault.xml"), plantedEdges(ui, "package $ui\nval x = org.onekash.kashpass\n    .vault.xml.parse()"))
        assertEquals(listOf("ui.lock -> vault.xml"), plantedEdges(ui, "package $ui\nval x = org.onekash.`kashpass`.vault.xml.X"))
        assertEquals(listOf("ui.lock -> <root>"), plantedEdges(ui, "package $ui\nval a: org.onekash.kashpass.MainActivity? = null"))
        // Only R and BuildConfig themselves are generated; a root class whose name starts the same
        // is not.
        assertEquals(listOf("ui.lock -> <root>"), plantedEdges(ui, "package $ui\nval r: org.onekash.kashpass.Receivers? = null"))
        assertEquals(emptyList<String>(), plantedEdges(ui, "package $ui\nimport org.onekash.kashpass.R\nval s = org.onekash.kashpass.R.string.app_name"))
        assertEquals(emptyList<String>(), plantedEdges(ui, "package $ui\nval d = org.onekash.kashpass.BuildConfig.DEBUG"))
        val commented = "package $ui\n// org.onekash.kashpass.vault.xml.X\n/** [org.onekash.kashpass.vault.xml.X] */\nval s = \"org.onekash.kashpass.vault.xml.X\""
        assertEquals(emptyList<String>(), plantedEdges(ui, commented))
        // Whole segments: with no vault.docs package, vault.docs.D falls back to the root, never
        // vault.doc.
        assertEquals(listOf("vault.open -> <root>"), uses("$APP.vault.open", "val d = org.onekash.kashpass.vault.docs.D", plantedKnown).map { it.second })
    }

    @Test
    fun `each layer uses only the layers below it`() {
        assertEquals("uses against the layering", emptyList<String>(), hits { pkg, target -> !allows(pkg, target) })
        assertTrue("every package has a rule", graph.keys.all { it == "<root>" || allowed.keys.any { k -> it == k || (k.endsWith(".") && it.startsWith(k)) } })
    }

    // Returns every path by which a package of [uses] reaches itself.
    private fun cycles(uses: Map<String, Set<String>>): List<String> {
        val found = mutableListOf<String>()
        fun visit(start: String, at: String, path: List<String>) {
            for (next in uses[at].orEmpty()) {
                if (next == start) found += (path + next).joinToString(" -> ")
                else if (next !in path && path.size < uses.size) visit(start, next, path + next)
            }
        }
        for (pkg in uses.keys) visit(pkg, pkg, listOf(pkg))
        return found.sorted()
    }

    @Test
    fun `the cycle check finds a package that reaches itself`() {
        assertEquals(listOf("vault.a -> vault.b -> vault.a", "vault.b -> vault.a -> vault.b"), cycles(mapOf("vault.a" to setOf("vault.b"), "vault.b" to setOf("vault.a"))))
        assertTrue("the graph holds package names", graph.getValue("vault.open").contains("vault.doc"))
    }

    @Test
    fun `no package reaches itself through its uses`() {
        assertEquals("package cycles", emptyList<String>(), cycles(graph))
    }

    // (line, name) of each Android name the vault-core file [text] uses. The libraries both
    // modules may use at all are DependencyRuleTest's (vault-core tests).
    private fun foreign(text: String): List<Pair<Int, String>> = KotlinSourceText.references(text, ANDROID_NAME)

    @Test
    fun `the Android check sees names written out in code`() {
        assertEquals(listOf(2 to "android.util.Log"), foreign("package x\nval l = android.util.Log::class"))
        assertEquals(listOf(1 to "androidx.core.Foo"), foreign("import androidx.core.Foo"))
        assertEquals(emptyList<Pair<Int, String>>(), foreign("// android.util.Log\nval s = \"android.util.Log\""))
        assertEquals(emptyList<Pair<Int, String>>(), foreign("/* androidx.core.Foo */ val s = \"androidx.core\""))
    }

    @Test
    fun `vault-core uses no Android`() {
        val bad = parsed.filter { it.scannable && it.pkg.startsWith(CORE) }.flatMap { src ->
            foreign(src.text).map { (line, name) -> "${src.file.name}:$line $name" }
        }
        assertEquals(emptyList<String>(), bad)
    }

    @Test
    fun `the scan check names each file it cannot read to the end`() {
        val planted = mapOf("a/Ok.kt" to "package a\nval s = \"x\"", "a/Open.kt" to "package a\nval s = \"unterminated", "a/Comment.kt" to "package a\n/* unterminated")
        assertEquals(listOf("a/Comment.kt", "a/Open.kt"), unscannable(planted))
    }

    @Test
    fun `every main source file can be scanned`() {
        assertEquals(emptyList<String>(), unscannable(parsed.associate { it.relativePath to it.text }))
    }

    @Test
    fun `the package check finds a package that is not its directory`() {
        assertEquals("org.onekash.kashpass.vault.doc", packageOf(KotlinSourceText.codeLines("/* x */\npackage org.onekash.kashpass.vault.doc\n")))
        assertEquals("", packageOf(KotlinSourceText.codeLines("val a = 1")))
        assertTrue(packageMatchesPath("org.onekash.kashpass.vault.doc", "org/onekash/kashpass/vault/doc/A.kt"))
        assertFalse(packageMatchesPath("org.onekash.kashpass.vault.doc", "org/onekash/kashpass/vault/xml/A.kt"))
        assertFalse(packageMatchesPath("org.onekash.kashpass.vault", "org/onekash/kashpass/vault/doc/A.kt"))
    }

    @Test
    fun `each file's package is its directory`() {
        assertEquals(emptyList<String>(), parsed.filterNot { packageMatchesPath(it.pkg, it.relativePath) }.map { "${it.relativePath}: ${it.pkg}" })
    }

    @Test
    fun `forbidden APIs appear only with a stated reason`() {
        val forbidden = mapOf(
            "validateHashes = false" to "decode must verify the block HMACs",
            "android.util.Log" to "no logging: entries, URIs and titles must never reach logcat",
            "println(" to "no logging",
            "printStackTrace" to "no logging",
            "java.net." to "no network access",
            "HttpURLConnection" to "no network access",
            "okhttp" to "no network access",
            "Socket(" to "no network access",
            "GlobalScope" to "coroutines run in a scope that a lock or the app owns",
            "runBlocking" to "no blocking the main thread",
            "openOutputStream(" to "a write must pass mode \"wt\" (\"w\" is not guaranteed to truncate)",
            "rememberSaveable" to "saved state can reach disk; it must never hold vault content",
        )
        val hits = parsed.flatMap { src ->
            src.lines.withIndex().flatMap { (i, line) ->
                val code = line.substringBefore("//")
                val reason = src.lines.getOrNull(i - 1)?.trim()?.startsWith("// allowed:") == true
                forbidden.filterKeys { code.contains(it) && !reason }.map { (token, why) -> "${src.file.name}:${i + 1} $token ($why)" }
            }
        }
        assertEquals(emptyList<String>(), hits)
    }

    // Packages other than the codec's (vault.doc) that use the container in [uses].
    private fun containerUsers(uses: Map<String, Set<String>>) =
        uses.filterValues { "vault.kdbx" in it }.keys.filter { it != "vault.doc" }.sorted()

    @Test
    fun `the container user check finds a package other than the codec`() {
        assertEquals(listOf("vault.open"), containerUsers(mapOf("vault.doc" to setOf("vault.kdbx"), "vault.open" to setOf("vault.kdbx", "vault.doc"))))
        val open = "$APP.vault.open"
        val written = uses(open, "package $open\nval c = org.onekash.kashpass.vault.kdbx.ChaCha20::class", plantedKnown).map { it.second.substringAfter(" -> ") }.toSet()
        assertEquals(listOf("vault.open"), containerUsers(mapOf("vault.open" to written)))
    }

    @Test
    fun `only vault doc uses the container package`() {
        assertEquals(emptyList<String>(), hits { pkg, target -> target == "vault.kdbx" && pkg != "vault.doc" })
    }

    private val containerForbidden = listOf(
        Regex("""(?<![\w.])String\(""") to "no String from key or plaintext bytes",
        Regex("""\btoString\(""") to "no String from key or plaintext bytes",
        Regex("""\bcontentEquals\b""") to "compare with Bytes.constantTimeEquals",
        Regex("""Arrays\.equals\(""") to "compare with Bytes.constantTimeEquals",
        Regex("""Class\.forName\(""") to "no reflection",
        Regex("""\.reflect\.""") to "no reflection",
        Regex("""::class\.java""") to "no reflection",
        Regex("""Charsets""") to "no text decoding of key or plaintext bytes",
        Regex("""System\.(out|err)""") to "no logging",
        Regex("""printStackTrace""") to "no logging",
        Regex("""\b(validate|verify|check|skip|ignore)\w*\s*:\s*Boolean""", RegexOption.IGNORE_CASE) to "no option to skip a hash or HMAC check",
        Regex("""\b\w*(Hash|Hmac|Mac)\w*\s*:\s*Boolean""") to "no option to skip a hash or HMAC check",
    )

    // Returns "line: reason" for each forbidden token on a code line of [lines]; comment and KDoc
    // lines are skipped, and a line after `// allowed: <reason>` is allowed.
    private fun containerHits(lines: List<String>): List<String> = lines.withIndex().flatMap { (i, line) ->
        val trimmed = line.trim()
        val comment = trimmed.startsWith("*") || trimmed.startsWith("/*") || trimmed.startsWith("//")
        val reason = lines.getOrNull(i - 1)?.trim()?.startsWith("// allowed:") == true
        if (comment || reason) emptyList() else containerForbidden.filter { it.first.containsMatchIn(line.substringBefore("//")) }.map { "${i + 1}: ${it.second}" }
    }

    @Test
    fun `the container check finds each forbidden token and skips comments`() {
        assertEquals(listOf("1: compare with Bytes.constantTimeEquals"), containerHits(listOf("val same = a contentEquals b")))
        assertEquals(listOf("1: no String from key or plaintext bytes"), containerHits(listOf("    override fun toString() = \"x\"")))
        assertEquals(listOf("1: no String from key or plaintext bytes"), containerHits(listOf("val s = String(bytes)")))
        assertEquals(listOf("1: no reflection"), containerHits(listOf("val c = Class.forName(name)")))
        assertEquals(emptyList<String>(), containerHits(listOf(" * Never String(bytes) or a.contentEquals(b).", "// String(x)")))
        assertEquals(emptyList<String>(), containerHits(listOf("// allowed: test", "val s = String(bytes)")))
        assertEquals(emptyList<String>(), containerHits(listOf("class Text(val value: ByteArray)", "val n = name.encodeToByteArray()")))
        val planted = listOf(
            "val same = java.util.Arrays.equals(a, b)", "import kotlin.reflect.KClass", "val c = Foo::class.java",
            "val s = bytes.toString(Charsets.UTF_8)", "System.out.write(1)", "e.printStackTrace()",
            "fun decode(bytes: ByteArray, validateHashes: Boolean)", "fun read(verify: Boolean = true)", "skipMacs : Boolean",
            "fun decode(checkHeaderHmac: Boolean)", "class D(val headerHash: Boolean)",
        )
        assertEquals(emptyList<String>(), containerHits(listOf("class Attachment(val protected: Boolean)", "val bytesAfterEnd: Boolean")))
        for (line in planted) assertTrue(line, containerHits(listOf(line)).isNotEmpty())
    }

    @Test
    fun `the container package uses no forbidden token`() {
        val container = parsed.filter { it.pkg == "$CORE.kdbx" }
        assertTrue("no container sources found", container.isNotEmpty())
        val hits = container.flatMap { src -> containerHits(src.lines).map { "${src.file.name}:$it" } }
        assertEquals(emptyList<String>(), hits)
    }

    // Building a VIEW intent sends one; MainActivity reading an incoming one doesn't count.
    @Test
    fun `links open only through openWebLink`() {
        val sends = Regex("""Intent\((Intent\.)?ACTION_VIEW|setAction\((Intent\.)?ACTION_VIEW|action = (Intent\.)?ACTION_VIEW""")
        val viewers = parsed.filter { src -> src.lines.any { sends.containsMatchIn(it.substringBefore("//")) } }.map { it.file.name }
        assertEquals(listOf("OpenLink.kt"), viewers)
    }

    // Returns the 1-based lines of `ModalBottomSheet(` calls in [text], plain or qualified, whose
    // arguments don't set SecureFlagPolicy.SecureOn. The arguments run to the parenthesis that
    // closes the call; parentheses inside string literals don't count.
    private fun unsecuredSheets(text: String): List<Int> =
        Regex("""(?<![\w])ModalBottomSheet\(""").findAll(text).mapNotNull { match ->
            var depth = 0
            var quoted = false
            var end = match.range.last
            while (end < text.length) {
                val c = text[end]
                when {
                    c == '"' && text[end - 1] != '\\' -> quoted = !quoted
                    quoted -> Unit
                    c == '(' -> depth++
                    c == ')' -> if (--depth == 0) break
                }
                end++
            }
            val args = text.substring(match.range.last, end)
            if (args.contains("SecureFlagPolicy.SecureOn")) null else text.substring(0, match.range.first).count { it == '\n' } + 1
        }.toList()

    @Test
    fun `the sheet check finds a sheet without the secure policy`() {
        val secure = "ModalBottomSheet(\n    onDismissRequest = {},\n    properties = ModalBottomSheetProperties(securePolicy = SecureFlagPolicy.SecureOn),\n) { Text(\"x\") }"
        val plain = "import androidx.compose.material3.ModalBottomSheet\nModalBottomSheet(onDismissRequest = { close() }) { Text(\"x\") }"
        val qualified = "androidx.compose.material3.ModalBottomSheet(onDismissRequest = {}) { Text(\"x\") }"
        val quotedParen = "ModalBottomSheet(onDismissRequest = { log(\"(\") }) { }\nOther(policy = SecureFlagPolicy.SecureOn)"
        assertEquals(emptyList<Int>(), unsecuredSheets(secure))
        assertEquals(listOf(2), unsecuredSheets(plain))
        assertEquals(listOf(1), unsecuredSheets(qualified))
        assertEquals(listOf(1), unsecuredSheets(quotedParen))
    }

    @Test
    fun `every bottom sheet window blocks screenshots`() {
        val hits = parsed.flatMap { src -> unsecuredSheets(src.lines.joinToString("\n")).map { "${src.file.name}:$it" } }
        assertEquals(emptyList<String>(), hits)
    }

    private companion object {
        const val APP = "org.onekash.kashpass"
        const val CORE = "org.onekash.kashpass.vault"

        val PROJECT_NAME = KotlinSourceText.qualifiedName(APP)
        val ANDROID_NAME = KotlinSourceText.qualifiedName("android", "androidx", requireMore = true)

        val ROOT: File = File("..").canonicalFile

        /** One main source file, read once for every test in the class. */
        class Source(val file: File, val relativePath: String, val pkg: String, val lines: List<String>, val text: String, val scannable: Boolean)

        val PARSED: List<Source> by lazy {
            listOf("app/src/main/kotlin", "vault-core/src/main/kotlin").map { File(ROOT, it) }.flatMap { dir ->
                dir.walk().filter { it.extension == "kt" }.map { file ->
                    val text = file.readText()
                    val scan = KotlinSourceText.scan(text)
                    Source(file, file.relativeTo(dir).invariantSeparatorsPath, packageOf(scan.lines), text.lines(), text, scan.endsInCode)
                }.toList()
            }
        }

        /** Packages declared in the main sources, by full name. */
        val KNOWN: Set<String> by lazy { PARSED.map { it.pkg }.toSet() }

        /**
         * Returns the paths in [files] (path to text) the reader cannot follow to the end,
         * sorted.
         */
        fun unscannable(files: Map<String, String>): List<String> =
            files.filterValues { !KotlinSourceText.scan(it).endsInCode }.keys.sorted()

        /**
         * Returns the name on the `package` line of a file's blanked [lines], empty without
         * one.
         */
        fun packageOf(lines: List<String>): String =
            lines.firstOrNull { it.trim().startsWith("package ") }?.trim()?.removePrefix("package ")?.trim().orEmpty()

        /** Returns true when [pkg] is the directory of [relativePath] below the source root. */
        fun packageMatchesPath(pkg: String, relativePath: String): Boolean =
            relativePath.substringBeforeLast('/', "").replace('/', '.') == pkg
    }
}
