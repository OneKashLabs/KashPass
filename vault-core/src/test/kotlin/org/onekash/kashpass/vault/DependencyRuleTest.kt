package org.onekash.kashpass.vault

import java.io.File
import java.lang.reflect.Modifier
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.OpenedVault
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.open.VaultSession
import org.onekash.kashpass.vault.testing.KotlinSourceText

/**
 * The libraries the code uses are the ones these lists name. Each import in the main and test
 * sources of both modules starts with an allowed root ([ROOTS]), and every entry on vault-core's
 * test runtime classpath is a project output (under the repository) or a Gradle-cached jar from an
 * allowed Maven group ([GROUPS]), so a library added to vault-core's tests, directly or
 * transitively, fails here until it is reviewed and its checksum pinned in verification-metadata.
 * The app's classpaths are checked by the import rule and preflight's release APK check, not
 * here; a name written out in code without an import is not seen. The public API of the vault
 * types the app sees names only project, JDK, Kotlin and coroutine types. No decode entry can skip
 * a hash or HMAC check: [DecoderChecksRuleTest].
 */
class DependencyRuleTest {

    private val sourceSets = listOf(
        "vault-core/src/main/kotlin", "vault-core/src/test/kotlin", "vault-core/src/testFixtures/kotlin",
        "app/src/main/kotlin", "app/src/test/kotlin",
    )

    // "path:line import" for each import of [files] (path to text) outside [ROOTS].
    private fun foreignImports(files: Map<String, String>): List<String> = files.flatMap { (path, text) ->
        KotlinSourceText.codeLines(text).mapIndexedNotNull { i, line ->
            val name = Regex("""^\s*import\s+([\w.`]+)""").find(line)?.groupValues?.get(1)?.replace("`", "") ?: return@mapIndexedNotNull null
            // A wildcard import of Kotest would reach the generators FORBIDDEN_IMPORTS names.
            val wildcard = name.endsWith(".") && name.startsWith("io.kotest.")
            val allowed = ROOTS.any { name == it || name.startsWith("$it.") } && name !in FORBIDDEN_IMPORTS && !wildcard
            if (allowed) null else "$path:${i + 1} $name"
        }
    }.sorted()

    // Each entry of [classpath] that is neither under [projectRoot] (build directories, the
    // test-fixtures jar) nor a Gradle-cached jar (files-2.1/<group>/...) of a group in [GROUPS].
    private fun foreignGroups(classpath: String, projectRoot: String): List<String> = classpath.split(File.pathSeparator).filter { it.isNotEmpty() }.mapNotNull { entry ->
        val path = entry.replace('\\', '/')
        val parts = path.split('/')
        val at = parts.indexOf("files-2.1")
        when {
            path.startsWith("$projectRoot/") -> null
            at < 0 || at + 1 >= parts.size -> "not a cached artifact ($entry)"
            parts[at + 1] !in GROUPS -> "${parts[at + 1]} ($entry)"
            else -> null
        }
    }.distinct().sorted()

    @Test
    fun `an import outside the allowed roots is reported with its path and line, a comment or string is not`() {
        val planted = mapOf(
            "a/Planted.kt" to "package x\n\nimport kotlin.io.path.Path\nimport com.example.vault.Reader\n// import com.example.Other\nval s = \"import com.example.Third\"",
            "b/Fine.kt" to "package y\nimport java.util.UUID\nimport org.onekash.kashpass.vault.doc.VaultKey",
        )
        assertEquals(listOf("a/Planted.kt:4 com.example.vault.Reader"), foreignImports(planted))
    }

    @Test
    fun `Kotest is allowed only for property testing, without the generators that need its excluded libraries`() {
        val planted = mapOf(
            "a/Props.kt" to "package x\nimport io.kotest.property.checkAll\nimport io.kotest.property.arbitrary.int\n" +
                "import io.kotest.property.arbitrary.stringPattern\nimport io.kotest.matchers.shouldBe\n" +
                "import io.kotest.property.arbitrary.pattern\nimport io.kotest.property.arbitrary.*\nimport io.kotest.common.ExperimentalKotest",
        )
        assertEquals(
            listOf(
                "a/Props.kt:4 io.kotest.property.arbitrary.stringPattern", "a/Props.kt:5 io.kotest.matchers.shouldBe",
                "a/Props.kt:6 io.kotest.property.arbitrary.pattern", "a/Props.kt:7 io.kotest.property.arbitrary.",
            ),
            foreignImports(planted),
        )
    }

    @Test
    fun `every import in both modules' main and test sources starts with an allowed root`() {
        val files = sourceSets.flatMap { set ->
            val dir = File(TestFiles.root, set)
            assertTrue(dir.isDirectory, "missing ${dir.path}")
            dir.walk().filter { it.isFile && it.extension == "kt" }.map { it.relativeTo(TestFiles.root).invariantSeparatorsPath to it.readText() }.toList()
        }.toMap()
        assertTrue(files.size > 300, "${files.size} sources")
        assertEquals(emptyList(), foreignImports(files))
    }

    @Test
    fun `a jar from another group or outside Gradle's cache is reported and a project output is not`() {
        val classpath = listOf(
            "/home/u/.gradle/caches/modules-2/files-2.1/org.junit.jupiter/junit-jupiter-api/5.0/abc/junit-jupiter-api-5.0.jar",
            "/home/u/.gradle/caches/modules-2/files-2.1/com.example/library/1.0/def/library-1.0.jar",
            "/home/u/.m2/repository/com/example/other/1.0/other-1.0.jar",
            "/repo/vault-core/build/classes/kotlin/test",
            "/repo/vault-core/build/libs/vault-core-test-fixtures.jar",
        ).joinToString(File.pathSeparator)
        val found = foreignGroups(classpath, "/repo")
        assertEquals(2, found.size, found.toString())
        assertTrue(found.any { it.startsWith("com.example (") })
        assertTrue(found.any { it.startsWith("not a cached artifact (/home/u/.m2/") })
    }

    @Test
    fun `every jar on the test runtime classpath comes from an allowed group`() {
        val classpath = System.getProperty("kashpass.test.classpath") ?: System.getProperty("java.class.path")
        assertTrue(classpath.contains("files-2.1"), "no cached jars on the classpath")
        assertEquals(emptyList(), foreignGroups(classpath, TestFiles.root.canonicalPath.replace('\\', '/')))
    }

    // The public methods of [types] whose parameter or return type comes from outside the
    // project, the JDK, Kotlin and coroutines, as "Type.method: class". Kotlin internal members
    // compile to public JVM methods with a '$'-mangled name, and internal constructors to public
    // ones; neither is reachable from Kotlin outside vault-core, so both are skipped.
    private fun foreignApiTypes(types: List<Class<*>>): List<String> = types.flatMap { type ->
        type.methods.filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic && '$' !in it.name }
            .flatMap { method -> (method.parameterTypes.toList() + method.returnType).map { type.simpleName + "." + method.name to it } }
    }.filterNot { (_, c) -> apiRoot(c) }.map { (where, c) -> "$where: ${c.name}" }.sorted()

    private fun apiRoot(c: Class<*>): Boolean {
        val element = generateSequence(c) { it.componentType }.last()
        return element.isPrimitive || API_ROOTS.any { element.name.startsWith("$it.") }
    }

    /** A public type naming a test library's class, so the API rule has something to report. */
    class PlantedApi {
        fun failure(): org.opentest4j.AssertionFailedError? = null
    }

    @Test
    fun `a public method naming a type outside the allowed roots is reported`() {
        assertEquals(listOf("PlantedApi.failure: org.opentest4j.AssertionFailedError"), foreignApiTypes(listOf(PlantedApi::class.java)))
    }

    @Test
    fun `the public API of the vault types names only project, JDK, Kotlin and coroutine types`() {
        val types = listOf(OpenedVault::class.java, VaultDocument::class.java, VaultSession::class.java, OpenedVault.Baseline::class.java)
        assertEquals(emptyList(), foreignApiTypes(types))
    }

    private companion object {
        /** Package roots the sources may import: project, platform, Kotlin, test libraries. */
        val ROOTS = listOf(
            "org.onekash.kashpass", "android", "androidx", "java", "javax", "org.w3c.dom", "kotlin", "kotlinx.coroutines",
            "org.junit", "org.robolectric", "com.code_intelligence.jazzer",
            // Roborazzi, the app tests' screen capture under Robolectric.
            "com.github.takahirom.roborazzi",
            // Kotest's property module, and the marker its run settings need: its matchers need
            // java-diff-utils, which the build excludes (vault-core/build.gradle.kts).
            "io.kotest.property", "io.kotest.common.ExperimentalKotest",
        )

        /** Imports under [ROOTS] that need a library the build excludes (rgxgen). */
        val FORBIDDEN_IMPORTS = setOf("io.kotest.property.arbitrary.stringPattern", "io.kotest.property.arbitrary.pattern")

        /** Package roots a vault type's public API may name. */
        val API_ROOTS = listOf("org.onekash.kashpass", "java", "kotlin", "kotlinx.coroutines")

        /** Maven groups of vault-core's test runtime classpath. */
        val GROUPS = setOf(
            "org.jetbrains", "org.jetbrains.kotlin", "org.jetbrains.kotlinx", "org.junit", "org.junit.jupiter",
            "org.junit.platform", "org.opentest4j", "org.apiguardian", "com.code-intelligence", "io.kotest",
        )
    }
}
