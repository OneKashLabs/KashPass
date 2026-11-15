import java.util.Properties

plugins {
    kotlin("jvm")
    `java-test-fixtures`
}

dependencies {
    implementation(libs.kotlinx.coroutines.core)

    testFixturesImplementation(libs.kotlinx.coroutines.core)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jazzer.junit)
    testImplementation(kotlin("test"))
    testImplementation(libs.kotlinx.coroutines.test)
    // Property tests (checkAll, generators, shrinking). The excluded modules are not needed by
    // checkAll and would add a bytecode agent with native access (kotlinx-coroutines-debug pulls
    // byte-buddy and jna), classpath scanning (classgraph), an XML serialization stack (xmlutil),
    // regex-driven generators (rgxgen, for Arb.stringPattern) and assertion diffs
    // (java-diff-utils, for Kotest's matchers); DependencyRuleTest allows only io.kotest.property
    // imports and rejects Arb.stringPattern. Declared once, on the test fixtures' API (PropertyRuns
    // and Generators use it), so vault-core's tests and the app's tests get it, with these
    // exclusions, by one path.
    testFixturesApi(libs.kotest.property) {
        exclude(group = "org.jetbrains.kotlinx", module = "kotlinx-coroutines-debug")
        exclude(group = "io.github.pdvrieze.xmlutil")
        exclude(group = "io.github.classgraph")
        exclude(group = "com.github.curious-odd-man")
        exclude(group = "community.flock.kotlinx.rgxgen")
        exclude(group = "io.github.java-diff-utils")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    // Shared fakes build the save package's internal types (PreparedSave) the way the real saver
    // does.
    target.compilations.getByName("testFixtures").associateWith(target.compilations.getByName("main"))
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

// Throwaway password of the KeePass 2 test vaults; see TestFiles.password.
val fixturePassword: String? = rootProject.file("local.properties")
    .takeIf { it.exists() }
    ?.let { file -> Properties().apply { file.inputStream().use { load(it) } } }
    ?.getProperty("KASHPASS_FIXTURE_PASSWORD")

// Every -Pkashpass.* flag the builds read. Gradle ignores an unknown -P property, so a misspelled
// or renamed flag would skip the tests it names and the build would pass; it fails here instead.
val kashpassFlags = setOf(
    "keepass2", "keepass", "matrix", "fixturesDir", "windowsKit", "windowsReturn", "interop.out",
    "fuzz", "fuzzSeeds", "propertySeed", "propertyIterations", "memory",
)
providers.gradlePropertiesPrefixedBy("kashpass.").get().keys.map { it.removePrefix("kashpass.") }
    .filterNot { it in kashpassFlags }.sorted().takeIf { it.isNotEmpty() }?.let { unknown ->
        throw GradleException("unknown flag: " + unknown.joinToString { "-Pkashpass.$it" } + "; known: " + kashpassFlags.sorted().joinToString())
    }
// The gate takes no version: -Pkashpass.keepass2=<v> would run the pin and look like a run on <v>.
providers.gradleProperty("kashpass.keepass2").orNull?.takeIf { it !in setOf("", "true", "false") }?.let {
    throw GradleException("-Pkashpass.keepass2 takes true or false; choose a KeePass 2 version with -Pkashpass.keepass=$it")
}
// -Pkashpass.keepass only picks the version the gated tests run on. Alone, or as a typo for
// -Pkashpass.keepass2, it would run none of them and the build would pass.
providers.gradleProperty("kashpass.keepass").orNull?.let { version ->
    val on = { name: String -> providers.gradleProperty(name).orNull.let { it != null && it != "false" } }
    if (!on("kashpass.keepass2") && !on("kashpass.matrix")) {
        throw GradleException("-Pkashpass.keepass=<v> picks the version for -Pkashpass.keepass2 or -Pkashpass.matrix; add one")
    }
    if (version.isNotEmpty() && !Regex("""\d+\.\d+(\.\d+)?""").matches(version)) {
        throw GradleException("-Pkashpass.keepass takes a KeePass 2 version such as 2.44, not '$version'")
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
    fixturePassword?.let { systemProperty("kashpass.fixture.password", it) }
    // -Pkashpass.interop.out=<dir> makes KeePass2InteropTest write the vaults it saved there.
    providers.gradleProperty("kashpass.interop.out").orNull?.let {
        systemProperty("kashpass.interop.out", it)
        outputs.upToDateWhen { false }
    }
    // MemoryRun measures open and save in a child JVM with the test classpath, and
    // DependencyRuleTest checks the libraries on it.
    val testClasspath = sourceSets["test"].runtimeClasspath
    doFirst { systemProperty("kashpass.test.classpath", testClasspath.asPath) }
    // -Pkashpass.keepass2 runs the gated tests that open test vaults with KeePass 2 in Docker
    // (KeePass2Run); without it they are skipped.
    // -Pkashpass.keepass2=false leaves them off.
    if (providers.gradleProperty("kashpass.keepass2").orNull.let { it != null && it != "false" }) {
        systemProperty("kashpass.keepass2", "true")
        outputs.upToDateWhen { false }
    }
    // -Pkashpass.memory runs MemoryPeakTest, which records heap use in child JVMs and checks
    // nothing.
    if (providers.gradleProperty("kashpass.memory").orNull.let { it != null && it != "false" }) {
        systemProperty("kashpass.memory", "true")
        outputs.upToDateWhen { false }
    }
    // The default suite runs in parallel forks. The KeePass 2, matrix, memory and fuzz runs share
    // build folders and Docker, so they run in one fork.
    val serial = listOf("kashpass.keepass2", "kashpass.matrix", "kashpass.memory", "kashpass.fuzz")
        .any { name -> providers.gradleProperty(name).orNull.let { it != null && it != "false" } }
    if (!serial) maxParallelForks = (Runtime.getRuntime().availableProcessors() / 2).coerceIn(1, 8)
    // -Pkashpass.matrix runs KeePass2VersionMatrixTest: every KeePass 2 version in the scripts'
    // version table against KashPass, in Docker; -Pkashpass.matrix=<v>,<v> limits the versions.
    providers.gradleProperty("kashpass.matrix").orNull?.takeIf { it != "false" }?.let {
        systemProperty("kashpass.matrix", it.ifEmpty { "true" })
        outputs.upToDateWhen { false }
    }
    // String properties passed to the tests when set:
    // -Pkashpass.keepass=<v> runs the gated KeePass 2 tests on that KeePass 2 version (KeePass2Run;
    // modes that need the pin or newer refuse an older one); -Pkashpass.fixturesDir=<dir> reads the
    // fixtures from <dir> (Fixtures.DIR_PROPERTY); -Pkashpass.windowsKit=<dir> writes the Windows
    // check kit and -Pkashpass.windowsReturn=<dir> checks the files KeePass 2 on Windows saved
    // into <dir>/returned (WindowsReturnCheckTest).
    // -Pkashpass.propertySeed=<seed>|random and -Pkashpass.propertyIterations=<n> change the
    // property tests' fixed seed and multiply their iterations (PropertyRuns).
    for (name in listOf("kashpass.keepass", "kashpass.fixturesDir", "kashpass.windowsKit", "kashpass.windowsReturn", "kashpass.propertySeed", "kashpass.propertyIterations")) {
        providers.gradleProperty(name).orNull?.takeIf { it.isNotEmpty() }?.let {
            systemProperty(name, it)
            outputs.upToDateWhen { false }
        }
    }
    // -Pkashpass.fuzz runs the @FuzzTest harnesses in fuzzing mode (Jazzer) under a 256 MiB heap,
    // with an input that takes over 2 s a finding (Jazzer passes JUnit's default timeout to
    // libFuzzer as -timeout); -Pkashpass.fuzz=5m sets each run's duration (default: the
    // annotation's 1h).
    // DecoderFuzzTest's KDoc describes what runs without it.
    providers.gradleProperty("kashpass.fuzz").orNull?.takeIf { it != "false" }?.let { fuzz ->
        environment("JAZZER_FUZZ", "1")
        environment("JAZZER_INSTRUMENTATION_INCLUDES", "org.onekash.kashpass.vault.**")
        systemProperty("junit.jupiter.execution.timeout.default", "2 s")
        // JUnit would apply the timeout to the whole fuzzing run; libFuzzer applies it per input.
        systemProperty("junit.jupiter.execution.timeout.mode", "disabled")
        if (fuzz != "true" && fuzz.isNotEmpty()) environment("JAZZER_MAX_DURATION", fuzz)
        maxHeapSize = "256m"
        outputs.upToDateWhen { false }
    }
    // -Pkashpass.fuzzSeeds writes the corpus-derived seed inputs into Jazzer's corpus folder.
    if (providers.gradleProperty("kashpass.fuzzSeeds").orNull.let { it != null && it != "false" }) {
        systemProperty("kashpass.fuzzSeeds", "true")
        outputs.upToDateWhen { false }
    }
}
