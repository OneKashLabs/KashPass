package org.onekash.kashpass.vault.memory

import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.fail
import org.onekash.kashpass.vault.fixtures.TestFiles

/**
 * Runs [MemoryProbe] in child JVMs with the test classpath: one generation run with a large heap,
 * then one measurement per vault and heap. The generated vaults live in `build/memory`, never
 * committed; the performance vault is `build/fixtures/keepass2-performance.kdbx`
 * (`make-fixtures.sh --performance`).
 */
internal object MemoryRun {

    const val MIB = 1024L * 1024

    val dir: File get() = File(TestFiles.root, "build/memory")

    val performance: File get() = File(TestFiles.root, "build/fixtures/keepass2-performance.kdbx")

    /** One step of one measurement, as [MemoryProbe] printed it. */
    class Step(val step: String, val outcome: String, val peak: Long, val millis: Long, val values: Map<String, String>) {
        val ok: Boolean get() = outcome == "Unlocked" || outcome == "Saved"
    }

    /** One measurement: [steps] in order, or a child that ended without a result ([log]). */
    class Measured(val vault: File, val xmx: String, val steps: List<Step>, val log: String) {
        fun step(name: String): Step? = steps.firstOrNull { it.step == name }
    }

    /** Writes every vault in [specs] that `build/memory` doesn't hold yet. */
    fun generate(specs: List<MemoryVaults.Spec>) {
        val missing = specs.map { it.name }.filterNot { File(dir, it).isFile }
        if (missing.isEmpty()) return
        val log = run(listOf("-Xmx8g"), listOf("generate", dir.path) + missing, minutes = 60)
        val absent = missing.filterNot { File(dir, it).isFile }
        if (absent.isNotEmpty()) fail("not generated: $absent\n$log")
    }

    /**
     * Opens and saves [vault] in a child JVM with [jvmFlags] (the heap size among them), the
     * opener and saver computing their limits for [limitHeapBytes], over the platform-like disk
     * storage with [disk] and the shared fake otherwise, after [edits] entry edits ([MemoryProbe]).
     */
    fun measure(vault: File, xmx: String, limitHeapBytes: Long, jvmFlags: List<String> = emptyList(), disk: Boolean = false, edits: Int = 0): Measured {
        val log = run(listOf("-Xmx$xmx") + jvmFlags, listOf("measure", vault.path, limitHeapBytes.toString(), if (disk) "disk" else "fake", edits.toString()), minutes = 20)
        return parsed(vault, xmx, log)
    }

    private fun parsed(vault: File, xmx: String, log: String): Measured {
        val steps = log.lines().filter { it.startsWith("RESULT\t") }.map { line ->
            val values = line.split('\t').drop(1).associate { it.substringBefore('=') to it.substringAfter('=') }
            Step(values.getValue("step"), values.getValue("outcome"), values.getValue("peak").toLong(), values.getValue("millis").toLong(), values)
        }
        return Measured(vault, xmx, steps, log)
    }

    /**
     * Checks, in a child JVM with a heap of [xmx], a file just under the read limit for that heap
     * whose outer header field [field] holds a dictionary of tiny entries ([MemoryProbe] `header`).
     */
    fun header(field: Int, xmx: String): Measured =
        parsed(File("header-$field"), xmx, run(listOf("-Xmx$xmx"), listOf("header", field.toString()), minutes = 10))

    /**
     * Opens, in a child JVM with a heap of [xmx], a vault with a key file of tiny elements under
     * the root element [root] ([MemoryProbe] `keyfile`), sized under the key-file limit when
     * [parsed], else under the vault XML limit.
     */
    fun keyFile(root: String, xmx: String, parsed: Boolean = false): Measured =
        parsed(File("keyfile-$root-$parsed"), xmx, run(listOf("-Xmx$xmx"), listOf("keyfile", root, if (parsed) "parsed" else "large"), minutes = 10))

    /**
     * Returns the heap, in bytes per entry, that a read dictionary of [count] byte-array entries
     * with [nameBytes]-byte names and [valueBytes]-byte values keeps, measured in a child JVM with
     * a 2 GiB heap ([MemoryProbe] `entries`).
     */
    fun entryCost(count: Int, nameBytes: Int, valueBytes: Int, jvmFlags: List<String> = emptyList()): Double {
        val log = run(listOf("-Xmx2g") + jvmFlags, listOf("entries", count.toString(), nameBytes.toString(), valueBytes.toString()), minutes = 10)
        val line = log.lines().firstOrNull { it.startsWith("ENTRIES\t") } ?: fail("no ENTRIES line:\n$log")
        return line.split('\t').first { it.startsWith("perEntry=") }.substringAfter('=').toDouble()
    }

    /**
     * Returns the smallest heap, in MiB steps of [stepMib] between [lowMib] and [highMib], under
     * which [vault] opens and saves (only opens with [openOnly]) with the default collector, the
     * limits computed for [limitHeapBytes], over the storage [disk] picks, after [edits] entry
     * edits ([measure]); null when [highMib] does not suffice. The search assumes that a larger
     * heap never fails where a smaller one succeeds.
     */
    fun smallestHeapMib(vault: File, limitHeapBytes: Long, lowMib: Int, highMib: Int, stepMib: Int = 8, openOnly: Boolean = false, disk: Boolean = false, edits: Int = 0): Int? {
        fun fits(mib: Int): Boolean {
            val m = measure(vault, "${mib}m", limitHeapBytes, disk = disk, edits = edits)
            return m.step("open")?.ok == true && (openOnly || m.step("save")?.ok == true)
        }
        if (!fits(highMib)) return null
        var lo = lowMib / stepMib
        var hi = highMib / stepMib
        if (fits(lo * stepMib)) return lo * stepMib
        // Invariant: lo fails, hi fits.
        while (hi - lo > 1) {
            val mid = (lo + hi) / 2
            if (fits(mid * stepMib)) hi = mid else lo = mid
        }
        return hi * stepMib
    }

    /** Runs [tasks] on [threads] threads and returns their results in order. */
    fun <T> parallel(threads: Int, tasks: List<() -> T>): List<T> {
        val pool = Executors.newFixedThreadPool(threads)
        try {
            return pool.invokeAll(tasks.map { Callable { it() } }).map { it.get() }
        } finally {
            pool.shutdownNow()
        }
    }

    private fun run(jvmFlags: List<String>, args: List<String>, minutes: Long): String {
        val classpath = System.getProperty("kashpass.test.classpath") ?: fail("kashpass.test.classpath is not set by the build")
        val java = File(System.getProperty("java.home"), "bin/java").path
        val command = listOf(java) + jvmFlags + listOf("-Dkashpass.fixture.password=${TestFiles.password}", "-cp", classpath, MemoryProbe::class.java.name) + args
        val log = File.createTempFile("kashpass-memory", ".log")
        try {
            val process = ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log).start()
            if (!process.waitFor(minutes, TimeUnit.MINUTES)) {
                process.destroyForcibly()
                fail("memory probe did not finish in $minutes minutes: $args\n${log.readText()}")
            }
            return log.readText()
        } finally {
            log.delete()
        }
    }
}
