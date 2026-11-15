package org.onekash.kashpass.vault

import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.testing.KotlinSourceText

/**
 * The decoder has no option to skip a hash or HMAC check: the decode entries take no Boolean, no
 * function returning Boolean, and only the parameters listed here. A new parameter needs a look
 * at what it can turn off before it joins the list.
 */
class DecoderChecksRuleTest {

    private val root = File("src/main/kotlin/org/onekash/kashpass/vault")

    // The decode entries by file; [allowed] lists every parameter name they take.
    private val entries = listOf(
        "kdbx/KdbxDecoder.kt" to "decode",
        "kdbx/BlockStream.kt" to "read",
        "doc/ContainerDecode.kt" to "decode",
        "doc/VaultXmlCodec.kt" to "decode",
        "doc/VaultXmlCodec.kt" to "readBack",
    )

    private val allowed = setOf(
        "bytes", "header", "compositeKey", "derive", "inflateLimit", "buffers", "step", "start", "keys",
        "passwordHash", "keyFilePart", "limits", "readLimitBytes", "kdfPolicy", "maxHeapBytes", "onXml", "settings",
        "credentials", "budget",
    )

    /** Returns "name: type" for each parameter of every function [name] declares in [source]. */
    private fun parameters(source: String, name: String): List<Pair<String, String>> {
        val code = KotlinSourceText.codeLines(source).joinToString("\n")
        val out = mutableListOf<Pair<String, String>>()
        var at = code.indexOf("fun $name(")
        while (at >= 0) {
            var i = code.indexOf('(', at) + 1
            var depth = 1
            val start = i
            while (depth > 0) {
                when {
                    code[i] in "(<{" -> depth++
                    code[i] in ")}" || (code[i] == '>' && code[i - 1] != '-') -> depth--
                }
                i++
            }
            val list = code.substring(start, i - 1)
            // Split on commas outside parentheses, angle brackets and braces.
            var d = 0
            var from = 0
            val parts = mutableListOf<String>()
            for ((k, c) in list.withIndex()) {
                when {
                    c in "(<{" -> d++
                    c in ")}" || (c == '>' && list.getOrNull(k - 1) != '-') -> d--
                    c == ',' && d == 0 -> {
                        parts += list.substring(from, k)
                        from = k + 1
                    }
                }
            }
            parts += list.substring(from)
            for (p in parts.map { it.trim() }.filter { it.isNotEmpty() }) {
                val pName = p.substringBefore(':').trim().split(' ').last()
                val type = p.substringAfter(':').substringBefore('=').trim()
                out += pName to type
            }
            at = code.indexOf("fun $name(", i)
        }
        return out
    }

    private fun offenders(source: String, name: String): List<String> = parameters(source, name).mapNotNull { (p, type) ->
        when {
            type == "Boolean" || type == "Boolean?" -> "$p: Boolean"
            type.contains("->") && type.substringAfterLast("->").trim().removeSuffix(")").trim().startsWith("Boolean") -> "$p: returns Boolean"
            p !in allowed -> "$p: not on the list"
            else -> null
        }
    }

    @Test
    fun `the decode entries have no option to skip a check`() {
        for ((path, name) in entries) {
            val source = File(root, path).readText()
            assertTrue(parameters(source, name).isNotEmpty(), "$path: no fun $name")
            assertEquals(emptyList(), offenders(source, name), path)
        }
    }

    @Test
    fun `the rule catches a planted skip option`() {
        val planted = "object X {\n    fun decode(bytes: ByteArray, skipHmac: Boolean = false, verify: (Int) -> Boolean, limits: Int) = Unit\n}"
        assertEquals(listOf("skipHmac: Boolean", "verify: returns Boolean"), offenders(planted, "decode"))
        assertEquals(listOf("repairMode: not on the list"), offenders("fun decode(bytes: ByteArray, repairMode: Int) = Unit", "decode"))
    }
}
