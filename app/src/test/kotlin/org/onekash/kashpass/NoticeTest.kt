package org.onekash.kashpass

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Checks that NOTICE, the third-party notices in the repository, names every licence the shipped
 * code carries and keeps the sections that were reviewed, and that LICENSE is the AGPL text alone,
 * so GitHub's licence detection reads it as AGPL-3.0.
 */
class NoticeTest {

    private val root = File("..").canonicalFile
    private val notice = File(root, "NOTICE").readText()

    @Test
    fun `the notice covers KashPass, the Apache libraries and Material Symbols`() {
        val required = listOf(
            "KashPass, Copyright 2026 onekash labs. Licensed under the GNU Affero General Public License v3.0 or later.",
            "kotlinx.coroutines",
            "kotlin-stdlib",
            "org.jetbrains:annotations",
            "org.jspecify:jspecify",
            "com.google.guava:listenablefuture",
            "androidx.compose.material3",
            "Apache License\n                           Version 2.0, January 2004",
            "END OF TERMS AND CONDITIONS",
        )
        val missing = required.filterNot { it in notice }
        assertTrue("missing from NOTICE: $missing", missing.isEmpty())
        // The KDBX container, its KDF and its ciphers are KashPass's own code, so the notice has
        // one section of Apache-licensed parts and the licence text; a part under another licence,
        // or vendored code, adds a section and fails here until it is reviewed.
        val lines = notice.lines()
        val sections = lines.indices.filter { lines[it].startsWith("=====") }.mapNotNull { lines.getOrNull(it + 1) }
        assertEquals(listOf("Libraries licensed under the Apache License, Version 2.0 (text at the end)", "Apache License, Version 2.0"), sections)
        assertTrue("the Apache text appears once", notice.split("END OF TERMS AND CONDITIONS").size == 2)
        val apache = notice.substringAfter(sections[0]).substringBefore("=====\n" + sections[1])
        assertTrue("Material Symbols is in the Apache section", "Material Symbols" in apache)
    }

    @Test
    fun `LICENSE is the AGPL text and nothing else`() {
        val license = File(root, "LICENSE").readText()
        assertEquals("GNU AFFERO GENERAL PUBLIC LICENSE", license.lines().first { it.isNotBlank() }.trim())
        assertTrue("ends with the AGPL's last section", license.trimEnd().endsWith("<https://www.gnu.org/licenses/>."))
    }
}
