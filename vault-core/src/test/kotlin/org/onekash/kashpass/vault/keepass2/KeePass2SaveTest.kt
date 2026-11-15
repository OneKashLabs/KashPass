package org.onekash.kashpass.vault.keepass2

import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.open
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile

/**
 * KeePass 2 opens every file KashPass's encoder saves from a vault KashPass's container opened,
 * with the content it reports for the file that was opened: every fixture and every editable
 * corpus case (a case only KeePass 2 on Windows opens is compared with its content
 * base). Runs with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2SaveTest {

    @Test
    fun `KeePass 2 opens every saved file with the opened file's content`() {
        val cases = KeePass2Files.saveCases
        val sources = KeePass2Files.saveSources
        // A case only KeePass 2 on Windows opens is compared with its content base, which the run
        // under Mono opens.
        val baseOf = cases.filter { it.windows != null }.associate { "${it.name}.kdbx" to "${it.sameContentAs}.kdbx" }
        val saved = sources.map { KeePass2Files.kashPassSave(it) }
        val key = KeePass2Run.newKey()
        val reports = KeePass2Run.keepass2(sources + saved, key)
        val problems = sources.mapNotNull { f ->
            val before = reports.getValue(baseOf[f.name] ?: f.name)
            val after = reports.getValue("saved-${f.name}")
            if (after !is KeePass2Report.Opened) return@mapNotNull "${f.name}: KeePass 2 refuses the saved file: $after"
            KeePass2Report.contentDiff(before, after).takeIf { it.isNotEmpty() }?.let { "${f.name}:\n  " + it.joinToString("\n  ") }
        }
        if (problems.isNotEmpty()) fail("${problems.size} files:\n" + problems.joinToString("\n"))
    }

    @Test
    fun `a save writes Generator KashPass and keeps control characters KeePass 2 reads back`() {
        val source = VaultFile("meta-protected.kdbx", org.onekash.kashpass.vault.testing.TestVaults.metaProtectedVault())
        val document = VaultXmlCodec.open(source.bytes, TestFiles.credentials(source), ContainerRig.LIMITS)
        val id = org.onekash.kashpass.vault.index.VaultIndex.from(document).rows(org.onekash.kashpass.vault.index.Chip.All, "eve").single().id
        val draft = org.onekash.kashpass.vault.edit.EntryEdits.draftOf(document, id)!!
        val edited = org.onekash.kashpass.vault.edit.EntryEdits.edit(
            document, id,
            org.onekash.kashpass.vault.edit.EntryDraft(draft.title, draft.userName, org.onekash.kashpass.vault.doc.ProtectedText.of("a\u0001b"), draft.url, "n\u0002"),
            java.time.Instant.parse("2026-10-31T12:00:00Z"),
        ) as org.onekash.kashpass.vault.edit.EditResult.Changed
        val saved = VaultFile("saved-meta-protected.kdbx", VaultXmlCodec.encodeBytes(edited.document))
        val reread = VaultXmlCodec.open(saved.bytes, TestFiles.credentials(saved), ContainerRig.LIMITS)
        kotlin.test.assertEquals(listOf("KashPass"), reread.xml.root.child("Meta")!!.children("Generator").map { it.text() })
        val key = KeePass2Run.newKey()
        val report = KeePass2Run.keepass2(listOf(saved), key).getValue(saved.name) as? KeePass2Report.Opened
            ?: fail("KeePass 2 refuses a file KashPass saved with Generator KashPass")
        fun field(name: String, value: String) = "field $name * " + KeePass2Report.mac(key, value.toByteArray(Charsets.UTF_8))
        kotlin.test.assertTrue(field("Password", "a\u0001b") in report.lines, "KeePass 2 reads the password with its control character")
        kotlin.test.assertTrue(field("Notes", "n\u0002") in report.lines, "KeePass 2 reads the protected notes with its control character")
    }
}
