package org.onekash.kashpass.vault.keepass2

import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.fixtures.CredentialMode
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.Kdbx3Vaults
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.TestVaults

/**
 * KeePass 2 opens every KDBX 4 fixture KashPass opens, every vault KashPass saves in the
 * interop round trip, the generated Salsa20 vault and the performance vault when it was
 * generated, and reports the content KashPass's own container reads. Runs with -Pkashpass.keepass2
 * only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2ReadTest {

    @Test
    fun `KeePass 2 opens every fixture, KashPass save and generated vault with the content KashPass reads`() {
        val performance = KeePass2Files.performance()
        if (performance == null) System.err.println("KeePass2ReadTest: no build/fixtures/keepass2-performance.kdbx; generate it to include it")
        assertEquals(TestVaults.PASSWORD, TestFiles.password, "the generated vaults use the fixture password")
        val files = Fixtures.kdbx4Opening.map { Fixtures.file(it) } + KeePass2Files.interopSaves +
            listOfNotNull(VaultFile("generated-salsa20.kdbx", TestVaults.salsa20Vault()), performance)
        val key = KeePass2Run.newKey()
        val problems = Agreement.owned(files, KeePass2Run.keepass2(files, key), key)
        if (problems.isNotEmpty()) fail(problems)
    }

    @Test
    fun `KeePass 2 opens the Argon2 0x12 fixture, which KashPass refuses by its KDF policy`() {
        // KdfPolicy accepts Argon2 versions 0x10 and 0x13 only.
        val file = Fixtures.file(Fixtures.named("keepass2-argon2-version-0x12.kdbx"))
        val key = KeePass2Run.newKey()
        assertIs<KeePass2Report.Opened>(KeePass2Run.keepass2(listOf(file), key).getValue(file.name))
        val ours = assertIs<KeePass2Report.Refused>(DocumentReport.of(file, key))
        assertTrue(ours.reason.startsWith("refused by policy"), ours.reason)
    }

    @Test
    fun `KeePass 2 opens the KDBX 3_1 vaults KashPass refuses as unsupported`() {
        // KashPass reads KDBX 4 only; KeePass 2 opening the vaults shows they are valid files.
        val key = KeePass2Run.newKey()
        val reports = KeePass2Run.keepass2(KeePass2Files.kdbx3(), key)
        assertEquals(2, reports.size)
        val title = "field Title - ${KeePass2Report.mac(key, Kdbx3Vaults.TITLE.toByteArray(Charsets.UTF_8))}"
        for ((name, report) in reports) {
            val opened = assertIs<KeePass2Report.Opened>(report, "$name: $report")
            assertEquals(1, opened.lines.count { it.startsWith("entry ") }, name)
            assertTrue(title in opened.lines, "$name: no entry titled ${Kdbx3Vaults.TITLE}")
        }
    }

    @Test
    fun `KeePass 2 opens a vault KashPass saved with the 65-byte key file`() = runBlocking<Unit> {
        val part = KdbxToolkit.sha256(Kdbx3Vaults.KEY_FILE)
        val generated = TestVaults.bytes(aesRounds = 6_000UL, password = TestFiles.password, keyPart = part)
        val document = TestVaults.unlock(generated, TestFiles.password, keyFile = Kdbx3Vaults.KEY_FILE).session.opened.document
        val saved = VaultFile("saved-keyfile-65.kdbx", VaultXmlCodec.encodeBytes(document), CredentialMode.PASSWORD_AND_KEY_FILE, Kdbx3Vaults.KEY_FILE_NAME, Kdbx3Vaults.KEY_FILE)
        val key = KeePass2Run.newKey()
        val problems = Agreement.owned(listOf(saved), KeePass2Run.keepass2(listOf(saved), key), key)
        if (problems.isNotEmpty()) fail(problems)
    }
}
