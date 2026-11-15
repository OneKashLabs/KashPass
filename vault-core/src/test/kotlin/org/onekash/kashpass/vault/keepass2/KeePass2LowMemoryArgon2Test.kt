package org.onekash.kashpass.vault.keepass2

import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.doc.withKdf
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.kdbx.Argon2Type
import org.onekash.kashpass.vault.kdbx.KdfParameters

/**
 * KeePass 2 derives Argon2 memory below 8 KiB per lane as KashPass does: a vault KashPass saves
 * with each setting KdfEngineTest pins opens in KeePass 2 with the content KashPass reads. Runs
 * with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2LowMemoryArgon2Test {

    @Test
    fun `KeePass 2 opens a vault saved with each Argon2 memory below 8 KiB per lane`() {
        val source = Fixtures.file(Fixtures.named("keepass2-weak-aeskdf-6000.kdbx"))
        val read = (ContainerRig.open(source) as? ContainerDecode.Result.Opened)?.read ?: fail("${source.name} does not open")
        val document = VaultXmlCodec.document(read, TestFiles.credentials(source), ContainerRig.LIMITS)
        val files = SETTINGS.map { (lanes, memory) ->
            val kdf = KdfParameters.Argon2(Argon2Type.ARGON2ID, ByteArray(32), lanes.toUInt(), memory.toULong(), 3UL, 0x13U, null, null)
            VaultFile("low-memory-$lanes-lanes-$memory-bytes.kdbx", VaultXmlCodec.encodeBytes(document.withKdf(kdf)), source.mode)
        }
        val key = KeePass2Run.newKey()
        val problems = Agreement.owned(files, KeePass2Run.keepass2(files, key), key)
        if (problems.isNotEmpty()) fail(problems)
    }

    private companion object {
        val SETTINGS = listOf(2 to 8192, 4 to 8192, 8 to 8192, 4 to 20480, 3 to 9216, 8 to 65535)
    }
}
