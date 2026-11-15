package org.onekash.kashpass.vault.fixtures

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.ContainerDecode
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.KeyFile
import org.onekash.kashpass.vault.doc.KeyFileResult
import org.onekash.kashpass.vault.kdbx.KdbxResult
import org.onekash.kashpass.vault.kdbx.KdbxUnsupported
import org.onekash.kashpass.vault.testing.KdbxToolkit

class Kdbx3VaultsTest {

    @Test
    fun `both vaults are KDBX 3_1 files, which KashPass refuses as unsupported`() {
        assertEquals(listOf(CredentialMode.PASSWORD_AND_KEY_FILE, CredentialMode.KEY_FILE_ONLY), Kdbx3Vaults.files.map { it.mode })
        for (f in Kdbx3Vaults.files) {
            assertContentEquals(byteArrayOf(0x03, 0xD9.toByte(), 0xA2.toByte(), 0x9A.toByte(), 0x67, 0xFB.toByte(), 0x4B, 0xB5.toByte(), 1, 0, 3, 0), f.bytes.copyOf(12), f.name)
            val r = assertIs<ContainerDecode.Result.Failed>(ContainerRig.open(f), f.name)
            assertEquals(KdbxResult.Unsupported(KdbxUnsupported.FormatVersion(3, 1)), r.result, f.name)
        }
    }

    @Test
    fun `the 65-byte key file is 64 hex characters and a newline, hashed as KeePass 2 reads it`() {
        assertEquals(65, Kdbx3Vaults.KEY_FILE.size)
        assertEquals('\n'.code.toByte(), Kdbx3Vaults.KEY_FILE.last())
        assertContentEquals(KdbxToolkit.sha256(Kdbx3Vaults.KEY_FILE), assertIs<KeyFileResult.Key>(KeyFile.parse(Kdbx3Vaults.KEY_FILE.copyOf())).part)
    }
}
