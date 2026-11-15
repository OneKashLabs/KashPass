package org.onekash.kashpass.vault.header

import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.VaultXmlCodecTest.Companion.fixture
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.u32

class KeePassSignatureTest {

    @Test
    fun `the KeePass signature check matches what KeePass 2 refuses as a key file`() {
        fun sig(second: Long) = u32(0x9AA2D903L) + u32(second)
        assertEquals(true, KeePassSignature.matches(fixture("keepass2-default-aeskdf.kdbx")))
        assertEquals(true, KeePassSignature.matches(sig(0xB54BFB65L)))
        assertEquals(true, KeePassSignature.matches(sig(0xB54BFB66L)))
        assertEquals(true, KeePassSignature.matches(sig(0xB54BFB67L)))
        assertEquals(false, KeePassSignature.matches(sig(0xB54BFB68L)))
        assertEquals(false, KeePassSignature.matches(sig(0xB54BFB67L).copyOf(7)))
        assertEquals(false, KeePassSignature.matches(TestVaults.KEY_FILE))
        assertEquals(false, KeePassSignature.matches(ByteArray(32)))
    }
}
