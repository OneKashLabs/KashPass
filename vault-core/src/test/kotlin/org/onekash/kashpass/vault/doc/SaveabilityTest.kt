package org.onekash.kashpass.vault.doc

import java.util.stream.Stream
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.doc.VaultXmlCodecTest.Companion.credentials
import org.onekash.kashpass.vault.doc.VaultXmlCodecTest.Companion.decode
import org.onekash.kashpass.vault.header.DamageReason
import org.onekash.kashpass.vault.testing.TestVaults

class SaveabilityTest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    fun `content KashPass can't hold exactly opens read-only`(reason: ReadOnlyReason, bytes: ByteArray) {
        assertEquals(Saveability.ReadOnly(reason), decode(bytes, TestVaults.PASSWORD).saveability)
    }

    @Test
    fun `a protected value with a child element is refused, as KeePass 2's ReadElementString refuses it`() {
        val xml = TestVaults.keePassXml(entries = "<Entry><String><Key>P</Key><Value Protected=\"True\"><X/></Value></String></Entry>")
        assertEquals(Decoded.Damaged(DamageReason.XML), VaultXmlCodec.decode(TestVaults.rawXmlVault(xml), credentials(TestVaults.PASSWORD), VaultXmlCodec.Limits(1 shl 20, 1L shl 20)))
    }

    @Test
    fun `an ordinary vault with referenced attachments is saveable`() {
        val bytes = TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry(0) + entry(1)), attachments = listOf(A, B))
        assertEquals(Saveability.Saveable, decode(bytes, TestVaults.PASSWORD).saveability)
        assertEquals(Saveability.Saveable, decode(TestVaults.browserVault(aesRounds = 1_000UL), TestVaults.PASSWORD).saveability)
    }

    @Test
    fun `an attachment no entry references leaves the vault saveable, and the save drops it`() {
        val bytes = TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry(0)), attachments = listOf(A, B))
        val document = decode(bytes, TestVaults.PASSWORD)
        assertEquals(Saveability.Saveable, document.saveability)
        assertEquals(listOf(A.toList()), decode(VaultXmlCodec.encodeBytes(document), TestVaults.PASSWORD).attachments.map { it.data.toList() })
    }

    @Test
    fun `decrypted XML over the save limit is read-only`() {
        val bytes = TestVaults.rawXmlVault(TestVaults.keePassXml())
        val doc = VaultXmlCodec.open(bytes, credentials(TestVaults.PASSWORD), VaultXmlCodec.Limits(open = 1024 * 1024, save = 100))
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.TOO_LARGE_TO_SAVE), doc.saveability)
    }

    @Test
    fun `a payload over the payload save cap opens read-only although its XML is under the save cap`() {
        val bytes = TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry(0)), attachments = listOf(ByteArray(10_000) { it.toByte() }))
        val open = VaultXmlCodec.Limits(open = 1024 * 1024, save = 1024 * 1024, decompression = 1024 * 1024, payloadSave = 1024 * 1024)
        val document = VaultXmlCodec.open(bytes, credentials(TestVaults.PASSWORD), open)
        assertEquals(Saveability.Saveable, document.saveability)
        val payload = VaultXmlCodec.payloadBytes(document)
        assertTrue(payload > 10_000 + document.xmlBytes, "the payload counts the attachment and the inner header: $payload")
        val under = VaultXmlCodec.Limits(open = 1024 * 1024, save = 1024 * 1024, decompression = 1024 * 1024, payloadSave = payload)
        assertEquals(Saveability.Saveable, VaultXmlCodec.open(bytes, credentials(TestVaults.PASSWORD), under).saveability)
        val over = VaultXmlCodec.Limits(open = 1024 * 1024, save = 1024 * 1024, decompression = 1024 * 1024, payloadSave = payload - 1)
        assertEquals(Saveability.ReadOnly(ReadOnlyReason.TOO_LARGE_TO_SAVE), VaultXmlCodec.open(bytes, credentials(TestVaults.PASSWORD), over).saveability)
    }

    @Test
    fun `missing Meta elements take KeePass 2's defaults`() {
        val meta = decode(TestVaults.rawXmlVault(TestVaults.keePassXml(meta = "")), TestVaults.PASSWORD).meta
        assertEquals(true, meta.recycleBinEnabled)
        assertEquals(null, meta.recycleBinUuid)
        assertEquals(10, meta.historyMaxItems)
        assertEquals(6L * 1024 * 1024, meta.historyMaxSize)
        assertEquals("", meta.defaultUserName)
        assertEquals(listOf(false, false, true, false, false), listOf("Title", "UserName", "Password", "URL", "Notes").map(meta::protects))
    }

    @Test
    fun `Meta values are read as written`() {
        val xml = TestVaults.keePassXml(
            meta = "<RecycleBinEnabled>False</RecycleBinEnabled><RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAg==</RecycleBinUUID>" +
                "<HistoryMaxItems>-1</HistoryMaxItems><HistoryMaxSize>8589934592</HistoryMaxSize><DefaultUserName>me</DefaultUserName>" +
                "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectPassword>False</ProtectPassword></MemoryProtection>",
        )
        val meta = decode(TestVaults.rawXmlVault(xml), TestVaults.PASSWORD).meta
        assertEquals(false, meta.recycleBinEnabled)
        assertEquals(java.util.UUID(0, 2), meta.recycleBinUuid)
        assertEquals(-1, meta.historyMaxItems)
        assertEquals(8_589_934_592L, meta.historyMaxSize)
        assertEquals("me", meta.defaultUserName)
        assertEquals(true, meta.protects("Title"))
        assertEquals(false, meta.protects("Password"))
    }

    companion object {
        private val A = "first attachment".toByteArray()
        private val B = "second attachment".toByteArray()

        private fun entry(ref: Int, history: String = "") =
            "<Entry><String><Key>Title</Key><Value>t$ref</Value></String><Binary><Key>f$ref.txt</Key><Value Ref=\"$ref\" /></Binary>$history</Entry>"

        @JvmStatic
        fun cases(): Stream<Arguments> = Stream.of(
            Arguments.of(ReadOnlyReason.DOCTYPE, TestVaults.rawXmlVault(TestVaults.keePassXml(prolog = "<!DOCTYPE KeePassFile>\n"))),
            Arguments.of(ReadOnlyReason.ATTACHMENT_REF_OUT_OF_RANGE, TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry(1)), attachments = listOf(A))),
            Arguments.of(ReadOnlyReason.ATTACHMENT_REF_OUT_OF_RANGE, TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry(0).replace("Ref=\"0\"", "Ref=\"x\"")), attachments = listOf(A))),
            // A history item's reference counts like any other.
            Arguments.of(
                ReadOnlyReason.ATTACHMENT_REF_OUT_OF_RANGE,
                TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry(0, history = "<History>${entry(5)}</History>")), attachments = listOf(A)),
            ),
            // Ref 2 names no attachment of two.
            Arguments.of(
                ReadOnlyReason.ATTACHMENT_REF_OUT_OF_RANGE,
                TestVaults.rawXmlVault(TestVaults.keePassXml(entries = entry(0) + entry(2)), attachments = listOf(A, B)),
            ),
            // Protected on an element that switches context is ignored and its children are
            // read; the encoder would replace them, so the vault stays read-only.
            Arguments.of(
                ReadOnlyReason.PROTECTED_CONTAINER,
                TestVaults.rawXmlVault(TestVaults.keePassXml(entries = "<Entry><String Protected=\"True\"><Key>P</Key><Value>v</Value></String></Entry>")),
            ),
        )
    }
}
