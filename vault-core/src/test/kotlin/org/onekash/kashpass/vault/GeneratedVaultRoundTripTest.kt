package org.onekash.kashpass.vault

import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.FieldKind
import org.onekash.kashpass.vault.index.FieldValue
import org.onekash.kashpass.vault.index.VaultIndex
import org.onekash.kashpass.vault.open.OpenResult
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeBackupStore
import org.onekash.kashpass.vault.testing.FakeSaveMarkerStore
import org.onekash.kashpass.vault.testing.FakeVaultStateStore
import org.onekash.kashpass.vault.testing.FakeVaultStorage
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.TestVaults

/**
 * The vaults [TestVaults] generates open through the real opener with their content and refuse a
 * wrong password, and a KashPass save of one reads back in [KdbxToolkit], which shares no
 * container code with KashPass: the generated vaults and KashPass agree in both directions.
 */
class GeneratedVaultRoundTripTest {

    private val loc = "content://fake/vault.kdbx"

    @Test
    fun `a generated vault opens with its entries and protected values`() = runBlocking<Unit> {
        val opened = TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL))
        val index = opened.session.index
        val rows = index.rows(Chip.All, "")
        assertEquals(listOf("Example Bank", "Example Mail"), rows.mapNotNull { it.title }.sorted())
        val mail = rows.single { it.title == "Example Mail" }
        val password = index.details(mail.id)!!.fields.single { it.kind == FieldKind.PASSWORD }
        assertEquals("mail-pass", assertIs<FieldValue.Protected>(password.value).reveal())
    }

    @Test
    fun `the generated Salsa20 vault opens through the opener with its protected values`() = runBlocking<Unit> {
        val index = TestVaults.unlock(TestVaults.salsa20Vault()).session.index
        val passwords = index.rows(Chip.All, "").associate { row ->
            row.title to assertIs<FieldValue.Protected>(index.details(row.id)!!.fields.single { it.kind == FieldKind.PASSWORD }.value).reveal()
        }
        assertEquals(mapOf<String?, String>("Salsa Mail" to "salsa-pass", "Salsa Bank" to "bänk-päss"), passwords)
    }

    @Test
    fun `the generated Meta-protected vault opens with its values, and the toolkit reads them protected`() = runBlocking<Unit> {
        val bytes = TestVaults.metaProtectedVault()
        val index = TestVaults.unlock(bytes).session.index
        val row = index.rows(Chip.All, "eve").single()
        val values = index.details(row.id)!!.fields.associate { it.name to it.value.reveal() }
        assertEquals(mapOf("UserName" to "eve", "Password" to "plain-pass", "URL" to "https://meta.example", "PIN" to "4711", "Floor" to "third", "Notes" to "meta notes"), values)
        val protectedValues = KdbxToolkit.open(bytes, KdbxToolkit.Key(TestVaults.PASSWORD)).layers.protectedValues.map { String(it, Charsets.UTF_8) }
        assertEquals(listOf("eve", "https://meta.example", "meta notes", "4711", "ordinary-pass"), protectedValues)
    }

    @Test
    fun `the generated reference vault opens with its entries, and the toolkit reads the same XML`() = runBlocking<Unit> {
        val bytes = TestVaults.referenceVault()
        val session = TestVaults.unlock(bytes).session
        // 2, 10-19, 201-212, 301-321 and 30 outside the recycle bin; 20 inside it.
        assertEquals(1 + 10 + 12 + 21 + 1, session.index.rows(Chip.All, "").size)
        assertEquals(listOf("Old Login"), session.index.rows(Chip.RecycleBin, "").map { it.title })
        val holder = session.index.rows(Chip.All, "Reference Holder").single()
        assertEquals("{REF:U@T:Example Bank}", holder.userName)
        assertEquals("bob", session.refs.resolve(FieldValue.Plain(holder.userName)).value.reveal())
        val xml = String(KdbxToolkit.open(bytes, KdbxToolkit.Key(TestVaults.PASSWORD)).layers.xml, Charsets.UTF_8)
        assertTrue("<Value>{REF:P@I:${TestVaults.refHex(11)}}</Value>" in xml)
    }

    @Test
    fun `a generated vault refuses a wrong password`() = runBlocking<Unit> {
        val storage = FakeVaultStorage().apply { put(loc, TestVaults.bytes(aesRounds = 1_000UL)) }
        val opener = VaultOpener.create(storage, FakeVaultStateStore(), Dispatchers.IO)
        assertEquals(OpenResult.WrongPassword, opener.open(loc, "wrong".toCharArray()))
    }

    @Test
    fun `a generated key-file vault opens with the password and the key file`() = runBlocking<Unit> {
        val bytes = TestVaults.bytes(aesRounds = 1_000UL, keyPart = TestVaults.KEY_FILE_PART)
        val opened = TestVaults.unlock(bytes, keyFile = TestVaults.KEY_FILE)
        assertEquals(2, opened.session.index.rows(Chip.All, "").size)
    }

    @Test
    fun `a KashPass save of a generated vault reads back in the toolkit with the edit`() = runBlocking<Unit> {
        val storage = FakeVaultStorage().apply { put(loc, TestVaults.bytes(aesRounds = 1_000UL)) }
        val state = FakeVaultStateStore()
        val opener = VaultOpener.create(storage, state, Dispatchers.IO)
        val session = assertIs<OpenResult.Unlocked>(opener.open(loc, TestVaults.PASSWORD.toCharArray())).session
        val document = session.opened.document
        val id = VaultIndex.from(document).rows(Chip.All, "").single { it.title == "Example Mail" }.id
        val d = EntryEdits.draftOf(document, id)!!
        val edited = assertIs<EditResult.Changed>(EntryEdits.edit(document, id, EntryDraft("Edited Mail", d.userName, d.password, d.url, d.notes), Instant.now())).document
        val saver = SafeSaver.create(storage, FakeBackupStore(), FakeSaveMarkerStore(), state, Dispatchers.IO, CoroutineScope(SupervisorJob() + Dispatchers.IO))
        assertIs<SaveResult.Saved>(saver.save(loc, session.opened.withDocument(edited)))

        val read = KdbxToolkit.open(storage.bytes(loc)!!, KdbxToolkit.Key(TestVaults.PASSWORD))
        val xml = String(read.layers.xml, Charsets.UTF_8)
        assertTrue("<Value>Edited Mail</Value>" in xml)
        assertTrue("mail-pass" in read.layers.protectedValues.map { String(it, Charsets.UTF_8) })
    }
}
