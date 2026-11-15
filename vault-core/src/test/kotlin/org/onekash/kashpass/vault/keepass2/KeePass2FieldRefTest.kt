package org.onekash.kashpass.vault.keepass2

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.doc.ContainerRig
import org.onekash.kashpass.vault.doc.FieldText
import org.onekash.kashpass.vault.doc.GroupView
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.open
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.index.FieldRefs
import org.onekash.kashpass.vault.index.FieldValue
import org.onekash.kashpass.vault.testing.TestVaults

/**
 * Every field of every current entry resolves to the same text with KashPass's [FieldRefs] as with
 * KeePass 2's reference rules (`keepass2-read.sh --refs`), compared by HMAC under a per-run key,
 * with the same answer to whether a password reference was resolved. The harness finds targets
 * with KeePass 2's own entry search; its substitution loop and cache are a transcription of
 * KeePass 2's placeholder engine, which is WinForms code the Mono run doesn't compile, so those
 * two parts are checked against that transcription, not against KeePass 2's own code. Runs with
 * -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2FieldRefTest {

    private val references = VaultFile("references.kdbx", TestVaults.referenceVault())

    @Test
    fun `every field resolves as KeePass 2 resolves it`() {
        val files = Fixtures.kdbx4Opening.map { Fixtures.file(it) } + listOf(references, VaultFile("browser.kdbx", TestVaults.browserVault(aesRounds = 1_000UL)))
        val key = KeePass2Run.newKey()
        val keepass = KeePass2Run.keepass2Refs(files, key)
        val problems = mutableListOf<String>()
        for (f in files) {
            val document = VaultXmlCodec.open(f.bytes, TestFiles.credentials(f), ContainerRig.LIMITS)
            val refs = FieldRefs.from(document)
            val ours = HashMap<Pair<String, String>, KeePass2Run.RefResult>()
            fun walk(group: GroupView) {
                for (entry in group.entries()) {
                    val uuid = entry.uuid ?: Uuids.ZERO
                    val hex = "%016X%016X".format(uuid.mostSignificantBits, uuid.leastSignificantBits)
                    val fields = LinkedHashMap<String, FieldText>()
                    for (field in entry.fields()) fields[field.key] = field.value
                    for ((name, value) in fields) {
                        val raw = when (value) {
                            is FieldText.Plain -> value.text
                            is FieldText.Protected -> value.value.reveal()
                        }
                        val resolved = refs.resolve(FieldValue.Plain(raw))
                        ours[hex to name] = KeePass2Run.RefResult(KeePass2Report.mac(key, resolved.value.reveal().toByteArray(Charsets.UTF_8)), resolved.insertsPassword)
                    }
                }
                for (child in group.groups()) walk(child)
            }
            walk(document.rootGroup)
            val theirs = keepass.getValue(f.name)
            for (k in ours.keys + theirs.keys) {
                if (ours[k] != theirs[k]) problems += "${f.name} entry ${k.first} field ${k.second}: KashPass ${ours[k]}, KeePass 2 ${theirs[k]}"
            }
        }
        assertEquals(emptyList(), problems)
        // The reference vault resolves what FieldRefsTest pins, so the comparison is not of
        // literals.
        val holder = keepass.getValue(references.name).getValue(TestVaults.refHex(14) to "UserName")
        assertEquals(KeePass2Report.mac(key, "bob".toByteArray(Charsets.UTF_8)), holder.mac)
        assertTrue(keepass.getValue(references.name).getValue(TestVaults.refHex(15) to "UserName").insertsPassword)
    }
}
