package org.onekash.kashpass.vault.keepass2

import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.keepass2.KeePassVersions.Expected
import org.onekash.kashpass.vault.keepass2.KeePassVersions.Kind

class KeePassVersionsTest {

    private fun fixture(name: String) = Fixtures.file(Fixtures.named(name))

    @Test
    fun `each fixture maps to the kind its header and key file give`() {
        assertEquals(Kind.ARGON2ID, KeePassVersions.kindOf(fixture("keepass2-argon2id.kdbx")))
        assertEquals(Kind.ARGON2ID, KeePassVersions.kindOf(fixture("keepass2-argon2-low-memory.kdbx")))
        assertEquals(Kind.ARGON2ID, KeePassVersions.kindOf(fixture("keepass2-argon2-version-0x10.kdbx")))
        assertEquals(Kind.XML_KEY_FILE_2, KeePassVersions.kindOf(fixture("keepass2-keyfile-only-v2.kdbx")))
        assertEquals(Kind.XML_KEY_FILE_2, KeePassVersions.kindOf(fixture("keepass2-password-keyfile-v2.kdbx")))
        for (name in listOf("keepass2-keyfile-only-v1.kdbx", "keepass2-keyfile-only-raw32.kdbx", "keepass2-keyfile-only-hex64.kdbx", "keepass2-keyfile-only-other.kdbx")) {
            assertEquals(Kind.OTHER, KeePassVersions.kindOf(fixture(name)), "$name: 2.35 reads this key-file format")
        }
        assertEquals(Kind.OTHER, KeePassVersions.kindOf(fixture("keepass2-chacha20-argon2d.kdbx")), "Argon2d opens on every version")
        assertEquals(Kind.OTHER, KeePassVersions.kindOf(fixture("keepass2-argon2-secret-and-data.kdbx")), "Argon2d with K and A")
        assertEquals(Kind.OTHER, KeePassVersions.kindOf(fixture("keepass2-kdbx41-tags.kdbx")), "4.1 is a capability, not a refusal")
        val corpus = { name: String -> org.onekash.kashpass.vault.corpus.Corpus.all.single { it.name == name }.file() }
        assertEquals(Kind.PROTECTED_UNKNOWN_ELEMENT, KeePassVersions.kindOf(corpus("spec-inner-protected-unknown-element")))
        assertEquals(Kind.OTHER, KeePassVersions.kindOf(corpus("spec-meta-binary-protected-unreferenced")), "a protected Meta binary is KeePass's own element")
    }

    @Test
    fun `only 2_35 refuses a protected unknown element, as it refuses the original file`() {
        assertEquals(Expected.Refuses("FormatException", null), KeePassVersions.expected(KeePassVersions.named("2.35"), Kind.PROTECTED_UNKNOWN_ELEMENT))
        for (v in KeePassVersions.all.drop(1)) assertTrue(KeePassVersions.expected(v, Kind.PROTECTED_UNKNOWN_ELEMENT) is Expected.Opens, v.name)
    }

    @Test
    fun `2_35 and 2_44 refuse Argon2id and XML 2_0 key files with their own exceptions`() {
        for (v in listOf("2.35", "2.44")) {
            val version = KeePassVersions.named(v)
            assertEquals(Expected.Refuses("Exception", "Unknown key derivation function!"), KeePassVersions.expected(version, Kind.ARGON2ID))
            assertEquals(Expected.Refuses("InvalidCompositeKeyException", null), KeePassVersions.expected(version, Kind.XML_KEY_FILE_2))
            assertEquals(Expected.Opens(KeePassVersions.PRE_KDBX41_UNSEEN), KeePassVersions.expected(version, Kind.OTHER))
        }
    }

    @Test
    fun `2_47 opens every kind without the KDBX 4_1 tokens, 2_48 and later with everything`() {
        for (kind in Kind.entries) assertEquals(Expected.Opens(KeePassVersions.PRE_KDBX41_UNSEEN), KeePassVersions.expected(KeePassVersions.named("2.47"), kind))
        for (v in listOf("2.48", "2.56", "2.57", "2.60", "2.61.1", "2.62")) {
            for (kind in Kind.entries) assertEquals(Expected.Opens(emptySet()), KeePassVersions.expected(KeePassVersions.named(v), kind), "$v $kind")
        }
    }

    @Test
    fun `each version writes the formats its GetMinKdbxVersion picks`() {
        fun w(v: String) = KeePassVersions.written(KeePassVersions.named(v))
        assertEquals(mapOf("defaults" to "3.1", "chacha20-aeskdf" to "3.1", "argon2d" to "4.0"), w("2.35"))
        assertEquals(mapOf("defaults" to "3.1", "chacha20-aeskdf" to "4.0", "argon2d" to "4.0"), w("2.44"))
        assertEquals(mapOf("defaults" to "3.1", "chacha20-aeskdf" to "4.0", "argon2d" to "4.0", "argon2id" to "4.0"), w("2.47"))
        for (v in listOf("2.48", "2.56")) {
            assertEquals(mapOf("defaults" to "3.1", "defaults-group-tags" to "4.1", "chacha20-aeskdf" to "4.0", "argon2d" to "4.0", "argon2id" to "4.0"), w(v))
        }
        for (v in listOf("2.57", "2.60", "2.61.1", "2.62")) {
            assertEquals(mapOf("defaults" to "4.0", "defaults-group-tags" to "4.1", "chacha20-aeskdf" to "4.0", "argon2d" to "4.0", "argon2id" to "4.0"), w(v))
        }
    }

    @Test
    fun `a refusal matches only its own exception`() {
        val unknownKdf = Expected.Refuses("Exception", "Unknown key derivation function!")
        assertTrue(unknownKdf.matches("Exception: Unknown key derivation function!"))
        assertTrue(!unknownKdf.matches("Exception: The file is corrupted."))
        assertTrue(!unknownKdf.matches("InvalidCompositeKeyException: The composite key is invalid!"))
        val wrongKey = Expected.Refuses("InvalidCompositeKeyException", null)
        assertTrue(wrongKey.matches("InvalidCompositeKeyException: The composite key is invalid!"))
        assertTrue(!wrongKey.matches("Exception: Unknown key derivation function!"))
    }

    @Test
    fun `the versions, their KDBX 4_1 support and the pin are the scripts', row for row`() {
        val table = File(TestFiles.root, "scripts/fixtures/keepass2-versions.tsv")
        if (!table.isFile) return // local tooling, not in git; the matrix itself fails without it
        val rows = table.readLines().filter { it.isNotBlank() && !it.startsWith("#") }.map { it.split('\t') }
        assertEquals(rows.map { it[0] }, KeePassVersions.all.map { it.name })
        for (row in rows) assertEquals("KP_PRE_2_48" !in row[3], KeePassVersions.named(row[0]).kdbx41, "${row[0]}: the table's symbols")
        val pin = File(table.parentFile, "keepass2-lib.sh").readLines().single { it.startsWith("KEEPASS_PIN=") }.substringAfter('=').trim('"')
        assertEquals(pin, KeePassVersions.PIN, "KeePassVersions.PIN and keepass2-lib.sh's KEEPASS_PIN")
    }
}
