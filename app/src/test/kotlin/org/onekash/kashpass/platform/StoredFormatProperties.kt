package org.onekash.kashpass.platform

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.orNull
import io.kotest.property.arbitrary.set
import io.kotest.property.checkAll
import java.io.File
import java.nio.file.Files
import java.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.testing.fakeKeyStore
import org.onekash.kashpass.vault.backup.SaveMarker
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.header.Argon2Variant
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.SealedKey
import org.onekash.kashpass.vault.storage.StoredKeyState
import org.onekash.kashpass.vault.storage.UnlockAvailability
import org.onekash.kashpass.vault.storage.UnsealResult
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.KotlinSourceText
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.robolectric.RobolectricTestRunner

/**
 * Stored formats are read by every later version, so each value the app stores reads back as
 * written, and a stored value of the type the app writes for its key, whatever its text or number,
 * reads as null, the default or a valid value and never throws. Values of another type than the
 * app writes for a key are out of scope: no version writes them.
 */
@RunWith(RobolectricTestRunner::class)
class StoredFormatProperties {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    private fun prefs(file: String) = context.getSharedPreferences(file, Context.MODE_PRIVATE)

    private fun clear(file: String) = prefs(file).edit().clear().commit()

    @Test
    fun `every stored value the app reads is covered here`() {
        val main = File(System.getProperty("user.dir")!!, "src/main/kotlin")
        val readers = main.walk().filter { it.extension == "kt" }.filter { file ->
            KotlinSourceText.codeLines(file.readText()).any { STORED_READ.containsMatchIn(it) }
        }.map { it.nameWithoutExtension }.toSortedSet()
        assertEquals(COVERED_READERS.keys, readers)
        assertEquals(VAULT_KEYS, PrefsVaultStateStore.KEYS)
    }

    @Test
    fun `the vault state store reads any stored text or number without throwing`() = runBlocking<Unit> {
        val reached = sortedMapOf<String, Int>()
        fun count(name: String, hit: Boolean) {
            if (hit) reached[name] = (reached[name] ?: 0) + 1
        }
        checkAll(PropertyRuns.config(iterations = 500), PLANTED_VAULT_STATE) { planted ->
            clear(PrefsVaultStateStore.FILE)
            prefs(PrefsVaultStateStore.FILE).edit().apply {
                planted.strings.forEach { (key, value) -> putString(key, value) }
                planted.readOnly?.let { putBoolean("vault_read_only", it) }
                planted.keep?.let { putInt("backup_keep", it) }
                planted.sets.forEach { (key, value) -> putStringSet(key, value) }
            }.commit()
            val store = PrefsVaultStateStore(context)
            val ours = { key: String -> planted.strings[key]?.startsWith("$LOCATION\n") == true }
            count("vault", store.vault() != null)
            count("key file", store.keyFile(LOCATION) != null)
            count("key file refused", ours("key_file") && store.keyFile(LOCATION) == null)
            val baseline = store.kdfBaseline(LOCATION)
            baseline?.let { assertEquals("a baseline holds the numbers stored", it, storedKdf(planted.strings.getValue("kdf_baseline"))) }
            count("aes baseline", baseline is KdfSettings.AesKdf)
            count("argon2 baseline", baseline is KdfSettings.Argon2)
            count("baseline refused", ours("kdf_baseline") && baseline == null)
            count("dismissed", store.weakWarningDismissedFor(LOCATION) != null)
            count("newest", store.newestSeen(LOCATION) != null)
            count("newest refused", ours("newest_seen") && store.newestSeen(LOCATION) == null)
            assertEquals(planted.keep, store.backupKeep())
            store.biometricOfferShown(LOCATION)
            store.biometricNeedsKeyFile(LOCATION)
            store.keyFileUnlock(LOCATION)
            store.clear(LOCATION)
        }
        val missing = listOf(
            "vault", "key file", "key file refused", "aes baseline", "argon2 baseline", "baseline refused", "dismissed", "newest", "newest refused",
        ).filter { it !in reached }
        assertTrue("never reached: $missing ($reached)", missing.isEmpty())
    }

    @Test
    fun `a stored newest change outside Instant's range reads as nothing stored`() {
        clear(PrefsVaultStateStore.FILE)
        prefs(PrefsVaultStateStore.FILE).edit().putString("newest_seen", "$LOCATION\n${Long.MAX_VALUE}").commit()
        assertNull(PrefsVaultStateStore(context).newestSeen(LOCATION))
    }

    @Test
    fun `the vault state store reads back what it wrote, for its location only`() = runBlocking<Unit> {
        checkAll(PropertyRuns.config(iterations = 500), WRITTEN_VAULT_STATE) { w ->
            clear(PrefsVaultStateStore.FILE)
            val store = PrefsVaultStateStore(context)
            store.saveVault(w.location, w.name, w.readOnly)
            store.saveKeyFile(w.location, w.keyFile, w.name)
            store.saveKdfBaseline(w.location, w.baseline)
            store.saveWeakWarningDismissed(w.location, w.dismissed)
            store.saveNewestSeen(w.location, w.newest)
            store.saveBackupKeep(w.keep)
            store.saveBiometricOfferShown(w.location)
            store.saveBiometricNeedsKeyFile(w.location, w.flag)
            store.saveKeyFileUnlock(w.location, !w.flag)

            val again = PrefsVaultStateStore(context)
            assertEquals(RememberedVault(w.location, w.name, w.readOnly), again.vault())
            assertEquals(RememberedKeyFile(w.keyFile, w.name), again.keyFile(w.location))
            assertEquals(w.baseline, again.kdfBaseline(w.location))
            assertEquals(w.dismissed, again.weakWarningDismissedFor(w.location))
            assertEquals(w.newest, again.newestSeen(w.location))
            assertEquals(w.keep, again.backupKeep())
            assertTrue(again.biometricOfferShown(w.location))
            assertEquals(w.flag, again.biometricNeedsKeyFile(w.location))
            assertEquals(!w.flag, again.keyFileUnlock(w.location))

            // State written for one file never applies to another.
            assertNull(again.keyFile(w.other))
            assertNull(again.kdfBaseline(w.other))
            assertNull(again.weakWarningDismissedFor(w.other))
            assertNull(again.newestSeen(w.other))
            assertEquals(false, again.biometricOfferShown(w.other))
        }
    }

    @Test
    fun `a location with a line feed reads back as nothing stored`() {
        clear(PrefsVaultStateStore.FILE)
        val store = PrefsVaultStateStore(context)
        val location = "content://fake/a\nb.kdbx"
        store.saveKdfBaseline(location, KdfSettings.AesKdf(600_000UL))
        store.saveNewestSeen(location, Instant.ofEpochSecond(1_800_000_000L))
        store.saveKeyFile(location, "content://fake/key", "key")
        assertNull(store.kdfBaseline(location))
        assertNull(store.kdfBaseline("content://fake/a"))
        assertNull(store.newestSeen(location))
        assertNull(store.keyFile(location))
    }

    @Test
    fun `the save marker store reads any stored text and reads back what it wrote`() = runBlocking<Unit> {
        // PrefsSaveMarkerStore's preferences file; the store keeps its name private.
        val markers = "save_markers"
        checkAll(PropertyRuns.config(iterations = 500), PLANTED_MARKER, SHA, SHA) { planted, old, new ->
            clear(markers)
            prefs(markers).edit().putString(Sha256.ofLocation(LOCATION), planted).commit()
            val store = PrefsSaveMarkerStore(context)
            store.get(LOCATION)
            assertTrue(store.isPending(Sha256.ofLocation(LOCATION)))
            store.set(LOCATION, old, new)
            assertEquals(SaveMarker(old, new), PrefsSaveMarkerStore(context).get(LOCATION))
            assertNull(store.get(OTHER))
            store.clear(LOCATION)
            assertNull(store.get(LOCATION))
        }
    }

    @Test
    fun `the clipboard deadline reads any stored value and reads back what it wrote`() = runBlocking<Unit> {
        checkAll(PropertyRuns.config(iterations = 500), Generators.anyText.orNull(0.2), Arb.long().orNull(0.2), Arb.long(), Generators.anyText) { label, at, writtenAt, writtenLabel ->
            clear(ClipboardDeadlineStore.FILE)
            prefs(ClipboardDeadlineStore.FILE).edit().apply {
                label?.let { putString(ClipboardDeadlineStore.KEY_LABEL, it) }
                at?.let { putLong(ClipboardDeadlineStore.KEY_DEADLINE, it) }
            }.commit()
            val store = ClipboardDeadlineStore(context)
            assertEquals(label?.let { ClipboardDeadlineStore.Deadline(at ?: 0L, it) }, store.read())
            store.write(ClipboardDeadlineStore.Deadline(writtenAt, writtenLabel))
            assertEquals(ClipboardDeadlineStore.Deadline(writtenAt, writtenLabel), ClipboardDeadlineStore(context).read())
        }
    }

    @Test
    fun `a stored sealed key file reads as nothing stored exactly when it doesn't decode`() = runBlocking<Unit> {
        val dir = Files.createTempDirectory("sealed").toFile()
        try {
            checkAll(PropertyRuns.config(iterations = 500), SEALED_FILE) { bytes ->
                dir.listFiles()?.forEach { it.delete() }
                File(dir, "${Sha256.ofLocation(LOCATION)}.bin").writeBytes(bytes)
                // A key store without the vault's key, so a decodable file reads as invalidated.
                val store = KeystoreUnlockKeyStore(dir, availability = { UnlockAvailability.READY }, keyStore = { fakeKeyStore(emptyMap()) }, io = Dispatchers.Unconfined)
                val decodes = SealedKey.decode(bytes) != null
                assertEquals(if (decodes) StoredKeyState.INVALIDATED else StoredKeyState.NONE, store.state(LOCATION))
                assertEquals(if (decodes) UnsealResult.Invalidated else UnsealResult.Missing, store.unseal(LOCATION) { Confirmation.Confirmed })
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a sealed key reads back as written`() = runBlocking<Unit> {
        checkAll(PropertyRuns.config(iterations = 500), Arb.byteArray(Arb.constant(12), Arb.byte()), Arb.byteArray(Arb.int(16..200), Arb.byte())) { iv, ciphertext ->
            val decoded = SealedKey.decode(SealedKey(iv, ciphertext).encode())!!
            assertTrue(iv.contentEquals(decoded.iv))
            assertTrue(ciphertext.contentEquals(decoded.ciphertext))
        }
    }

    // What planting writes into the vault state file: a value of the stored type for each key.
    class PlantedVaultState(
        val strings: Map<String, String>,
        val readOnly: Boolean?,
        val keep: Int?,
        val sets: Map<String, Set<String>>,
    ) {
        override fun toString() = "strings=${strings.mapValues { it.value.escaped() }}, readOnly=$readOnly, keep=$keep, sets=$sets"
    }

    class WrittenVaultState(
        val location: String,
        val other: String,
        val name: String,
        val keyFile: String,
        val readOnly: Boolean,
        val baseline: KdfSettings,
        val dismissed: KdfSettings,
        val newest: Instant,
        val keep: Int,
        val flag: Boolean,
    ) {
        override fun toString() = "location=$location other=$other name=${name.escaped()} keyFile=$keyFile readOnly=$readOnly " +
            "baseline=$baseline dismissed=$dismissed newest=$newest keep=$keep flag=$flag"
    }

    private companion object {
        const val LOCATION = "content://com.google.android.apps.docs.storage/document/acc%3D1%3Bdoc%3Dencoded%3Dvault"
        const val OTHER = "content://com.google.android.apps.docs.storage/document/acc%3D1%3Bdoc%3Dencoded%3Dother"

        // A read of stored state: a preferences file or a file's bytes.
        val STORED_READ = Regex("""getSharedPreferences\(|\.readBytes\(\)|readText\(|openFileInput\(""")

        // Each main file that reads stored state, and where this class covers it.
        val COVERED_READERS = sortedMapOf(
            "PrefsVaultStateStore" to "the vault state store properties",
            "PrefsSaveMarkerStore" to "the save marker store property",
            "SensitiveClipboard" to "the clipboard deadline property (ClipboardDeadlineStore)",
            "KeystoreUnlockKeyStore" to "the sealed key properties",
            "FileBackupStore" to "out of scope: backups are encrypted vault bytes, opened by the vault decoder",
        )

        // PrefsVaultStateStore's keys, each planted by PLANTED_VAULT_STATE with the type it stores.
        val STRING_KEYS = listOf("vault_uri", "vault_name", "kdf_baseline", "weak_warning_dismissed", "newest_seen", "key_file")
        val SET_KEYS = listOf("biometric_offer_shown", "biometric_needs_key_file", "key_file_unlock")
        val VAULT_KEYS = (STRING_KEYS + SET_KEYS + listOf("vault_read_only", "backup_keep")).toSet()

        // Numbers as stored text: in range, out of range, signed, padded, empty or not numbers.
        val NUMBER: Arb<String> = Arb.choice(
            Arb.long().map { it.toString() },
            Arb.long().map { it.toULong().toString() },
            Arb.element("", "-1", "0", " 5", "5 ", "1e3", "0x10", "18446744073709551616", "9223372036854775808", "-9223372036854775809", "4294967296"),
            Generators.anyText,
        )

        // The settings the stored text "<location>\n<kdf>" names, read field by field: the
        // rounds of "aes:<rounds>[:...]", or the five fields of
        // "argon2:<variant>:<it>:<mem>:<p>:<v>".
        fun storedKdf(stored: String): KdfSettings? {
            val f = stored.substringAfter('\n').split(':')
            return when (f[0]) {
                "aes" -> f.getOrNull(1)?.toULongOrNull()?.let { KdfSettings.AesKdf(it) }
                "argon2" -> if (f.size != 6) null else KdfSettings.Argon2(
                    Argon2Variant.entries.firstOrNull { it.name == f[1] } ?: return null,
                    f[2].toULongOrNull() ?: return null, f[3].toULongOrNull() ?: return null,
                    f[4].toUIntOrNull() ?: return null, f[5].toUIntOrNull() ?: return null,
                )
                else -> null
            }
        }

        val VARIANT: Arb<String> = Arb.choice(Arb.element("ARGON2D", "ARGON2ID", "argon2d", "", "ARGON2I"), Generators.anyText)

        // KDF text near the stored form "aes:<rounds>" or "argon2:<variant>:<it>:<mem>:<p>:<v>",
        // with the wrong field count as often as the right one.
        val KDF_TEXT: Arb<String> = Arb.choice(
            NUMBER.map { "aes:$it" },
            Arb.bind(VARIANT, Arb.list(NUMBER, 0..6)) { v, n -> (listOf("argon2", v) + n).joinToString(":") },
            // Well formed, so the decoder's success path is reached too.
            Generators.kdfSettings.map { kdf ->
                when (kdf) {
                    is KdfSettings.AesKdf -> "aes:${kdf.rounds}"
                    is KdfSettings.Argon2 -> "argon2:${kdf.variant.name}:${kdf.iterations}:${kdf.memoryBytes}:${kdf.parallelism}:${kdf.version}"
                }
            },
            Generators.anyText,
        )

        // Stored text for a key, with the location prefix the store compares often enough to
        // reach the decoders.
        fun stored(tail: Arb<String>): Arb<String> = Arb.choice(
            tail.map { "$LOCATION\n$it" },
            tail.map { "$OTHER\n$it" },
            Generators.anyText,
            Arb.list(Generators.anyText, 0..4).map { it.joinToString("\n") },
        )

        val PLANTED_VAULT_STATE: Arb<PlantedVaultState> = Arb.bind(
            stored(KDF_TEXT).orNull(0.3),
            stored(KDF_TEXT).orNull(0.3),
            stored(NUMBER).orNull(0.3),
            stored(Arb.list(Generators.anyText, 0..3).map { it.joinToString("\n") }).orNull(0.3),
            Arb.list(Generators.anyText.orNull(0.3), 2..2),
            Arb.boolean().orNull(0.3),
            Arb.int().orNull(0.3),
            Arb.list(Arb.set(Arb.choice(Generators.anyText, Arb.constant(Sha256.ofLocation(LOCATION))), 0..3).orNull(0.3), 3..3),
        ) { baseline, dismissed, newest, keyFile, vault, readOnly, keep, sets ->
            PlantedVaultState(
                strings = listOfNotNull(
                    vault[0]?.let { "vault_uri" to it }, vault[1]?.let { "vault_name" to it }, baseline?.let { "kdf_baseline" to it },
                    dismissed?.let { "weak_warning_dismissed" to it }, newest?.let { "newest_seen" to it }, keyFile?.let { "key_file" to it },
                ).toMap(),
                readOnly = readOnly,
                keep = keep,
                sets = SET_KEYS.zip(sets).mapNotNull { (key, value) -> value?.let { key to it } }.toMap(),
            )
        }

        // Content URI characters: a SAF document URI has no line feed; non-ASCII is
        // percent-encoded.
        val URI_CHAR: Arb<String> = Arb.choice(
            Arb.element(('a'..'z') + ('A'..'Z') + ('0'..'9') + listOf('/', ':', '.', '-', '_', '~', '=', ';', '!', '@')).map { "$it" },
            Arb.element("%3A", "%2F", "%3D", "%3B", "%C3%A9", "%E6%BC%A2", "%20", "%0A", "%25"),
        )
        val URI: Arb<String> = Arb.list(URI_CHAR, 1..40).map { "content://${it.joinToString("")}" }

        val WRITTEN_VAULT_STATE: Arb<WrittenVaultState> = Arb.bind(
            URI, URI, Generators.anyText, URI, Arb.boolean(),
            Generators.kdfSettings, Generators.kdfSettings,
            Arb.long(Instant.MIN.epochSecond..Instant.MAX.epochSecond), Arb.int(), Arb.boolean(),
        ) { location, other, name, keyFile, readOnly, baseline, dismissed, seconds, keep, flag ->
            WrittenVaultState(
                location, if (other == location) "$other/x" else other, name, keyFile, readOnly,
                baseline, dismissed, Instant.ofEpochSecond(seconds), keep, flag,
            )
        }

        val SHA: Arb<String> = Arb.list(Arb.element("0123456789abcdef".toList()), 64..64).map { it.joinToString("") }

        val PLANTED_MARKER: Arb<String> = Arb.choice(
            Generators.anyText,
            Arb.list(Generators.anyText, 0..4).map { it.joinToString(":") },
        )

        // Sealed key file bytes: any bytes, and valid encodings truncated, extended or with one
        // byte changed.
        val SEALED_FILE: Arb<ByteArray> = Arb.choice(
            Arb.byteArray(Arb.int(0..80), Arb.byte()),
            Arb.bind(Arb.byteArray(Arb.int(0..60), Arb.byte()), Arb.int(-40..40), Arb.int(0..100), Arb.byte()) { ct, cut, at, b ->
                val valid = SealedKey(ByteArray(12) { it.toByte() }, ct).encode()
                val sized = if (cut < 0) valid.copyOf(maxOf(0, valid.size + cut)) else valid + ByteArray(cut)
                if (sized.isNotEmpty() && at % 3 == 0) sized.also { it[at % it.size] = b } else sized
            },
        )

        fun String.escaped() = buildString { this@escaped.forEach { c -> if (c.code < 0x20 || c.code in 0xD800..0xDFFF) append("\\u%04x".format(c.code)) else append(c) } }
    }
}
