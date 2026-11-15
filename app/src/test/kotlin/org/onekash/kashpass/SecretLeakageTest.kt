package org.onekash.kashpass

import android.net.Uri
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performImeAction
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import java.io.ByteArrayInputStream
import java.io.File
import androidx.lifecycle.ViewModelProvider
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.lock.LockViewModel
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLog

/**
 * Follows one set of secrets through the real path (choose the file, a wrong password, the right
 * password typed into the field, search, reveal, copy, edit with a generated password, lock) and
 * checks that none of them reaches a log or a file in the app's data directory. Every vault value
 * here is a test sentinel.
 */
@OptIn(ExperimentalTestApi::class)
@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class SecretLeakageTest {

    @get:Rule(order = 0)
    val overlay = org.onekash.kashpass.testing.OverlayPermissionRule()

    @get:Rule(order = 1)
    val rule = createAndroidComposeRule<MainActivity>()

    @Test
    fun `no password, entry value, title or field name reaches logs or app files`() {
        ShadowLog.clear()
        val bytes = TestVaults.browserVault()
        shadowOf(rule.activity.contentResolver).registerInputStreamSupplier(VAULT) { ByteArrayInputStream(bytes) }
        // What the system picker's result does: LockRoute hands the URI to the view model.
        rule.runOnUiThread { ViewModelProvider(rule.activity)[LockViewModel::class.java].onPicked(VAULT) }
        rule.waitUntilAtLeastOneExists(hasText("Vault password"), TIMEOUT)

        rule.onNodeWithText("Vault password").performTextInput(WRONG_PASSWORD)
        rule.onNodeWithText("Vault password").performImeAction()
        rule.waitUntilAtLeastOneExists(hasText("Wrong vault password", substring = true), TIMEOUT)
        rule.onNodeWithText("Vault password").performTextInput(TestVaults.PASSWORD)
        rule.onNodeWithText("Vault password").performImeAction()
        rule.waitUntilAtLeastOneExists(hasText("Example Mail"), TIMEOUT)

        // A search whose only match is a notes snippet, then one for the entry to open.
        rule.onNode(hasSetTextAction()).performTextInput("recovery hint")
        rule.waitUntilAtLeastOneExists(hasText("Notes · Recovery hint", substring = true), TIMEOUT)
        rule.onNode(hasSetTextAction()).performTextClearance()
        rule.onNode(hasSetTextAction()).performTextInput("Example")
        rule.onNodeWithText("Example Mail").performClick()
        rule.onNodeWithContentDescription("Show Password").performClick()
        rule.onNodeWithContentDescription("Show otp").performScrollTo().performClick()
        rule.onNodeWithContentDescription("Copy Password").performClick()
        rule.onNodeWithContentDescription("Copy Account ID").performScrollTo().performClick()
        rule.onNodeWithContentDescription("Copy Notes").performScrollTo().performClick()
        rule.waitForIdle()
        // Edit: a new title, a generated password, a save the provider refuses (this test file
        // has no documents provider behind it), then close and confirm the discard.
        rule.onNodeWithContentDescription("Edit Example Mail").performClick()
        rule.waitUntilAtLeastOneExists(hasText("Edit entry"), TIMEOUT)
        rule.onNodeWithText("Example Mail").performTextClearance()
        rule.onNodeWithText("Title").performTextInput(EDITED_TITLE)
        rule.onNodeWithText("Generate").performClick()
        rule.onNodeWithText("Save").performClick()
        rule.waitUntilAtLeastOneExists(hasText("can't be reached", substring = true), TIMEOUT)
        rule.onNodeWithContentDescription("Close without saving").performClick()
        rule.onNodeWithText("Discard?").performClick()
        rule.waitUntilAtLeastOneExists(hasContentDescription("Settings"), TIMEOUT)
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("Lock vault").performClick()
        rule.waitUntilAtLeastOneExists(hasText("Vault password"), TIMEOUT)

        val logs = ShadowLog.getLogs().joinToString("\n") { "${it.tag} ${it.msg} ${it.throwable?.stackTraceToString().orEmpty()}" }
        val files = File(rule.activity.applicationInfo.dataDir).walk().filter { it.isFile }.toList()
        val leaks = SECRETS.flatMap { secret ->
            val inLogs = if (logs.contains(secret)) listOf("logcat") else emptyList()
            inLogs + files.filter { it.readBytes().contains(secret) }.map { it.relativeTo(File(rule.activity.applicationInfo.dataDir)).path }
                .map { "$it holds \"$secret\"" }
        }
        assertEquals(emptyList<String>(), leaks)
    }

    @Test
    fun `a key-file unlock leaves no key-file bytes, password or vault value in logs or app files`() {
        ShadowLog.clear()
        val vault = TestVaults.bytes(keyPart = TestVaults.KEY_FILE_PART)
        val resolver = shadowOf(rule.activity.contentResolver)
        resolver.registerInputStreamSupplier(KEY_VAULT) { ByteArrayInputStream(vault) }
        resolver.registerInputStreamSupplier(KEY_FILE) { ByteArrayInputStream(TestVaults.KEY_FILE) }
        val lock = ViewModelProvider(rule.activity)[LockViewModel::class.java]
        rule.runOnUiThread { lock.onPicked(KEY_VAULT) }
        rule.waitUntilAtLeastOneExists(hasText("Vault password"), TIMEOUT)
        // What the key-file picker's result does.
        rule.runOnUiThread {
            lock.startKeyFilePick()
            lock.onKeyFilePicked(KEY_FILE)
        }
        rule.waitUntilAtLeastOneExists(hasContentDescription("Key file: ${KEY_FILE.lastPathSegment}, remove"), TIMEOUT)

        rule.onNodeWithText("Vault password").performTextInput(WRONG_PASSWORD)
        rule.onNodeWithText("Vault password").performImeAction()
        rule.waitUntilAtLeastOneExists(hasText("Wrong vault password or key file.", substring = true), TIMEOUT)
        rule.onNodeWithText("Vault password").performTextInput(TestVaults.PASSWORD)
        rule.onNodeWithText("Vault password").performImeAction()
        rule.waitUntilAtLeastOneExists(hasText("Example Mail"), TIMEOUT)
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("Lock vault").performClick()
        rule.waitUntilAtLeastOneExists(hasText("Vault password"), TIMEOUT)

        val logs = ShadowLog.getLogs().joinToString("\n") { "${it.tag} ${it.msg} ${it.throwable?.stackTraceToString().orEmpty()}" }
        val dataDir = File(rule.activity.applicationInfo.dataDir)
        val files = dataDir.walk().filter { it.isFile }.toList()
        // The key file's hex groups as the file holds them, plus the raw key part and the file.
        val keyText = String(TestVaults.KEY_FILE, Charsets.UTF_8)
        val hexGroups = Regex("[0-9A-F]{8}").findAll(keyText.substringAfter("<Data")).map { it.value }.toList()
        val secrets = hexGroups + listOf(TestVaults.PASSWORD, WRONG_PASSWORD, "mail-pass", "bank-pass")
        val leaks = secrets.flatMap { secret ->
            val inLogs = if (logs.contains(secret)) listOf("logcat holds \"$secret\"") else emptyList()
            inLogs + files.filter { it.readBytes().contains(secret) }.map { "${it.relativeTo(dataDir).path} holds \"$secret\"" }
        } + listOf(TestVaults.KEY_FILE_PART, TestVaults.KEY_FILE).flatMap { raw ->
            files.filter { it.readBytes().containsBytes(raw) }.map { "${it.relativeTo(dataDir).path} holds key-file bytes" }
        }
        // Eight groups of key data and the Hash attribute.
        assertEquals(9, hexGroups.size)
        assertEquals(emptyList<String>(), leaks)
    }

    @Test
    fun `revealing and copying a referenced password leaves the resolved values out of logs and app files`() {
        ShadowLog.clear()
        val bytes = TestVaults.referenceVault()
        shadowOf(rule.activity.contentResolver).registerInputStreamSupplier(REF_VAULT) { ByteArrayInputStream(bytes) }
        rule.runOnUiThread { ViewModelProvider(rule.activity)[LockViewModel::class.java].onPicked(REF_VAULT) }
        rule.waitUntilAtLeastOneExists(hasText("Vault password"), TIMEOUT)
        rule.onNodeWithText("Vault password").performTextInput(TestVaults.PASSWORD)
        rule.onNodeWithText("Vault password").performImeAction()
        // The first row A to Z.
        rule.waitUntilAtLeastOneExists(hasText("Café Noir"), TIMEOUT)
        rule.onNode(hasSetTextAction()).performTextInput("holder")
        rule.waitUntilAtLeastOneExists(hasText("Reference Holder"), TIMEOUT)
        rule.onNodeWithText("Reference Holder").performClick()
        // The user name shows resolved once the entry is resolved.
        rule.waitUntilAtLeastOneExists(hasText("bob"), TIMEOUT)
        rule.onNodeWithContentDescription("Show Password").performClick()
        rule.waitUntilAtLeastOneExists(hasText("bank-pass"), TIMEOUT)
        rule.onNodeWithContentDescription("Copy User name").performClick()
        rule.onNodeWithContentDescription("Copy Password").performClick()
        rule.waitUntilAtLeastOneExists(hasText("Password inserts another entry's password. Copy it?"), TIMEOUT)
        rule.onNodeWithText("Copy").performClick()
        rule.onNodeWithContentDescription("Copy Notes").performScrollTo().performClick()
        rule.onNodeWithText("Copy").performScrollTo().performClick()
        rule.waitForIdle()
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("Lock vault").performClick()
        rule.waitUntilAtLeastOneExists(hasText("Vault password"), TIMEOUT)

        val logs = ShadowLog.getLogs().joinToString("\n") { "${it.tag} ${it.msg} ${it.throwable?.stackTraceToString().orEmpty()}" }
        val dataDir = File(rule.activity.applicationInfo.dataDir)
        val files = dataDir.walk().filter { it.isFile }.toList()
        val secrets = listOf(TestVaults.PASSWORD, "bank-pass", "pw bank-pass", "Reference Holder", "Example Bank", "bob", "{REF:")
        val leaks = secrets.flatMap { secret ->
            val inLogs = if (logs.contains(secret)) listOf("logcat holds \"$secret\"") else emptyList()
            inLogs + files.filter { it.readBytes().contains(secret) }.map { "${it.relativeTo(dataDir).path} holds \"$secret\"" }
        }
        assertEquals(emptyList<String>(), leaks)
    }

    private fun ByteArray.containsBytes(needle: ByteArray): Boolean =
        (0..size - needle.size).any { start -> needle.indices.all { this[start + it] == needle[it] } }

    private fun ByteArray.contains(text: String): Boolean = listOf(Charsets.UTF_8, Charsets.UTF_16LE, Charsets.UTF_16BE).any { cs ->
        val needle = text.toByteArray(cs)
        (0..size - needle.size).any { start -> needle.indices.all { this[start + it] == needle[it] } }
    }

    private companion object {
        val VAULT: Uri = Uri.parse("content://org.onekash.kashpass.test.drive/document/browser")
        val REF_VAULT: Uri = Uri.parse("content://org.onekash.kashpass.test.drive/document/references")
        val KEY_VAULT: Uri = Uri.parse("content://org.onekash.kashpass.test.drive/document/with-key-file")
        val KEY_FILE: Uri = Uri.parse("content://org.onekash.kashpass.test.drive/document/vault.keyx")
        const val WRONG_PASSWORD = "wrong-sentinel-7Q"
        const val EDITED_TITLE = "edited-sentinel-9X"
        const val TIMEOUT = 60_000L

        // The master password, a wrong one, and the vault's values, titles, user names and
        // custom field names (see TestVaults.browserVault).
        val SECRETS = listOf(
            TestVaults.PASSWORD,
            WRONG_PASSWORD,
            EDITED_TITLE,
            "mail-pass",
            "JBSWY3DPEHPK3PXP",
            "A-1234",
            "Account ID",
            "Recovery hint",
            "Example Mail",
            "alice",
            "router-pass",
            "old-bank-pass",
        )
    }
}
