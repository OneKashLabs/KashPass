package org.onekash.kashpass.ui.save

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import java.time.Instant
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.format.SaveChoice
import org.onekash.kashpass.ui.format.SaveProblem
import org.onekash.kashpass.session.FileDetails
import org.onekash.kashpass.testing.TouchModeRule
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.testing.FakeVaultSaver
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.test.hasProgressBarRangeInfo
import androidx.compose.ui.test.assertIsNotEnabled

@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class SaveProblemSheetTest {

    @get:Rule(order = 0)
    val touchMode = TouchModeRule()

    @get:Rule(order = 1)
    val rule = createComposeRule()

    private val vault = runBlocking { TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL)) }.session.opened
    private val prepared = FakeVaultSaver().prepared(vault)
    private val choices = mutableListOf<SaveChoice>()
    private var detailsAsked = 0

    private fun show(result: SaveResult, details: FileDetails? = null, working: Boolean = false) = rule.setContent {
        KashPassTheme {
            SaveProblemSheet(result, "Passwords.kdbx", details, onChoice = { choices += it }, onShowDetails = { detailsAsked++ }, working = working)
        }
    }

    @Test
    fun `a conflict names the file and shows copy, reload and keep editing`() {
        show(SaveResult.Conflict(vault, prepared))
        rule.onNodeWithText("Passwords.kdbx changed since you opened it. Your edits are not saved.").assertExists()
        rule.onNodeWithText("Retry").assertDoesNotExist()
        rule.onNodeWithText("Save as copy").performClick()
        rule.onNodeWithText("Reload and lose my edits").performClick()
        rule.onNodeWithText("Keep editing").performClick()
        assertEquals(listOf(SaveChoice.SAVE_AS_COPY, SaveChoice.RELOAD, SaveChoice.KEEP_EDITING), choices)
    }

    @Test
    fun `an unverified write points to Vault backups and shows no retry`() {
        show(SaveResult.VerifyFailed(vault, prepared))
        rule.onNodeWithText("Not saved: KashPass couldn't confirm the save. Your previous version is kept in Vault backups.").assertExists()
        rule.onNodeWithText("Retry").assertDoesNotExist()
    }

    @Test
    fun `a failed write shows retry`() {
        show(SaveResult.WriteFailed(vault, prepared))
        rule.onNodeWithText("Not saved. The file is unchanged.").assertExists()
        rule.onNodeWithText("Retry").performClick()
        assertEquals(listOf(SaveChoice.RETRY), choices)
    }

    @Test
    fun `file details show what is known and omit the rest`() {
        show(SaveResult.Conflict(vault, prepared))
        rule.onNodeWithText("File details").performClick()
        assertEquals(1, detailsAsked)
    }

    @Test
    fun `loaded details show the opened and current file`() {
        show(SaveResult.Conflict(vault, prepared), FileDetails(Instant.parse("2026-10-20T08:00:00Z"), 2_048, null, 4_096))
        rule.onNodeWithText("Opened:", substring = true).assertExists()
        rule.onNodeWithText("Now: 4.1 kB").assertExists()
    }

    @Test
    fun `while a choice runs the sheet shows progress and every choice is disabled`() {
        show(SaveResult.WriteFailed(vault, prepared), working = true)
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
        rule.onNodeWithText("Retry").assertIsNotEnabled()
        rule.onNodeWithText("Save as copy").assertIsNotEnabled()
        rule.onNodeWithText("Keep editing").assertIsNotEnabled()
    }
}
