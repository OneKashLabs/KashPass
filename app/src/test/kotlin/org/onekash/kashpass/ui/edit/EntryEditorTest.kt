package org.onekash.kashpass.ui.edit

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import org.junit.Assert.assertEquals
import androidx.compose.ui.test.assertAll
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.testing.TouchModeRule
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.edit.GroupChoice
import org.onekash.kashpass.vault.save.SaveResult
import org.onekash.kashpass.vault.storage.Writability
import org.onekash.kashpass.vault.testing.TestVaults
import kotlinx.coroutines.runBlocking
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.test.hasProgressBarRangeInfo
import org.junit.Assert.assertTrue

@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class EntryEditorTest {

    @get:Rule(order = 0)
    val touchMode = TouchModeRule()

    @get:Rule(order = 1)
    val rule = createComposeRule()

    private val calls = mutableListOf<String>()
    private val password = TextFieldState("hunter2")
    private val groups = listOf(GroupChoice("root", "Database", true), GroupChoice("g1", "Email", false), GroupChoice("g2", "Work / Email", false))

    private fun show(state: EditorUiState) {
        rule.setContent {
            KashPassTheme {
                EntryEditor(
                    state = state,
                    password = password,
                    onTitle = { calls += "title:$it" },
                    onUserName = {},
                    onUrl = {},
                    onNotes = {},
                    onGroup = { calls += "group:$it" },
                    onLength = {},
                    onSymbols = { calls += "symbols:$it" },
                    onGenerate = { calls += "generate" },
                    onSave = { calls += "save" },
                    onClose = { calls += "close" },
                )
            }
        }
    }

    private fun editing(saving: Boolean = false, problem: SaveResult? = null) =
        EditorUiState("id", "Bank", "alice", "https://bank", "notes", null, emptyList(), saving = saving, problem = problem)

    @Test
    fun `the editor shows the five fields with the password masked and a reveal toggle`() {
        show(editing())
        rule.onNodeWithText("Bank").assertExists()
        rule.onNodeWithText("alice").assertExists()
        // The secure field marks itself as a password (masked on screen, never shown to autofill as
        // text).
        rule.onNode(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password)).assertExists()
        rule.onNodeWithContentDescription("Show password").performClick()
        rule.onNodeWithContentDescription("Hide password").assertExists()
        rule.onNodeWithText("https://bank").performScrollTo().assertExists()
        rule.onNodeWithText("notes").performScrollTo().assertExists()
        rule.onNodeWithText("Edit entry").assertExists()
    }

    @Test
    fun `only the password is masked`() {
        show(editing())
        rule.onNodeWithContentDescription("Show Title").assertDoesNotExist()
        rule.onNodeWithContentDescription("Show Notes").assertDoesNotExist()
        assertEquals(1, rule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password)).fetchSemanticsNodes().size)
    }

    @Test
    fun `generate, save and close reach their actions`() {
        show(editing())
        rule.onNodeWithText("Generate").performClick()
        rule.onNodeWithTag(SAVE_TAG).performClick()
        rule.onNodeWithContentDescription("Close without saving").performClick()
        assertEquals(listOf("generate", "save", "close"), calls)
    }

    @Test
    fun `after a first close with changes the close button reads Discard and discards on tap`() {
        show(editing().copy(discardConfirm = true))
        rule.onNodeWithContentDescription("Close without saving").assertDoesNotExist()
        rule.onNodeWithText("Discard?").performClick()
        assertEquals(listOf("close"), calls)
    }

    @Test
    fun `while saving every control is disabled and Saving shows in the top bar`() {
        show(editing(saving = true))
        val saving = rule.onNodeWithText("Saving…").fetchSemanticsNode().boundsInRoot
        val title = rule.onNodeWithText("Title").fetchSemanticsNode().boundsInRoot
        assertTrue("Saving… sits above the form, in the top bar", saving.bottom <= title.top)
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
        rule.onNodeWithTag(SAVE_TAG).assertDoesNotExist()
        rule.onNodeWithText("Generate").assertIsNotEnabled()
        rule.onNodeWithContentDescription("Close without saving").assertIsNotEnabled()
    }

    @Test
    fun `a refusal is explained in place`() {
        val vault = runBlocking { TestVaults.unlock(TestVaults.bytes(aesRounds = 1_000UL)) }.session.opened
        show(editing(problem = SaveResult.NotWritable(vault, Writability.NO_WRITE_GRANT)))
        rule.onNodeWithText("KashPass can only read this file. Choose it again to allow changes.").assertExists()
        rule.onNodeWithTag(SAVE_TAG).assertIsEnabled()
    }

    @Test
    fun `a new entry picks its group from the vault's groups`() {
        show(EditorUiState(null, "", "me", "", "", "g1", groups))
        rule.onNodeWithText("New entry").assertExists()
        rule.onNodeWithText("Email").performClick()
        rule.onNodeWithText("Work / Email").performClick()
        assertEquals(listOf("group:g2"), calls)
    }

    @Test
    @Config(qualifiers = "w411dp-h891dp", fontScale = 2.0f)
    fun `at 200 percent font size every field and action can be reached`() {
        show(EditorUiState(null, "T", "U", "https://u", "N", null, groups))
        rule.onNodeWithTag(SAVE_TAG).assertExists()
        for (text in listOf("T", "U", "Generate", "Include symbols", "https://u", "N")) rule.onNodeWithText(text).performScrollTo().assertExists()
    }


    private fun editorInfoOf(view: android.view.View): android.view.inputmethod.EditorInfo {
        val info = android.view.inputmethod.EditorInfo()
        rule.runOnIdle { view.onCreateInputConnection(info) }
        return info
    }

    @Test
    fun `the password and fields the vault protects tell the keyboard not to learn, unmasked`() {
        lateinit var view: android.view.View
        rule.setContent {
            view = androidx.compose.ui.platform.LocalView.current
            KashPassTheme {
                EntryEditor(
                    state = editing().copy(protectedKeys = setOf("Notes")), password = password,
                    onTitle = {}, onUserName = {}, onUrl = {}, onNotes = {}, onGroup = {}, onLength = {}, onSymbols = {},
                    onGenerate = {}, onSave = {}, onClose = {},
                )
            }
        }
        val noLearning = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        rule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password))[0].performScrollTo().performClick()
        assertEquals(noLearning, editorInfoOf(view).imeOptions and noLearning)
        rule.onNodeWithText("notes").performScrollTo().performClick()
        val notes = editorInfoOf(view)
        assertEquals(noLearning, notes.imeOptions and noLearning)
        assertEquals(0, notes.inputType and android.text.InputType.TYPE_TEXT_FLAG_AUTO_CORRECT)
        assertEquals(1, rule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password)).fetchSemanticsNodes().size)
        rule.onNodeWithText("Bank").performScrollTo().performClick()
        assertEquals(0, editorInfoOf(view).imeOptions and noLearning)
    }

    @Test
    fun `every editor field opts out of autofill`() {
        show(editing())
        val fields = rule.onAllNodes(androidx.compose.ui.test.hasSetTextAction()).fetchSemanticsNodes()
        assertEquals(5, fields.size)
        rule.onAllNodes(androidx.compose.ui.test.hasSetTextAction()).assertAll(androidx.compose.ui.test.SemanticsMatcher.expectValue(androidx.compose.ui.semantics.SemanticsProperties.ContentDataType, androidx.compose.ui.autofill.ContentDataType.None))
    }
}
