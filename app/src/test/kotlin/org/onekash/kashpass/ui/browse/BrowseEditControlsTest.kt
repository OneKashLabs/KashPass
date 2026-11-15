package org.onekash.kashpass.ui.browse

import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasAnyDescendant
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.performCustomAccessibilityActionWithLabel
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.testing.TouchModeRule
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalTestApi::class)
@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class BrowseEditControlsTest {

    @get:Rule(order = 0)
    val touchMode = TouchModeRule()

    @get:Rule(order = 1)
    val rule = createComposeRule()

    private val sessions = SessionHolder()
    private val edits = mutableListOf<String>()
    private var adds = 0
    private val deletes = mutableListOf<String>()
    private val permanent = mutableListOf<String>()

    private var saves = 0
    private var closes = 0

    private fun show(bytes: ByteArray, backup: Boolean = false, lastCopy: org.onekash.kashpass.vault.open.LastCopyReason? = null) {
        val result = if (!backup) {
            runBlocking { TestVaults.unlock(bytes) }
        } else {
            val info = org.onekash.kashpass.vault.backup.BackupInfo("b", java.time.Instant.now(), 1, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "")
            runBlocking { FakeVaultOpener().openBackup(TestVaults.LOCATION, info, TestVaults.PASSWORD.toCharArray(), lastCopy) } as org.onekash.kashpass.vault.open.OpenResult.Unlocked
        }
        sessions.set(Unlocked(TestVaults.LOCATION, result.session, result.kdf, false, result.backup))
        val vm = BrowseViewModel(sessions, FakeVaultOpener()) { true }
        rule.setContent {
            KashPassTheme {
                val state by vm.uiState.collectAsState()
                state?.let {
                    BrowseScreen(
                        state = it,
                        onQueryChange = vm::setQuery,
                        onSelectChip = vm::selectChip,
                        onOpenEntry = vm::openEntry,
                        onCloseEntry = vm::closeEntry,
                        onToggleReveal = vm::toggleReveal,
                        onCopy = vm::copy,
                        onDismissWeakWarning = {},
                        onOpenSettings = {},
                        onSubmitSearch = {},
                        onSearchFocused = vm::consumeSearchFocus,
                        onEdit = { id -> edits += id },
                        onAdd = { adds++ },
                        deleteKind = vm::deleteKind,
                        onDelete = { id -> deletes += id },
                        onDeletePermanently = { id -> permanent += id },
                        onSaveAsNewFile = { saves++ },
                        onCloseBackup = { closes++ },
                    )
                }
            }
        }
    }

    @Test
    fun `a saveable vault shows add, and edit in the details sheet`() {
        show(TestVaults.bytes(aesRounds = 1_000UL))
        rule.onNodeWithContentDescription("Add entry").performClick()
        assertEquals(1, adds)
        rule.onNodeWithText("Example Mail").performClick()
        rule.onNodeWithContentDescription("Edit Example Mail").performClick()
        assertEquals(1, edits.size)
        // Delete is on the row's swipe, not in the sheet.
        rule.onNodeWithContentDescription("Delete Example Mail").assertDoesNotExist()
    }

    @Test
    fun `a read-only vault shows neither`() {
        val readOnly = TestVaults.rawXmlVault(
            TestVaults.keePassXml(
                prolog = "<!DOCTYPE KeePassFile>\n",
                entries = "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><String><Key>Title</Key><Value>Only</Value></String></Entry>",
            ),
        )
        show(readOnly)
        rule.onNodeWithContentDescription("Add entry").assertDoesNotExist()
        rule.onNode(hasText("Only") and SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions)).assertDoesNotExist()
        rule.onNodeWithText("Only").performClick()
        rule.onNodeWithContentDescription("Edit Only").assertDoesNotExist()
    }

    @Test
    fun `a permanent delete confirms inline in its row, no dialog`() {
        val noBin = TestVaults.rawXmlVault(
            TestVaults.keePassXml(
                meta = "<RecycleBinEnabled>False</RecycleBinEnabled>",
                entries = "<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID><String><Key>Title</Key><Value>Gone soon</Value></String></Entry>",
            ),
        )
        show(noBin)
        val row = rule.onNode(SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions) and hasText("Gone soon"))
        row.performCustomAccessibilityActionWithLabel("Delete Gone soon")
        rule.onNodeWithText("Delete forever? Can't be undone.").assertExists()
        assertEquals(null, org.robolectric.shadows.ShadowDialog.getLatestDialog())
        rule.onNodeWithText("Cancel").performClick()
        rule.onNodeWithText("Delete forever? Can't be undone.").assertDoesNotExist()
        assertEquals(emptyList<String>(), permanent)
        rule.onNode(SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions) and hasText("Gone soon")).performCustomAccessibilityActionWithLabel("Delete Gone soon")
        rule.onNode(hasText("Delete") and hasClickAction() and hasAnyAncestor(hasAnyDescendant(hasText("Delete forever? Can't be undone.")))).performClick()
        assertEquals(1, permanent.size)
        assertEquals("a permanent delete never stages", emptyList<String>(), deletes)
    }

    @Test
    fun `the last copy shows its age, allows copying, and allows no change`() {
        show(TestVaults.bytes(aesRounds = 1_000UL), backup = true, lastCopy = org.onekash.kashpass.vault.open.LastCopyReason.UNAVAILABLE)
        rule.onNodeWithText("Can't open the vault file. Showing a backup from", substring = true).assertExists()
        rule.onNodeWithText("To make changes, save it as a new file.").assertExists()
        rule.onNodeWithContentDescription("Add entry").assertDoesNotExist()
        rule.onNodeWithText("Save as new file").assertExists()
        rule.onNodeWithText("Example Mail").performClick()
        rule.onNodeWithContentDescription("Copy User name").assertExists()
        rule.onNodeWithContentDescription("Edit Example Mail").assertDoesNotExist()
        rule.onNodeWithContentDescription("Delete Example Mail").assertDoesNotExist()
    }

    @Test
    fun `an open backup shows Save as new file and Close backup`() {
        show(TestVaults.bytes(aesRounds = 1_000UL), backup = true)
        rule.onNodeWithText("Showing a backup from", substring = true).assertExists()
        rule.onNodeWithText("Save as new file").performClick()
        rule.onNodeWithText("Close backup").performClick()
        assertEquals(1, saves)
        assertEquals(1, closes)
        rule.onNodeWithContentDescription("Add entry").assertDoesNotExist()
    }

    @Test
    fun `a vault that can't be saved says so`() {
        show(TestVaults.rawXmlVault(TestVaults.keePassXml(prolog = "<!DOCTYPE KeePassFile>\n")))
        rule.onNodeWithText("KashPass can't save this vault safely. To make changes, use the KeePass desktop app.").assertExists()
    }
}
