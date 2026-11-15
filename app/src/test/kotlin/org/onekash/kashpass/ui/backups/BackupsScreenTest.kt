package org.onekash.kashpass.ui.backups

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTouchHeightIsEqualTo
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasProgressBarRangeInfo
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performCustomAccessibilityActionWithLabel
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.unit.dp
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.format.BackupFormat
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.robolectric.RobolectricTestRunner

@OptIn(ExperimentalTestApi::class)
@RunWith(RobolectricTestRunner::class)
class BackupsScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val calls = mutableListOf<String>()

    private fun backup(n: Int, kind: BackupKind = BackupKind.OPENED) =
        BackupInfo("$n-${kind.name.lowercase()}-${"0".repeat(64)}.kdbx", Instant.parse("2026-10-20T10:00:00Z").plusSeconds(n * 3_600L), 1_000, kind, "0".repeat(64))

    // Newest first, as the store lists them.
    private val three = listOf(backup(3, BackupKind.SAVED), backup(2, BackupKind.BEFORE_SAVE), backup(1))

    private fun show(state: BackupsUiState) = rule.setContent {
        KashPassTheme {
            BackupsScreen(
                state,
                onSelect = { calls += "select:${it.id.substringBefore('-')}" },
                onKeep = { count, confirmed -> calls += "keep:$count:$confirmed" },
                onDismissAsk = { calls += "dismiss" },
                onDelete = { calls += "delete:${it.id.substringBefore('-')}" },
                onUndo = { calls += "undo" },
                onOpenWithPassword = { calls += "password" },
            )
        }
    }

    private fun stepper() = rule.onNode(SemanticsMatcher.keyIsDefined(SemanticsProperties.ProgressBarRangeInfo))

    @Test
    fun `the header names Vault backups and its info explains the copies`() {
        show(BackupsUiState(three))
        rule.onNodeWithText("Vault backups").assertExists()
        rule.onNodeWithText("Encrypted copies kept on this device", substring = true).assertDoesNotExist()
        rule.onNodeWithContentDescription("About Vault backups").performClick()
        rule.onNodeWithText("Encrypted copies of this vault, kept only on this device. Open one to view it or save it as a new file.").assertExists()
    }

    @Test
    fun `each copy shows only its date and time, and a tap opens it`() {
        show(BackupsUiState(three))
        val older = BackupFormat.dateTime(three[1].createdAt)
        rule.onNodeWithText(older).assertExists()
        rule.onNodeWithText("Before save", substring = true).assertDoesNotExist()
        rule.onNodeWithText("kB", substring = true).assertDoesNotExist()
        rule.onNodeWithText(older).performClick()
        assertEquals(listOf("select:2"), calls)
    }

    @Test
    fun `the newest copy has a Newest chip whose tooltip explains it, without opening the copy`() {
        show(BackupsUiState(three))
        rule.onNodeWithText("Newest").assertTouchHeightIsEqualTo(48.dp).performClick()
        rule.onNodeWithText("KashPass always keeps the newest copy, so it can't be deleted. It's used if the vault file can't be opened.").assertExists()
        assertEquals(emptyList<String>(), calls)
    }

    @Test
    fun `Copies to keep explains itself and has no subtitle`() {
        show(BackupsUiState(three, keep = 3))
        rule.onNodeWithText("Copies to keep").assertExists()
        rule.onNodeWithText("The latest version", substring = true).assertDoesNotExist()
        rule.onNodeWithContentDescription("About Copies to keep").performClick()
        rule.onNodeWithText("A copy is kept for every change. Older ones beyond this number are removed.").assertExists()
    }

    @Test
    fun `plus saves at once and minus saves at once when it removes no copy`() {
        show(BackupsUiState(three.take(2), keep = 3))
        rule.onNodeWithContentDescription("Keep more copies").performClick()
        rule.onNodeWithContentDescription("Keep fewer copies").performClick()
        assertEquals(listOf("keep:4:0", "keep:2:0"), calls)
    }

    @Test
    fun `a step down that removes copies shows an inline confirm first that says it can't be undone`() {
        show(BackupsUiState(three, keep = 3))
        rule.onNodeWithContentDescription("Keep fewer copies").performClick()
        rule.onNodeWithText("Removes 1 older copy. Can't be undone.").assertExists()
        assertEquals(emptyList<String>(), calls)
        rule.onNode(hasText("Remove") and hasClickAction()).performClick()
        assertEquals(listOf("keep:2:1"), calls)
    }

    @Test
    fun `TalkBack's adjust goes through the same confirm`() {
        show(BackupsUiState(three, keep = 3))
        stepper().performSemanticsAction(SemanticsActions.SetProgress) { it(1f) }
        rule.onNodeWithText("Removes 2 older copies. Can't be undone.").assertExists()
        assertEquals(emptyList<String>(), calls)
    }

    @Test
    fun `the stepper reads as adjustable from 1 to 30 with the count spoken`() {
        show(BackupsUiState(three, keep = 3))
        stepper().assert(SemanticsMatcher.expectValue(SemanticsProperties.ProgressBarRangeInfo, ProgressBarRangeInfo(3f, 1f..30f, 28)))
        stepper().assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, "3 copies"))
    }

    @Test
    fun `minus stops at 1`() {
        show(BackupsUiState(three.take(1), keep = 1))
        rule.onNodeWithContentDescription("Keep fewer copies").assertIsNotEnabled()
    }

    @Test
    fun `plus stops at 30`() {
        show(BackupsUiState(three.take(1), keep = 30))
        rule.onNodeWithContentDescription("Keep more copies").assertIsNotEnabled()
    }

    @Test
    fun `an unverified save turns Remove off and says when it can go`() {
        show(BackupsUiState(three, keep = 3, pinned = true))
        rule.onNodeWithContentDescription("Keep fewer copies").performClick()
        rule.onNodeWithText("You can remove copies once KashPass finishes saving.").assertExists()
        rule.onNode(hasText("Remove") and hasClickAction()).assertIsNotEnabled()
    }

    @Test
    fun `with a backup open the stepper is off and says why`() {
        show(BackupsUiState(three, keep = 3, isFile = false))
        rule.onNodeWithText("Not available while a backup is open.").assertExists()
        stepper().assert(SemanticsMatcher.keyNotDefined(SemanticsActions.SetProgress))
        rule.onNodeWithContentDescription("Keep fewer copies").assertIsNotEnabled()
    }

    @Test
    fun `a refused change shows the confirm again with the new count`() {
        show(BackupsUiState(three, keep = 3, askKeep = 1))
        rule.onNodeWithText("Removes 2 older copies. Can't be undone.").assertExists()
        rule.onNodeWithText("Cancel").performClick()
        assertEquals(listOf("dismiss"), calls)
    }

    @Test
    fun `while a change applies, the stepper and an open confirm's action are off`() {
        show(BackupsUiState(three, keep = 3, askKeep = 2, applying = true))
        rule.onNodeWithContentDescription("Keep more copies").assertIsNotEnabled()
        rule.onNode(hasText("Remove") and hasClickAction()).assertIsNotEnabled()
    }

    @Test
    fun `no copies reads No backups yet`() {
        show(BackupsUiState(emptyList()))
        rule.onNodeWithText("No backups yet.").assertExists()
    }

    @Test
    fun `a damaged backup is reported`() {
        show(BackupsUiState(emptyList(), damaged = true))
        rule.onNodeWithText("This backup is corrupted.").assertExists()
    }

    @Test
    fun `a slow backup is reported with a way to open it`() {
        show(BackupsUiState(three, slow = true, passwordTarget = PasswordTarget(three[1], null)))
        rule.onNodeWithText("This backup takes much longer to unlock than the file.").assertExists()
        rule.onNodeWithText("Open with its password").performClick()
        assertEquals(listOf("password"), calls)
    }

    @Test
    fun `a copy under an older password says so, with a way to open it`() {
        show(BackupsUiState(three, failed = true, oldPassword = true, passwordTarget = PasswordTarget(three[1], null)))
        rule.onNodeWithText("This backup couldn't be opened. It may use an older vault password.").assertExists()
        rule.onNodeWithText("Open with its password").performClick()
        assertEquals(listOf("password"), calls)
    }

    @Test
    fun `any other failure says only that it couldn't be opened`() {
        show(BackupsUiState(three, failed = true))
        rule.onNodeWithText("This backup couldn't be opened.").assertExists()
        rule.onNodeWithText("Open with its password").assertDoesNotExist()
    }

    @Test
    fun `a bar shows while the list loads, and the stepper waits for the count`() {
        show(BackupsUiState(null))
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
        rule.onNodeWithContentDescription("Keep more copies").assertIsNotEnabled()
    }

    @Test
    fun `every copy but the newest offers Delete to TalkBack, named by its date`() {
        show(BackupsUiState(three))
        val older = BackupFormat.dateTime(three[1].createdAt)
        rule.onNode(hasText(older) and SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions))
            .performCustomAccessibilityActionWithLabel("Delete backup from $older")
        assertEquals(listOf("delete:2"), calls)
        rule.onNode(hasText(BackupFormat.dateTime(three[0].createdAt)) and SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions)).assertDoesNotExist()
    }

    @Test
    fun `no copy offers Delete while a save is unverified`() {
        show(BackupsUiState(three, pinned = true))
        rule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions)).assertCountEquals(0)
    }

    @Test
    fun `a staged delete shows Backup deleted with Undo`() {
        show(BackupsUiState(three, undo = 1))
        rule.onNodeWithText("Backup deleted").assertExists()
        rule.onNodeWithText("Undo").performClick()
        assertEquals(listOf("undo"), calls)
    }

    @Test
    fun `a refused delete says why`() {
        show(BackupsUiState(three, notice = BackupsNotice.FAILED))
        rule.onNodeWithText("Couldn't delete the backup. Try again.").assertExists()
    }

    @Test
    fun `a delete refused for an unverified save says when it can go`() {
        show(BackupsUiState(three, notice = BackupsNotice.PINNED))
        rule.onNodeWithText("You can remove copies once KashPass finishes saving.").assertExists()
    }

    @Test
    fun `a refused delete's reason shows even though the sheet clears it once shown`() {
        var state by mutableStateOf(BackupsUiState(three, notice = BackupsNotice.FAILED))
        rule.setContent {
            KashPassTheme {
                BackupsScreen(state, onSelect = {}, onNoticeShown = { state = state.copy(notice = null) })
            }
        }
        rule.waitForIdle()
        rule.onNodeWithText("Couldn't delete the backup. Try again.").assertExists()
    }

    @Test
    fun `no copy offers Delete while a copy is opening or a backup is open`() {
        show(BackupsUiState(three, opening = true))
        rule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions)).assertCountEquals(0)
    }

    @Test
    fun `with a backup open no copy offers Delete`() {
        show(BackupsUiState(three, isFile = false))
        rule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions)).assertCountEquals(0)
    }
}
