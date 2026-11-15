package org.onekash.kashpass.ui.browse

import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.backup.BackupKind
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.index.Chip
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class ReadOnlyBannerTest {

    @get:Rule
    val rule = createComposeRule()

    private var saves = 0
    private var closes = 0
    private var accepts = 0
    private val backup = BackupInfo("1-opened-${"0".repeat(64)}.kdbx", Instant.parse("2026-10-19T10:00:00Z"), 100, BackupKind.OPENED, "0".repeat(64))

    private fun show(
        reason: ReadOnlyReason? = ReadOnlyReason.BACKUP,
        olderThan: Instant? = null,
        working: Boolean = false,
        now: Instant = backup.createdAt.plusSeconds(86_400),
        withBackup: Boolean = true,
        replaces: String? = null,
    ) = rule.setContent {
        KashPassTheme {
            BrowseScreen(
                state = BrowseUiState(
                    chips = listOf(Chip.All), selectedChip = Chip.All, query = "", searching = false, letterHeaders = true, groupInRows = true,
                    rows = emptyList(), vaultEmpty = true, weakKdf = null, openEntry = null, revealed = emptySet(),
                    readOnly = reason?.let { ReadOnlyBanner(it, backup.takeIf { withBackup }) },
                    olderThan = olderThan,
                    working = working,
                    now = now,
                ),
                onQueryChange = {}, onSelectChip = {}, onOpenEntry = {}, onCloseEntry = {}, onToggleReveal = {}, onCopy = { CopyOutcome.COPIED },
                onDismissWeakWarning = {}, onOpenSettings = {}, onSubmitSearch = {}, onSearchFocused = {},
                onSaveAsNewFile = { saves++ },
                saveAsNewReplaces = replaces,
                onCloseBackup = { closes++ },
                onAcceptOlderFile = { accepts++ },
            )
        }
    }

    @Test
    fun `a backup says how old it is and how to make changes, with Save as new file and Close backup`() {
        show()
        rule.onNodeWithText("Showing a backup from yesterday.").assertExists()
        rule.onNodeWithText("To make changes, save it as a new file.").assertExists()
        rule.onNodeWithText("Save as new file").performClick()
        rule.onNodeWithText("Close backup").performClick()
        assertEquals(1, saves)
        assertEquals(1, closes)
    }

    @Test
    fun `a corrupted file's copy shows Save as new file and no Close backup`() {
        show(ReadOnlyReason.LAST_COPY_CORRUPTED)
        rule.onNodeWithText("The vault file is corrupted. Showing a backup from yesterday.").assertExists()
        rule.onNodeWithText("To make changes, save it as a new file.").assertExists()
        rule.onNodeWithText("Close backup").assertDoesNotExist()
        rule.onNodeWithText("Save as new file").performClick()
        assertEquals(1, saves)
    }

    @Test
    fun `the copy of a file damaged after its header names KeePass 2's Repair Mode import`() {
        show(ReadOnlyReason.LAST_COPY_CORRUPTED_AFTER_HEADER)
        rule.onNodeWithText("The vault file is damaged. Showing a backup from yesterday. KeePass 2's Repair Mode import can recover the rest.").assertExists()
        rule.onNodeWithText("Save as new file").assertExists()
        rule.onNodeWithText("Close backup").assertDoesNotExist()
    }

    @Test
    fun `an unavailable file's copy shows Save as new file and no Close backup`() {
        show(ReadOnlyReason.LAST_COPY)
        rule.onNodeWithText("Can't open the vault file. Showing a backup from yesterday.").assertExists()
        rule.onNodeWithText("To make changes, save it as a new file.").assertExists()
        rule.onNodeWithText("Close backup").assertDoesNotExist()
        rule.onNodeWithText("Save as new file").performClick()
        assertEquals(1, saves)
    }

    @Test
    fun `a file whose app allows reading only says so and offers Save as new file, not Close backup`() {
        show(ReadOnlyReason.PROVIDER_READ_ONLY, withBackup = false)
        rule.onNodeWithText("This file's app allows reading only.").assertExists()
        rule.onNodeWithText("To make changes, save it as a new file.").assertExists()
        rule.onNodeWithText("Close backup").assertDoesNotExist()
        rule.onNodeWithText("Save as new file").performClick()
        assertEquals(1, saves)
    }

    @Test
    fun `a file opened from another app says so and offers Save as new file, not Close backup`() {
        show(ReadOnlyReason.OPENED_FROM_APP, withBackup = false)
        rule.onNodeWithText("Opened from another app, read-only.").assertExists()
        rule.onNodeWithText("To make changes, save it as a new file.").assertExists()
        rule.onNodeWithText("Close backup").assertDoesNotExist()
        rule.onNodeWithText("Save as new file").performClick()
        assertEquals(1, saves)
    }

    @Test
    fun `a file opened from another app names the remembered vault the new file replaces, before the tap`() {
        show(ReadOnlyReason.OPENED_FROM_APP, withBackup = false, replaces = "Passwords.kdbx")
        rule.onNodeWithText("Saves an editable copy and makes it your vault in place of Passwords.kdbx.").assertExists()
        rule.onNodeWithText("To make changes, save it as a new file.").assertDoesNotExist()
        assertEquals(0, saves)
        rule.onNodeWithText("Save as new file").performClick()
        assertEquals(1, saves)
    }

    @Test
    fun `a file KashPass can't save safely has no Save as new file`() {
        show(ReadOnlyReason.DOCTYPE, withBackup = false)
        rule.onNodeWithText("KashPass can't save this vault safely", substring = true).assertExists()
        rule.onNodeWithText("Save as new file").assertDoesNotExist()
    }

    @Test
    fun `a backup from minutes ago says how many minutes`() {
        show(ReadOnlyReason.LAST_COPY, now = backup.createdAt.plusSeconds(5 * 60 + 10))
        rule.onNodeWithText("Can't open the vault file. Showing a backup from 5 minutes ago.").assertExists()
    }

    @Test
    fun `a backup under a minute old is from just now`() {
        show(now = backup.createdAt.plusSeconds(20))
        rule.onNodeWithText("Showing a backup from just now.").assertExists()
    }

    @Test
    fun `while the app works on the file, Save as new file and Close backup are disabled`() {
        show(working = true)
        rule.onNodeWithText("Save as new file").assertIsNotEnabled()
        rule.onNodeWithText("Close backup").assertIsNotEnabled()
    }

    @Test
    fun `an older file is named with the newer date and Use this version accepts it`() {
        show(reason = null, olderThan = Instant.parse("2026-06-01T10:00:00Z"))
        rule.onNodeWithText("This file is older than the last version KashPass saw", substring = true).assertExists()
        rule.onNodeWithText("Use this version").performClick()
        assertEquals(1, accepts)
    }

    @Test
    fun `while the app works on the file, Use this version is disabled`() {
        show(reason = null, olderThan = Instant.parse("2026-06-01T10:00:00Z"), working = true)
        rule.onNodeWithText("Use this version").assertIsNotEnabled()
    }
}
