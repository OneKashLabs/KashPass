package org.onekash.kashpass.ui.lock

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.isHeading
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.unit.toSize
import androidx.compose.ui.test.performImeAction
import androidx.compose.ui.test.performTextInput
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.components.KASH_TAG
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.doc.DecodeFailure
import org.onekash.kashpass.vault.header.UnsupportedReason
import org.onekash.kashpass.vault.policy.KdfRejection
import org.onekash.kashpass.vault.policy.KdfSetting
import org.onekash.kashpass.vault.storage.StorageFailure
import org.onekash.kashpass.vault.storage.maxVaultBytes
import org.robolectric.RobolectricTestRunner
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.test.hasProgressBarRangeInfo

@RunWith(RobolectricTestRunner::class)
class LockScreenTest {

    private val limitMib = maxVaultBytes(Runtime.getRuntime().maxMemory()) / (1024 * 1024)

    @get:Rule
    val rule = createComposeRule()

    private var chooses = 0
    private var unlocks = 0
    private var retries = 0
    private var addKeyFiles = 0
    private var removeKeyFiles = 0
    private var opensOffered = 0
    private var cancelsIncoming = 0
    private var cancelsUnlock = 0
    private var back: androidx.activity.OnBackPressedDispatcher? = null
    private val password = TextFieldState()

    private fun show(
        state: LockUiState,
        finishingSave: Boolean = false,
        lostChange: org.onekash.kashpass.session.LostChange? = null,
        fontScale: Float? = null,
        biometricButton: String = "",
        onOpenLastCopy: () -> Unit = {},
    ) = rule.setContent {
        back = androidx.activity.compose.LocalOnBackPressedDispatcherOwner.current?.onBackPressedDispatcher
        val density = androidx.compose.ui.platform.LocalDensity.current
        androidx.compose.runtime.CompositionLocalProvider(
            androidx.compose.ui.platform.LocalDensity provides androidx.compose.ui.unit.Density(density.density, fontScale ?: density.fontScale),
        ) {
            KashPassTheme {
                LockScreen(
                    state = state,
                    password = password,
                    onChooseFile = { chooses++ },
                    onUnlock = { unlocks++ },
                    onRetry = { retries++ },
                    finishingSave = finishingSave,
                    lostChange = lostChange,
                    biometricButton = biometricButton,
                    onAddKeyFile = { addKeyFiles++ },
                    onRemoveKeyFile = { removeKeyFiles++ },
                    onOpenOffered = { opensOffered++ },
                    onCancelIncoming = { cancelsIncoming++ },
                    onOpenLastCopy = onOpenLastCopy,
                    onCancelUnlock = { cancelsUnlock++ },
                )
            }
        }
    }

    @Test
    fun `a file opened from another app says how to edit it, offers Make it your vault and Cancel, and unlocks`() {
        show(LockUiState(vaultName = "Shared.kdbx", showPasswordField = true, openedFromApp = true))
        rule.onNodeWithText("Shared.kdbx").assertExists()
        rule.onNodeWithText("Opened from another app, read-only. Make it your vault to edit and save.").assertExists()
        rule.onNodeWithText("Choose a different file").assertDoesNotExist()
        rule.onNodeWithText("Choose vault file").assertDoesNotExist()
        rule.onNodeWithText("Making it your vault replaces", substring = true).assertDoesNotExist()
        rule.onNodeWithText("Make it your vault").performScrollTo().performClick()
        rule.onNodeWithText("Cancel").performScrollTo().performClick()
        rule.onNodeWithText("Unlock").performScrollTo().performClick()
        assertEquals(1, chooses)
        assertEquals(1, cancelsIncoming)
        assertEquals(1, unlocks)
    }


    @Test
    fun `a file opened from another app names the vault that making it your vault replaces`() {
        show(LockUiState(vaultName = "Shared.kdbx", showPasswordField = true, openedFromApp = true, openedInPlaceOf = "Passwords.kdbx"))
        rule.onNodeWithText("Making it your vault replaces Passwords.kdbx.").assertExists()
    }
    @Test
    fun `a file offered in place of the remembered vault shows Open this file and Cancel, no password field`() {
        show(LockUiState(vaultName = "Shared.kdbx", offered = true, offeredInPlaceOf = "Passwords.kdbx"))
        rule.onNodeWithText("Another app sent this file. Opening it makes it your vault in place of Passwords.kdbx.").assertExists()
        rule.onNodeWithText("Vault password").assertDoesNotExist()
        rule.onNodeWithText("Open this file").performScrollTo().performClick()
        rule.onNodeWithText("Cancel").performScrollTo().performClick()
        assertEquals(1, opensOffered)
        assertEquals(1, cancelsIncoming)
        assertEquals(0, chooses)
    }

    @Test
    fun `a file offered with no vault remembered waits for Open this file or Cancel`() {
        show(LockUiState(vaultName = "Shared.kdbx", offered = true))
        rule.onNodeWithText("Another app sent this file. Opening it makes it your vault.").assertExists()
        rule.onNodeWithText("Vault password").assertDoesNotExist()
        rule.onNodeWithText("Choose vault file").assertDoesNotExist()
        rule.onNodeWithText("Open this file").performScrollTo().performClick()
        rule.onNodeWithText("Cancel").performScrollTo().performClick()
        assertEquals(1, opensOffered)
        assertEquals(1, cancelsIncoming)
        assertEquals(0, chooses)
    }

    // The laid-out text of the node showing [text].
    private fun layout(text: String): androidx.compose.ui.text.TextLayoutResult {
        val results = mutableListOf<androidx.compose.ui.text.TextLayoutResult>()
        rule.onNodeWithText(text, useUnmergedTree = true)
            .performSemanticsAction(androidx.compose.ui.semantics.SemanticsActions.GetTextLayoutResult) { it(results) }
        return results.single()
    }

    // Every line of [text] shows whole inside its button: no edge, ellipsis or line limit cuts it.
    private fun assertFits(text: String) {
        val label = rule.onNodeWithText(text, useUnmergedTree = true).fetchSemanticsNode()
        val button = rule.onNodeWithText(text).fetchSemanticsNode()
        val laid = layout(text)
        assertEquals("$text is shortened with an ellipsis", false, (0 until laid.lineCount).any { laid.isLineEllipsized(it) })
        assertEquals("$text has lines a line limit hides", false, laid.didOverflowHeight)
        val lines = laid.multiParagraph
        val left = label.positionInRoot.x
        val top = label.positionInRoot.y
        // Unclipped: the test window is short, so a button can sit partly below it.
        val bounds = androidx.compose.ui.geometry.Rect(button.positionInRoot, button.size.toSize())
        val message = "$text: lines ${lines.width} x ${lines.height} at ($left, $top), button $bounds"
        assertEquals(message, true, top >= bounds.top && top + lines.height <= bounds.bottom + 0.5f)
        assertEquals(message, true, left >= bounds.left && left + lines.widestLine() <= bounds.right + 0.5f)
    }

    private fun androidx.compose.ui.text.MultiParagraph.widestLine(): Float =
        (0 until lineCount).maxOf { getLineWidth(it) }

    // Native graphics measure text with real fonts; the default mode doesn't.
    @Test
    @org.robolectric.annotation.GraphicsMode(org.robolectric.annotation.GraphicsMode.Mode.NATIVE)
    fun `Choose vault file fits its button on one line`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Damaged))
        val text = layout("Choose vault file")
        assertEquals(1, text.lineCount)
        assertFits("Choose vault file")
    }

    // Native graphics measure text with real fonts; the default mode doesn't.
    @Test
    @org.robolectric.annotation.GraphicsMode(org.robolectric.annotation.GraphicsMode.Mode.NATIVE)
    fun `the main button grows instead of cutting its label at a large font size`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Damaged), fontScale = 2f)
        assertFits("Choose vault file")
    }

    // Native graphics measure text with real fonts; the default mode doesn't.
    @Test
    @org.robolectric.annotation.GraphicsMode(org.robolectric.annotation.GraphicsMode.Mode.NATIVE)
    fun `the biometric button grows instead of cutting its label at a large font size`() {
        show(LockUiState(vaultName = "v", showPasswordField = true, biometricOn = true), fontScale = 2f, biometricButton = "Unlock with fingerprint")
        assertFits("Unlock with fingerprint")
    }

    @Test
    fun `while a save finishes behind it the lock screen shows only that`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true), finishingSave = true)
        rule.onNodeWithText("Finishing the save…").assertExists()
        rule.onNodeWithText("Vault password").assertDoesNotExist()
        rule.onNodeWithText("Unlock").assertDoesNotExist()
        rule.onNodeWithText("Passwords.kdbx").assertDoesNotExist()
    }

    @Test
    fun `a change lost at the lock is reported with the right certainty`() {
        show(LockUiState(vaultName = "v", showPasswordField = true), lostChange = org.onekash.kashpass.session.LostChange.NOT_SAVED)
        rule.onNodeWithText("Your last change wasn't saved.").assertExists()
    }

    @Test
    fun `a change cut off by the wait cap is reported as maybe not saved`() {
        show(LockUiState(vaultName = "v", showPasswordField = true), lostChange = org.onekash.kashpass.session.LostChange.MAYBE_NOT_SAVED)
        rule.onNodeWithText("Your last change may not have been saved.").assertExists()
    }

    @Test
    fun `first run shows Kash, one heading, Choose vault file and the short footnote`() {
        show(LockUiState())
        rule.onNodeWithTag(KASH_TAG).assertExists()
        rule.onNodeWithText("Open your KeePass vault").assert(isHeading())
        rule.onNodeWithText("No internet access.").assertExists()
        rule.onNodeWithText("KashPass").assertDoesNotExist()
        rule.onNodeWithText("No vault yet").assertDoesNotExist()
        rule.onNodeWithText("Vault password").assertDoesNotExist()
        rule.onNodeWithText("Choose vault file").performClick()
        assertEquals(1, chooses)
    }

    @Test
    fun `a no-vault state with a problem keeps the app-name layout and no Kash`() {
        show(LockUiState(message = LockMessage.ChooseFailed))
        assertNoKashWithVaultHeading()
    }

    @Test
    fun `an offered first file shows no Kash`() {
        show(LockUiState(offered = true))
        assertNoKashWithVaultHeading()
    }

    @Test
    fun `a first file being checked shows no Kash`() {
        show(LockUiState(checking = true))
        assertNoKashWithVaultHeading()
    }

    @Test
    fun `a save ending behind the lock shows no Kash`() {
        show(LockUiState(), finishingSave = true)
        assertNoKashWithVaultHeading()
    }

    @Test
    fun `a lost change shows no Kash`() {
        show(LockUiState(), lostChange = org.onekash.kashpass.session.LostChange.NOT_SAVED)
        assertNoKashWithVaultHeading()
    }

    @Test
    fun `a save cut off at the lock shows no Kash`() {
        show(LockUiState(lostCutOffSave = true))
        assertNoKashWithVaultHeading()
    }

    @Test
    fun `a password field or a backup to open with no vault name shows no Kash`() {
        show(LockUiState(showPasswordField = true, backupTarget = org.onekash.kashpass.vault.backup.BackupInfo(
            "b", java.time.Instant.EPOCH, 10L, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "00",
        )))
        assertNoKashWithVaultHeading()
    }

    @Test
    fun `an unlock running with no vault name shows no Kash`() {
        show(LockUiState(unlocking = true))
        assertNoKashWithVaultHeading()
    }

    @Test
    fun `a chosen vault shows no Kash, and the app name is a heading`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true))
        rule.onNodeWithTag(KASH_TAG).assertDoesNotExist()
        rule.onNodeWithText("KashPass").assert(isHeading())
    }

    // Every no-vault state other than first run keeps the app name, "No vault yet" and no Kash.
    private fun assertNoKashWithVaultHeading() {
        rule.onNodeWithTag(KASH_TAG).assertDoesNotExist()
        rule.onNodeWithText("Open your KeePass vault").assertDoesNotExist()
        rule.onNodeWithText("KashPass").assert(isHeading())
        rule.onNodeWithText("No vault yet").assertExists()
    }

    @Test
    fun `a ready vault shows its name, the password field, Unlock and Choose a different file, no Backups`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true))
        rule.onNodeWithText("Passwords.kdbx").assertExists()
        rule.onNodeWithText("Locked").assertExists()
        rule.onNodeWithText("Choose a different file").performClick()
        assertEquals(1, chooses)
        rule.onNodeWithText("Unlock").performScrollTo().performClick()
        assertEquals(1, unlocks)
        // Backups live in Settings, behind an unlock.
        rule.onNodeWithText("Backups").assertDoesNotExist()
    }

    @Test
    fun `problems and a wrong password are announced to screen readers`() {
        show(LockUiState(vaultName = "Passwords.kdbx", message = LockMessage.Damaged))
        rule.onNode(SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite)).assertExists()
    }

    @Test
    fun `a wrong password is announced to screen readers`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true, message = LockMessage.WrongPassword))
        rule.onNode(SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Polite), useUnmergedTree = true).assertExists()
    }

    @Test
    fun `Choose a different file is disabled while unlocking`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true, unlocking = true))
        rule.onNodeWithText("Choose a different file").assertIsNotEnabled()
    }

    @Test
    fun `Done on the keyboard unlocks`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true))
        rule.onNodeWithText("Vault password").performTextInput("secret")
        rule.onNodeWithText("Vault password").performImeAction()
        assertEquals(1, unlocks)
    }

    @Test
    fun `the reveal toggle has a content description`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true))
        rule.onNodeWithContentDescription("Show password").performClick()
        rule.onNodeWithContentDescription("Hide password").assertExists()
    }

    @Test
    fun `a wrong password shows the message under the field`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true, message = LockMessage.WrongPassword))
        rule.onNodeWithText("Wrong vault password. Check Caps Lock and try again.").assertExists()
    }

    @Test
    fun `while unlocking the button reads Unlocking and is disabled`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true, unlocking = true))
        rule.onNodeWithText("Unlocking…").assertIsNotEnabled()
        rule.onNodeWithText("Unlocking…").performClick()
        assertEquals(0, unlocks)
    }

    @Test
    fun `Back while unlocking cancels the attempt`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true, unlocking = true))
        rule.runOnIdle { back!!.onBackPressed() }
        rule.runOnIdle { assertEquals(1, cancelsUnlock) }
    }

    @Test
    fun `Back is left to the system when no attempt runs`() {
        show(LockUiState(vaultName = "Passwords.kdbx", showPasswordField = true))
        rule.runOnIdle { assertEquals(false, back!!.hasEnabledCallbacks()) }
        assertEquals(0, cancelsUnlock)
    }

    @Test
    fun `a switch of KDF type with less work names the work in units of KeePass 2's defaults`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Refused(KdfRejection.Weakened(KdfSetting.WORK_UNITS, 100_000UL, 1_000UL))))
        rule.onNodeWithText("Key derivation work in units of KeePass 2's defaults went from 100 to 1", substring = true).assertExists()
    }

    @Test
    fun `work that differs by under a thousandth of a unit shows both numbers to three decimals`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Refused(KdfRejection.Weakened(KdfSetting.WORK_UNITS, 1_001UL, 1_000UL))))
        rule.onNodeWithText("went from 1.001 to 1)", substring = true).assertExists()
    }

    @Test
    fun `a refused file explains why, says the password wasn't used, and hides the field`() {
        show(
            LockUiState(
                vaultName = "Passwords.kdbx",
                message = LockMessage.Refused(KdfRejection.Weakened(KdfSetting.AES_ROUNDS, 600_000UL, 1UL)),
            ),
        )
        rule.onNodeWithText("KashPass won't open this file").assertExists()
        rule.onNodeWithText("AES-KDF iterations went from 600,000 to 1", substring = true).assertExists()
        rule.onNodeWithText("Your password wasn't used.").assertExists()
        rule.onNodeWithText("Vault password").assertDoesNotExist()
    }

    @Test
    fun `an out-of-bounds setting names the setting and its value`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Refused(KdfRejection.OutOfBounds(KdfSetting.ARGON2_ITERATIONS, 0UL))))
        rule.onNodeWithText("Argon2 iterations is 0", substring = true).assertExists()
    }

    @Test
    fun `a 64-bit out-of-bounds value is shown as written, not wrapped negative`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Refused(KdfRejection.OutOfBounds(KdfSetting.AES_ROUNDS, ULong.MAX_VALUE))))
        rule.onNodeWithText("AES-KDF iterations is 18,446,744,073,709,551,615", substring = true).assertExists()
    }

    @Test
    fun `an unsupported KDBX 3 file says which KeePass versions upgrade it, and how`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Unsupported(UnsupportedReason.FormatVersion(3, 1))))
        rule.onNodeWithText("KashPass can't open this file").assertExists()
        rule.onNodeWithText(
            "It's a KDBX 3.1 file. KashPass opens KDBX 4 files. KeePass 2.57 or later saves every vault as KDBX 4: open it " +
                "there and save it. In KeePass 2.35 to 2.56, choose Argon2 under File, Database Settings, " +
                "Security, then save.",
        ).assertExists()
    }

    @Test
    fun `a format setting KeePass 2 can't read either says so, and the password wasn't used`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Unsupported(UnsupportedReason.InnerStream(4, keyChecked = false))))
        rule.onNodeWithText("It uses a format setting that current KeePass 2 versions don't know either, perhaps from a newer version.").assertExists()
        rule.onNodeWithText("Your password wasn't used.").assertExists()
    }

    @Test
    fun `an unknown inner stream found after the password check omits the unused-password line`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Unsupported(UnsupportedReason.InnerStream(4, keyChecked = true))))
        rule.onNodeWithText("It uses a format setting that current KeePass 2 versions don't know either, perhaps from a newer version.").assertExists()
        rule.onNodeWithText("Your password wasn't used.").assertDoesNotExist()
    }

    @Test
    fun `a platform failure says the device can't run the encryption`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Failed(DecodeFailure.PLATFORM)))
        rule.onNodeWithText("This device can't run the encryption this vault needs. KeePass 2 on a computer opens it.").assertExists()
    }

    @Test
    fun `an internal failure says the problem is in KashPass, not the file`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Failed(DecodeFailure.INTERNAL)))
        rule.onNodeWithText("KashPass couldn't open this vault because of a problem in KashPass, not in the file. KeePass 2 on a computer opens it.").assertExists()
        rule.onNodeWithText("Your password wasn't used.").assertDoesNotExist()
    }

    @Test
    fun `a file newer than KDBX 4 is not told to upgrade`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Unsupported(UnsupportedReason.FormatVersion(5, 0))))
        rule.onNodeWithText("It's a KDBX 5.0 file, a newer format than KashPass opens.").assertExists()
    }

    @Test
    fun `an unreadable file explains the fix and shows Retry`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Unreadable(StorageFailure.IO_FAILURE)))
        rule.onNodeWithText("make it available offline", substring = true).assertExists()
        rule.onNodeWithText("Retry").performClick()
        assertEquals(1, retries)
    }

    @Test
    fun `a file that didn't respond says so and offers Retry`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Unreadable(StorageFailure.TIMED_OUT)))
        rule.onNodeWithText("The file didn't respond in 30 seconds.", substring = true).assertExists()
        rule.onNodeWithText("Retry").performClick()
        assertEquals(1, retries)
    }

    @Test
    fun `the last copy is offered by its age, and the main button chooses the vault file`() {
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "1-opened-${"0".repeat(64)}.kdbx", java.time.Instant.now().minusSeconds(5 * 60 + 10), 100, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0".repeat(64),
        )
        show(LockUiState(vaultName = "v", message = LockMessage.Unreadable(StorageFailure.PERMISSION_REVOKED), lastCopy = LastCopy(backup, org.onekash.kashpass.vault.open.LastCopyReason.UNAVAILABLE)))
        rule.onNodeWithText("KashPass no longer has access to this file.").assertExists()
        rule.onNodeWithText("Open backup from 5 minutes ago").assertExists()
        rule.onNodeWithText("Choose vault file").assertExists()
        rule.onNodeWithText("Choose a different file").assertDoesNotExist()
        rule.onNodeWithText("A copy kept on this device", substring = true).assertDoesNotExist()
    }

    @Test
    fun `a missing file says it may have moved`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Unreadable(StorageFailure.NOT_FOUND)))
        rule.onNodeWithText("KashPass can't find this file. It may have been moved, renamed or deleted.").assertExists()
        rule.onNodeWithText("Choose vault file").assertExists()
    }

    @Test
    fun `opening a backup names its age and the password to use`() {
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "1-opened-${"0".repeat(64)}.kdbx", java.time.Instant.now().minusSeconds(5 * 60 + 10), 100, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0".repeat(64),
        )
        show(LockUiState(vaultName = "v", showPasswordField = true, backupTarget = backup))
        rule.onNodeWithText("Opening the backup from 5 minutes ago. Use the vault password from that time.").assertExists()
    }

    @Test
    fun `too large names the limit and KeePass 2 and has no Retry`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Unreadable(StorageFailure.TOO_LARGE)))
        rule.onNodeWithText("This vault is too large for this device's memory (the limit here is $limitMib MiB). KeePass 2 on a computer opens it.").assertExists()
        rule.onNodeWithText("Retry").assertDoesNotExist()
    }

    @Test
    fun `a damaged backup is reported while the backup is the target`() {
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "1-opened-${"0".repeat(64)}.kdbx", java.time.Instant.parse("2026-10-19T10:00:00Z"), 100, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0".repeat(64),
        )
        show(LockUiState(vaultName = "v", showPasswordField = true, backupTarget = backup, message = LockMessage.BackupDamaged))
        rule.onNodeWithText("This backup is corrupted.").assertExists()
    }

    @Test
    fun `damaged file message`() {
        show(LockUiState(vaultName = "v", message = LockMessage.Damaged))
        rule.onNodeWithText("This file is corrupted or isn't a KeePass vault.").assertExists()
    }

    @Test
    fun `damage after the header names KeePass 2's Repair Mode import and offers the last copy`() {
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "1-opened-${"0".repeat(64)}.kdbx", java.time.Instant.parse("2026-10-19T10:00:00Z"), 100, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0".repeat(64),
        )
        show(LockUiState(vaultName = "v", message = LockMessage.DamagedAfterHeader, lastCopy = LastCopy(backup, org.onekash.kashpass.vault.open.LastCopyReason.CORRUPTED_AFTER_HEADER)))
        rule.onNodeWithText(
            "This vault file is damaged. KeePass 2 on a computer can recover what's readable: open any database, then File, Import..., KeePass KDBX (2.x) (Repair Mode).",
        ).assertExists()
        rule.onNodeWithText("This file is corrupted or isn't a KeePass vault.").assertDoesNotExist()
        rule.onNodeWithText("Open backup from", substring = true).assertExists()
    }

    @Test
    fun `a corrupted file shows its last copy`() {
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "1-opened-${"0".repeat(64)}.kdbx", java.time.Instant.parse("2026-10-19T10:00:00Z"), 100, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0".repeat(64),
        )
        show(LockUiState(vaultName = "v", message = LockMessage.Damaged, lastCopy = LastCopy(backup, org.onekash.kashpass.vault.open.LastCopyReason.CORRUPTED)))
        rule.onNodeWithText("This file is corrupted or isn't a KeePass vault.").assertExists()
        rule.onNodeWithText("Open backup from", substring = true).assertExists()
        rule.onNodeWithText("Retry").assertDoesNotExist()
        rule.onNodeWithText("A save was cut off", substring = true).assertDoesNotExist()
    }

    @Test
    fun `a last copy that fails to open is not shown again`() {
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "1-opened-${"0".repeat(64)}.kdbx", java.time.Instant.parse("2026-10-19T10:00:00Z"), 100, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0".repeat(64),
        )
        show(
            LockUiState(
                vaultName = "v", showPasswordField = true, message = LockMessage.BackupDamaged, backupTarget = backup,
                lastCopy = LastCopy(backup, org.onekash.kashpass.vault.open.LastCopyReason.CORRUPTED),
            ),
        )
        rule.onNodeWithText("This backup is corrupted.").assertExists()
        rule.onNodeWithText("Open backup from", substring = true).assertDoesNotExist()
    }

    @Test
    fun `a save cut off before the lock is reported`() {
        show(LockUiState(vaultName = "v", showPasswordField = true, lostCutOffSave = true))
        rule.onNodeWithText("Your last change on this device wasn't saved.").assertExists()
    }

    @Test
    fun `the lock-time line replaces the cut-off note`() {
        show(LockUiState(vaultName = "v", showPasswordField = true, lostCutOffSave = true), lostChange = org.onekash.kashpass.session.LostChange.NOT_SAVED)
        rule.onNodeWithText("Your last change wasn't saved.").assertExists()
        rule.onNodeWithText("Your last change on this device wasn't saved.").assertDoesNotExist()
    }

    @Test
    fun `not enough memory message`() {
        show(LockUiState(vaultName = "v", message = LockMessage.NotEnoughMemory))
        rule.onNodeWithText("This vault needs more memory than this device allows.").assertExists()
    }

    @Test
    fun `not enough memory offers the last copy by its age`() {
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "1-opened-${"0".repeat(64)}.kdbx", java.time.Instant.now().minusSeconds(5 * 60 + 10), 100, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0".repeat(64),
        )
        var opened = 0
        show(LockUiState(vaultName = "v", message = LockMessage.NotEnoughMemory, lastCopy = LastCopy(backup, org.onekash.kashpass.vault.open.LastCopyReason.UNAVAILABLE)), onOpenLastCopy = { opened++ })
        rule.onNodeWithText("This vault needs more memory than this device allows.").assertExists()
        rule.onNodeWithText("Open backup from 5 minutes ago").performScrollTo().performClick()
        assertEquals(1, opened)
        rule.onNodeWithText("Retry").assertDoesNotExist()
    }

    @Test
    fun `taking the password copies it out and leaves the field empty`() {
        val state = TextFieldState("pässwörd")
        val taken = state.takePassword()
        assertArrayEquals("pässwörd".toCharArray(), taken)
        assertEquals("", state.text.toString())
    }

    @Test
    fun `a much slower file shows the warning and Unlock anyway`() {
        show(LockUiState(vaultName = "v", showPasswordField = true, slow = org.onekash.kashpass.vault.policy.SlowKdf(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(100_000_000UL), 100, 166)))
        rule.onNodeWithText("This file now takes about 100 times longer to unlock than before. If you didn't change its settings in KeePass 2, don't continue.").assertExists()
        rule.onNodeWithText("Unlock anyway").performScrollTo().performClick()
        assertEquals(1, unlocks)
    }

    @Test
    fun `a first open with very slow settings says how they compare with KeePass 2's default`() {
        show(LockUiState(vaultName = "v", showPasswordField = true, slow = org.onekash.kashpass.vault.policy.SlowKdf(org.onekash.kashpass.vault.header.KdfSettings.AesKdf(100_000_000UL), null, 166)))
        rule.onNodeWithText("This file's unlock settings are about 166 times KeePass 2's default. Unlocking can take minutes.").assertExists()
    }

    @Test
    fun `the vault password opts out of autofill and keyboard learning`() {
        lateinit var view: android.view.View
        rule.setContent {
            view = androidx.compose.ui.platform.LocalView.current
            KashPassTheme { LockScreen(state = LockUiState(vaultName = "v", showPasswordField = true), password = password, onChooseFile = {}, onUnlock = {}, onRetry = {}) }
        }
        rule.onNode(androidx.compose.ui.test.hasSetTextAction()).assert(androidx.compose.ui.test.SemanticsMatcher.expectValue(androidx.compose.ui.semantics.SemanticsProperties.ContentDataType, androidx.compose.ui.autofill.ContentDataType.None))
        rule.onNode(androidx.compose.ui.test.hasSetTextAction()).performClick()
        val info = android.view.inputmethod.EditorInfo()
        rule.runOnIdle { view.onCreateInputConnection(info) }
        val flag = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        assertEquals(flag, info.imeOptions and flag)
    }

    @Test
    fun `with fingerprint unlock on, the main button uses it and Use password has its own button`() {
        var biometrics = 0
        var passwords = 0
        rule.setContent {
            KashPassTheme {
                LockScreen(
                    state = LockUiState(vaultName = "v", showPasswordField = true, biometricOn = true),
                    password = password, onChooseFile = {}, onUnlock = {}, onRetry = {},
                    onBiometric = { biometrics++ }, onUsePassword = { passwords++ },
                    biometricButton = "Use fingerprint", biometricName = "Fingerprint unlock",
                )
            }
        }
        rule.onNodeWithText("Vault password").assertDoesNotExist()
        rule.onNodeWithText("Use fingerprint").performScrollTo().performClick()
        rule.onNodeWithText("Use password").performScrollTo().performClick()
        assertEquals(1, biometrics)
        assertEquals(1, passwords)
    }

    @Test
    fun `fingerprint unlock set up with a key file requests the key file and offers Add key file`() {
        rule.setContent {
            KashPassTheme {
                LockScreen(
                    state = LockUiState(vaultName = "v", showPasswordField = true, biometricOn = true, passwordChosen = true, keyFileNeeded = true),
                    password = password, onChooseFile = {}, onUnlock = {}, onRetry = {},
                    biometricButton = "Use fingerprint", biometricName = "Fingerprint unlock",
                    onAddKeyFile = { addKeyFiles++ },
                )
            }
        }
        rule.onNodeWithText("Add the key file to use fingerprint unlock.").assertExists()
        rule.onNodeWithText("Add key file").performScrollTo().performClick()
        assertEquals(1, addKeyFiles)
    }

    @Test
    fun `each reason it turned off is said once above the field`() {
        val reasons = mapOf(
            org.onekash.kashpass.session.TurnOffReason.NEW_BIOMETRIC to "Fingerprint unlock is off because a new fingerprint or face was added to this device. Unlock with your vault password to turn it back on.",
            org.onekash.kashpass.session.TurnOffReason.LOCKED_OUT to "Fingerprint unlock is off after too many failed tries. Unlock with your vault password.",
            org.onekash.kashpass.session.TurnOffReason.PASSWORD_CHANGED to "The vault password changed in KeePass 2. Unlock with the new password, then turn fingerprint unlock back on in Settings.",
            org.onekash.kashpass.session.TurnOffReason.SCREEN_LOCK_REMOVED to "Fingerprint unlock is off because this device no longer has a screen lock.",
            org.onekash.kashpass.session.TurnOffReason.UNRECOVERABLE_KEY to "Fingerprint unlock was turned off because this device's key store couldn't use its key. Turn it on again in Settings.",
        )
        var current by androidx.compose.runtime.mutableStateOf(org.onekash.kashpass.session.TurnOffReason.NEW_BIOMETRIC)
        rule.setContent {
            KashPassTheme {
                LockScreen(
                    state = LockUiState(vaultName = "v", showPasswordField = true, turnedOff = current),
                    password = password, onChooseFile = {}, onUnlock = {}, onRetry = {},
                    biometricButton = "Use fingerprint", biometricName = "Fingerprint unlock",
                )
            }
        }
        for ((reason, text) in reasons) {
            current = reason
            rule.onNodeWithText(text).assertExists()
        }
    }

    @Test
    fun `while the first file is checked, a spinner replaces Choose vault file`() {
        show(LockUiState(checking = true))
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
        rule.onNodeWithText("Choose vault file").assertDoesNotExist()
    }

    @Test
    fun `while another file is checked, a spinner replaces Unlock`() {
        show(LockUiState(vaultName = "v", checking = true, showPasswordField = true))
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
        rule.onNodeWithText("Unlock").assertDoesNotExist()
    }

    @Test
    fun `while a fingerprint unlock runs, its button shows a spinner and is disabled`() {
        show(LockUiState(vaultName = "v", showPasswordField = true, biometricOn = true, unlocking = true), biometricButton = "Unlock with fingerprint")
        rule.onNodeWithText("Unlocking…").assertIsNotEnabled()
        rule.onNodeWithText("Unlock with fingerprint").assertDoesNotExist()
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
    }

    @Test
    fun `Add key file shows under the password field and opens the picker`() {
        show(LockUiState(vaultName = "v", showPasswordField = true))
        rule.onNodeWithText("Add key file").performScrollTo().performClick()
        assertEquals(1, addKeyFiles)
        val field = rule.onNodeWithText("Vault password").fetchSemanticsNode().boundsInRoot
        val button = rule.onNodeWithText("Add key file").fetchSemanticsNode().boundsInRoot
        assertEquals(true, button.top >= field.bottom)
    }

    @Test
    fun `a chosen key file shows as a chip with its name, and its remove button clears it`() {
        show(LockUiState(vaultName = "v", showPasswordField = true, keyFileName = "vault.keyx"))
        rule.onNodeWithText("Add key file").assertDoesNotExist()
        // TalkBack reads the name once, in the remove button's description.
        rule.onNodeWithText("vault.keyx", useUnmergedTree = true).assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.HideFromAccessibility))
        rule.onNodeWithContentDescription("Key file: vault.keyx, remove").performScrollTo().performClick()
        assertEquals(1, removeKeyFiles)
    }

    @Test
    fun `neither Add key file nor the chip shows without the password field`() {
        show(LockUiState(vaultName = "v", showPasswordField = false, keyFileName = "vault.keyx"))
        rule.onNodeWithText("Add key file").assertDoesNotExist()
        rule.onNodeWithContentDescription("Key file: vault.keyx, remove").assertDoesNotExist()
    }

    @Test
    fun `with a key file set a wrong result names both`() {
        show(LockUiState(vaultName = "v", showPasswordField = true, keyFileName = "vault.keyx", message = LockMessage.WrongPassword))
        rule.onNodeWithText("Wrong vault password or key file.").assertExists()
        rule.onNodeWithText("Check Caps Lock", substring = true).assertDoesNotExist()
    }

    @Test
    fun `a wrong password without the chip of a vault last unlocked with a key file requests it`() {
        show(LockUiState(vaultName = "v", showPasswordField = true, keyFileUnlockedBefore = true, message = LockMessage.WrongPassword))
        rule.onNodeWithText("This vault was unlocked with a key file before. Add it again.").assertExists()
        rule.onNodeWithText("Check Caps Lock", substring = true).assertDoesNotExist()
    }

    @Test
    fun `with the chip attached a vault last unlocked with a key file names both`() {
        show(
            LockUiState(
                vaultName = "v", showPasswordField = true, keyFileName = "vault.keyx", keyFileUnlockedBefore = true,
                message = LockMessage.WrongPassword,
            ),
        )
        rule.onNodeWithText("Wrong vault password or key file.").assertExists()
    }

    @Test
    fun `each key file problem has its own message and keeps the password field`() {
        val cases = listOf(
            LockMessage.KeyFileUnreadable(StorageFailure.NOT_FOUND) to "Key file not found. Choose it again.",
            LockMessage.KeyFileUnreadable(StorageFailure.PERMISSION_REVOKED) to "KashPass no longer has access to the key file. Choose it again.",
            LockMessage.KeyFileUnreadable(StorageFailure.TOO_LARGE) to "This key file is too large for this device's memory (the limit here is $limitMib MiB). KeePass 2 on a computer reads it.",
            LockMessage.KeyFileUnreadable(StorageFailure.IO_FAILURE) to "Couldn't read the key file. If it's stored online, check your connection, then try again.",
            LockMessage.KeyFileUnreadable(StorageFailure.TIMED_OUT) to "The key file didn't respond in 30 seconds. If it's stored online, check your connection, then try again.",
            LockMessage.KeyFileDamaged to "Key file is damaged.",
            LockMessage.KeyFileTooLarge to "This key file is too large to read on this device. Choose another key file.",
            LockMessage.NotKeyFile to "This is a KeePass vault, not a key file.",
            LockMessage.KeyFileMismatch to "The key file didn't match. Choose the right key file or use your vault password.",
        )
        var current by androidx.compose.runtime.mutableStateOf(cases.first().first as LockMessage)
        rule.setContent {
            KashPassTheme {
                LockScreen(
                    state = LockUiState(vaultName = "v", showPasswordField = true, keyFileName = "vault.keyx", message = current),
                    password = password,
                    onChooseFile = {},
                    onUnlock = {},
                    onRetry = {},
                )
            }
        }
        for ((message, text) in cases) {
            current = message
            rule.onNodeWithText(text).assertExists()
            rule.onNodeWithText("Vault password").assertExists()
            rule.onNodeWithContentDescription("Key file: vault.keyx, remove").assertExists()
            rule.onNodeWithText("Retry").assertDoesNotExist()
        }
    }

    @Test
    fun `a key file problem shows while a backup is the target`() {
        val backup = org.onekash.kashpass.vault.backup.BackupInfo(
            "b", java.time.Instant.now(), 1, org.onekash.kashpass.vault.backup.BackupKind.OPENED, "0",
        )
        show(LockUiState(vaultName = "v", showPasswordField = true, backupTarget = backup, message = LockMessage.KeyFileDamaged))
        rule.onNodeWithText("Key file is damaged.").assertExists()
    }
}
