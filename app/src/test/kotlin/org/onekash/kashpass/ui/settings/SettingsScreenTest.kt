package org.onekash.kashpass.ui.settings

import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.hasProgressBarRangeInfo
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.session.BiometricStatus
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.storage.UnlockAvailability
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SettingsScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val calls = mutableListOf<String>()

    private fun show(status: BiometricStatus, isFile: Boolean = true, failed: Boolean = false, applying: Boolean = false, biometricShown: Boolean = true) = rule.setContent {
        KashPassTheme {
            SettingsScreen(
                state = SettingsUiState(
                    fileName = "kashpass-test.kdbx",
                    biometric = status,
                    isFile = isFile,
                    biometricFailed = failed,
                    applying = applying,
                    biometricShown = biometricShown,
                ),
                biometricNoun = "fingerprint",
                onBack = { calls += "back" },
                onLock = { calls += "lock" },
                onBiometric = { calls += "biometric:$it" },
                onEnroll = { calls += "enroll" },
                onBackups = { calls += "backups" },
                onChooseFile = { calls += "choose" },
                onAbout = { calls += "about" },
            )
        }
    }

    @Test
    fun `the page is the vault with Lock vault, then four rows and no section headers`() {
        show(BiometricStatus.On)
        rule.onNodeWithText("kashpass-test.kdbx").assertExists()
        rule.onNodeWithText("Opened", substring = true).assertDoesNotExist()
        rule.onNodeWithText("Unlock").assertDoesNotExist()
        rule.onNodeWithText("This vault").assertDoesNotExist()
        rule.onNodeWithText("Lock vault").performClick()
        rule.onNodeWithText("Vault backups").performClick()
        rule.onNodeWithText("copies on this device", substring = true).assertDoesNotExist()
        rule.onNodeWithText("Open another vault").performClick()
        rule.onNodeWithText("Opens the file picker").assertDoesNotExist()
        rule.onNodeWithText("Turns", substring = true).assertDoesNotExist()
        rule.onNodeWithText("About KashPass").performClick()
        rule.onNodeWithContentDescription("Back").performClick()
        assertEquals(listOf("lock", "backups", "choose", "about", "back"), calls)
    }

    @Test
    fun `About KashPass is the last row`() {
        show(BiometricStatus.Off)
        val rows = listOf("Biometric unlock", "Vault backups", "Open another vault", "About KashPass")
        val tops = rows.map { rule.onNodeWithText(it).fetchSemanticsNode().boundsInRoot.top }
        assertEquals(tops.sorted(), tops)
    }

    @Test
    fun `Copies to keep and Delete older copies are not on the page`() {
        show(BiometricStatus.Off)
        rule.onNodeWithText("Copies to keep").assertDoesNotExist()
        rule.onNodeWithText("Delete older copies").assertDoesNotExist()
    }

    @Test
    fun `the switch is titled Biometric unlock, shows the state and has no line under it`() {
        show(BiometricStatus.On)
        rule.onNodeWithText("Biometric unlock").assertIsOn().performClick()
        rule.onNodeWithText("On for this file").assertDoesNotExist()
        rule.onNodeWithText("Off").assertDoesNotExist()
        assertEquals(listOf("biometric:false"), calls)
    }

    @Test
    fun `the info button explains biometric unlock and doesn't toggle the row`() {
        show(BiometricStatus.On)
        rule.onNodeWithContentDescription("About Biometric unlock").performClick()
        rule.onNodeWithText("Unlock this file with biometrics instead of the vault password.").assertExists()
        rule.onAllNodesWithText("Biometric unlock").assertCountEquals(2)
        assertEquals(emptyList<String>(), calls)
    }

    @Test
    fun `without an enrolled biometric the switch is off and disabled, with a way to set one up`() {
        show(BiometricStatus.Unavailable(UnlockAvailability.NONE_ENROLLED))
        rule.onNodeWithText("Biometric unlock").assertIsOff().assertIsNotEnabled()
        rule.onNodeWithText("Add a fingerprint in device settings first.").assertExists()
        rule.onNodeWithText("Open device settings").performClick()
        assertEquals(listOf("enroll"), calls)
    }

    @Test
    fun `without a screen lock the line says to set one`() {
        show(BiometricStatus.Unavailable(UnlockAvailability.NO_SCREEN_LOCK))
        rule.onNodeWithText("Set a screen lock in device settings first.").assertExists()
        rule.onNodeWithText("Open device settings").assertExists()
    }

    @Test
    fun `a phone that can't do it says so, with no settings button`() {
        show(BiometricStatus.Unavailable(UnlockAvailability.UNAVAILABLE))
        rule.onNodeWithText("This device doesn't support biometric unlock.").assertExists()
        rule.onNodeWithText("Open device settings").assertDoesNotExist()
    }

    @Test
    fun `a failed turn-on says so`() {
        show(BiometricStatus.Off, failed = true)
        rule.onNodeWithText("Couldn't turn on biometric unlock. Try again.").assertExists()
    }

    @Test
    fun `for a backup the switch is disabled and says why`() {
        show(BiometricStatus.Unavailable(UnlockAvailability.NONE_ENROLLED), isFile = false)
        rule.onNodeWithText("Biometric unlock").assertIsNotEnabled()
        rule.onAllNodesWithText("Not available while a backup is open.").assertCountEquals(1)
        rule.onNodeWithText("Open device settings").assertDoesNotExist()
    }

    @Test
    fun `while a change applies, a bar shows and the switch is disabled`() {
        show(BiometricStatus.Off, applying = true)
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
        rule.onNodeWithText("Biometric unlock").assertIsNotEnabled()
    }

    @Test
    fun `no bar shows while nothing applies`() {
        show(BiometricStatus.Off)
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertDoesNotExist()
    }

    @Test
    fun `the biometric row is hidden when the vault has no password to seal`() {
        show(BiometricStatus.Off, biometricShown = false)
        rule.onNodeWithText("Biometric unlock").assertDoesNotExist()
        rule.onNodeWithText("Vault backups").assertExists()
    }
}
