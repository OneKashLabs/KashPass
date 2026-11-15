package org.onekash.kashpass.ui.settings

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.components.KASH_TAG
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class AboutSheetTest {

    @get:Rule
    val rule = createComposeRule()

    private val opened = mutableListOf<String>()
    private var opens = true

    private fun show() = rule.setContent {
        KashPassTheme {
            AboutSheet(AppVersion("1.2.3"), onDismiss = {}, onOpenLink = { opened += it; opens }, rowsPlayed = true, onRowsPlayed = {})
        }
    }

    @Test
    fun `the sheet shows Kash, KashPass as a heading, the tagline and the version`() {
        show()
        rule.onNodeWithTag(KASH_TAG).assertExists()
        rule.onNodeWithText("KashPass").assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Heading))
        rule.onNodeWithText("Android companion for your KeePass vaults. Secure access, no internet.").assertExists()
        rule.onNodeWithText("Version 1.2.3").assertExists()
    }

    @Test
    fun `the sheet holds no commit, licence link or sentence, privacy row or KeePass lines`() {
        show()
        for (gone in listOf("Commit", "AGPL", "Licences", "Privacy", "Works with KeePass", "Tested with KeePass", "Open-source licences")) {
            rule.onNodeWithText(gone, substring = true).assertDoesNotExist()
        }
    }

    @Test
    fun `each link opens its target`() {
        show()
        rule.onNodeWithContentDescription("Source code, On GitHub, Opens in browser").performClick()
        rule.onNodeWithContentDescription("Report a problem, Never attach your vault., Opens in browser").performScrollTo().performClick()
        rule.onNodeWithContentDescription("Support KashPass, Thank you to everyone who already does, Opens in browser").performScrollTo().performClick()
        assertEquals(
            listOf(
                "https://github.com/OneKashLabs/KashPass",
                "https://github.com/OneKashLabs/KashPass/issues",
                "https://github.com/sponsors/one-kash",
            ),
            opened,
        )
    }

    @Test
    fun `a link no app opens says so inline`() {
        opens = false
        show()
        rule.onNodeWithContentDescription("Source code, On GitHub, Opens in browser").performClick()
        rule.onNodeWithText("No app on this device can open this link.").assertExists()
    }

    @Test
    fun `read takes the version name from the package`() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        assertEquals(info.versionName.orEmpty(), AppVersion.read(context).name)
    }
}
