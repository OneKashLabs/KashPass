package org.onekash.kashpass.ui.components

import androidx.compose.ui.test.assertTouchHeightIsEqualTo
import androidx.compose.ui.test.assertTouchWidthIsEqualTo
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class InfoButtonTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun `a tap opens the explanation, and the touch target is at least 48dp`() {
        rule.setContent { KashPassTheme { InfoButton("Copies to keep", "A copy is kept for every change.") } }
        rule.onNodeWithContentDescription("About Copies to keep").assertTouchWidthIsEqualTo(48.dp).assertTouchHeightIsEqualTo(48.dp)
        rule.onNodeWithContentDescription("About Copies to keep").performClick()
        rule.onNodeWithText("A copy is kept for every change.").assertExists()
    }
}
