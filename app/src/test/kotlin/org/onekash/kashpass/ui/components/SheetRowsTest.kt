package org.onekash.kashpass.ui.components

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.R
import org.robolectric.RobolectricTestRunner

/**
 * Tests the sheets' rising rows: they rest from the start when played or with motion off, play
 * once and mark themselves played as they start, and a link row tells TalkBack it opens the
 * browser.
 */
@RunWith(RobolectricTestRunner::class)
class SheetRowsTest {

    @get:Rule
    val rule = createComposeRule()

    // The rows' progress values on the last composition.
    private var values = emptyList<Float>()

    private fun show(motion: Boolean, played: () -> Boolean, onPlayed: () -> Unit) {
        rule.mainClock.autoAdvance = false
        rule.setContent {
            MaterialTheme {
                val progress = rememberEntranceProgress(listOf(520L, 580L), 420, motion, played(), onPlayed)
                values = progress.map { it.value }
            }
        }
    }

    @Test
    fun `with motion off every row rests from the start`() {
        var marks = 0
        show(motion = false, played = { false }, onPlayed = { marks++ })
        rule.mainClock.advanceTimeByFrame()
        assertEquals(listOf(1f, 1f), values)
        assertEquals(0, marks)
    }

    @Test
    fun `played rows rest from the start`() {
        var marks = 0
        show(motion = true, played = { true }, onPlayed = { marks++ })
        rule.mainClock.advanceTimeBy(700)
        assertEquals(listOf(1f, 1f), values)
        assertEquals(0, marks)
    }

    @Test
    fun `rows rise once, marked played as they start, and the flag fed back does not cut them short`() {
        var played by mutableStateOf(false)
        var marks = 0
        show(motion = true, played = { played }, onPlayed = { marks++; played = true })
        rule.mainClock.advanceTimeByFrame()
        assertEquals(1, marks)
        assertEquals(listOf(0f, 0f), values)
        rule.mainClock.advanceTimeBy(700)
        assertTrue("first row mid-rise: $values", values[0] > 0f && values[0] < 1f)
        rule.mainClock.advanceTimeBy(1000)
        assertEquals(listOf(1f, 1f), values)
        assertEquals(1, marks)
    }

    @Test
    fun `a link row tells TalkBack it opens the browser and taps through`() {
        var taps = 0
        rule.setContent {
            MaterialTheme {
                RisingRows(
                    listOf(SheetRowSpec(R.drawable.ic_open_in_new, R.string.app_name, R.string.cd_opens_in_browser, { taps++ }, opensBrowser = true)),
                    motionEnabled = false,
                    played = false,
                    onPlayed = {},
                )
            }
        }
        rule.onNodeWithContentDescription("KashPass, Opens in browser, Opens in browser").performClick()
        assertEquals(1, taps)
        rule.onNodeWithText("KashPass", useUnmergedTree = true).assertExists()
    }
}
