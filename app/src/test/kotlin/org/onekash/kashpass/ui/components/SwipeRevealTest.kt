package org.onekash.kashpass.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedback
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performCustomAccessibilityActionWithLabel
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.test.swipeLeft
import androidx.compose.ui.test.swipeRight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalTestApi::class)
@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class SwipeRevealTest {

    @get:Rule
    val rule = createComposeRule()

    private val revealed = RevealedRow()
    private val haptics = mutableListOf<HapticFeedbackType>()
    private val deleted = mutableListOf<String>()

    private var enabled by mutableStateOf(true)

    private fun show(enabled: Boolean = true, direction: LayoutDirection = LayoutDirection.Ltr) = rule.setContent {
        val recorder = object : HapticFeedback {
            override fun performHapticFeedback(hapticFeedbackType: HapticFeedbackType) {
                haptics += hapticFeedbackType
            }
        }
        CompositionLocalProvider(LocalLayoutDirection provides direction, LocalHapticFeedback provides recorder) {
            KashPassTheme {
                Column {
                    for (id in listOf("a", "b")) {
                        SwipeRevealRow(
                            enabled = enabled && this@SwipeRevealTest.enabled,
                            open = revealed.openId == id,
                            onOpenChange = { revealed.set(id, it) },
                            deleteLabel = "Delete $id",
                            onDelete = { deleted += id },
                        ) {
                            Text("Row $id", it.testTag("row-$id").fillMaxWidth().padding(16.dp))
                        }
                    }
                }
            }
        }
    }

    private fun left(id: String) = rule.onNodeWithTag("row-$id").getUnclippedBoundsInRoot().left

    @Test
    fun `a swipe toward the start opens the row with one haptic tick, a short one springs back`() {
        show()
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft(startX = right - 2f, endX = right - 30f, durationMillis = 1_000) }
        rule.waitForIdle()
        assertEquals(null, revealed.openId)
        assertEquals(0.dp, left("a"))
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        assertEquals("a", revealed.openId)
        assertEquals(-96.dp, left("a"))
        assertEquals(listOf(HapticFeedbackType.GestureThresholdActivate), haptics)
    }

    @Test
    fun `opening a second row closes the first`() {
        show()
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        rule.onNodeWithTag("row-b").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        assertEquals("b", revealed.openId)
        assertEquals(0.dp, left("a"))
        assertEquals(2, haptics.size)
    }

    @Test
    fun `closing from outside springs the row back and rearms the tick`() {
        show()
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        revealed.close()
        rule.waitForIdle()
        assertEquals(0.dp, left("a"))
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        assertEquals(2, haptics.size)
    }

    @Test
    fun `right to left the swipe goes the other way and the button sits at the left end`() {
        show(direction = LayoutDirection.Rtl)
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        assertEquals(null, revealed.openId)
        rule.onNodeWithTag("row-a").performTouchInput { swipeRight() }
        rule.waitForIdle()
        assertEquals("a", revealed.openId)
        assertEquals(96.dp, left("a"))
    }

    @Test
    fun `a row that can't be edited neither swipes nor shows Delete`() {
        show(enabled = false)
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        assertEquals(null, revealed.openId)
        rule.onNode(SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions)).assertDoesNotExist()
    }

    @Test
    fun `Delete is also an accessibility action on the row`() {
        show()
        // On the row's own node, the one TalkBack focuses.
        rule.onNode(SemanticsMatcher.keyIsDefined(SemanticsActions.CustomActions) and hasText("Row b"))
            .performCustomAccessibilityActionWithLabel("Delete b")
        assertEquals(listOf("b"), deleted)
    }

    @Test
    fun `tapping the revealed button deletes`() {
        show()
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        rule.onAllNodesWithText("Delete")[0].performClick()
        assertEquals(listOf("a"), deleted)
    }

    @Test
    fun `a drag that reaches the reveal and comes back short ticks once and stays closed`() {
        show()
        rule.onNodeWithTag("row-a").performTouchInput {
            down(centerRight - Offset(2f, 0f))
            moveBy(Offset(-400f, 0f))
            moveBy(Offset(380f, 0f))
            up()
        }
        rule.waitForIdle()
        assertEquals(null, revealed.openId)
        assertEquals(listOf(HapticFeedbackType.GestureThresholdActivate), haptics)
    }

    @Test
    fun `opening a row closes the inline confirm of another`() {
        show()
        revealed.confirmingId = "b"
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        assertEquals(null, revealed.confirmingId)
    }

    @Test
    fun `an open row that turns plain reports closed`() {
        show()
        rule.onNodeWithTag("row-a").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        assertEquals("a", revealed.openId)
        enabled = false
        rule.waitForIdle()
        assertEquals(null, revealed.openId)
    }
}
