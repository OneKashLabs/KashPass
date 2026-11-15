package org.onekash.kashpass.ui.components

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createComposeRule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Tests Kash's entrance: the frame at each moment of the settle and the two waves, that it plays
 * once in real time, and that it rests from the start when played or with motion off.
 */
@RunWith(RobolectricTestRunner::class)
class KashWaveEntranceTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun `Kash starts above its place, hidden, arm down`() {
        val start = kashWaveFrame(0)
        assertEquals(-14f, start.offsetDp, 0.01f)
        assertEquals(0f, start.alpha, 0.01f)
        assertEquals(0f, start.armDegrees, 0.01f)
    }

    @Test
    fun `Kash lands with a slight squash, then rests`() {
        val landing = kashWaveFrame(300)
        assertTrue("squashed: ${landing.scaleY} < 1 < ${landing.scaleX}", landing.scaleY < 1f && landing.scaleX > 1f)
        val touchdown = kashWaveFrame(480)
        assertEquals(0f, touchdown.offsetDp, 0.01f)
        assertEquals(1f, touchdown.alpha, 0.01f)
        assertNotEquals("still settling", KashWaveFrame.REST, touchdown)
        val settled = kashWaveFrame(704)
        assertEquals(1f, settled.scaleX, 0.001f)
        assertEquals(1f, settled.scaleY, 0.001f)
    }

    @Test
    fun `Kash waves twice after landing`() {
        assertEquals(0f, kashWaveFrame(704).armDegrees, 0.01f)
        assertEquals(-18f, kashWaveFrame(960).armDegrees, 0.01f)
        assertEquals(0f, kashWaveFrame(1216).armDegrees, 0.01f)
        assertEquals(-18f, kashWaveFrame(1472).armDegrees, 0.01f)
        assertEquals(0f, kashWaveFrame(1728).armDegrees, 0.01f)
    }

    @Test
    fun `after the waves Kash stays at rest, and any time is valid`() {
        assertEquals(1728, KASH_WAVE_TOTAL_MS)
        assertEquals(KashWaveFrame.REST, kashWaveFrame(KASH_WAVE_TOTAL_MS.toLong()))
        assertEquals(KashWaveFrame.REST, kashWaveFrame(60_000))
        assertEquals(kashWaveFrame(0), kashWaveFrame(-50))
    }

    @Test
    fun `it plays once, in real time, and marks itself played as it starts`() {
        val frames = mutableListOf<KashWaveFrame>()
        var recompose by mutableIntStateOf(0)
        // The caller's flag, fed back as the screens do.
        var played by mutableStateOf(false)
        var marks = 0
        rule.mainClock.autoAdvance = false
        rule.setContent {
            MaterialTheme {
                recompose.let {
                    KashWaveEntrance(motionEnabled = true, played = played, onPlayed = { marks++; played = true }, onFrame = { frames += it })
                }
            }
        }
        rule.mainClock.advanceTimeByFrame()
        assertEquals(1, marks)
        assertTrue("marked played", played)
        assertNotEquals("starts moving", KashWaveFrame.REST, frames.last())
        // Times count from the end of the start delay; the animation also starts about one frame
        // after the first composition, hence the slack.
        val at = { ms: Long -> rule.mainClock.advanceTimeBy(ms); frames.last() }
        val touchdown = at(KASH_WAVE_START_DELAY_MS + 464)
        assertTrue("squashed at 480 ms, not cut short: ${touchdown.scaleX}", touchdown.scaleX > 1f && touchdown.scaleY < 1f)
        assertEquals(-18f, at(480).armDegrees, 2f)
        assertEquals(0f, at(256).armDegrees, 2f)
        at(1000)
        assertEquals(KashWaveFrame.REST, frames.last())
        recompose++
        rule.mainClock.advanceTimeByFrame()
        assertEquals("no replay", KashWaveFrame.REST, frames.last())
        assertEquals(1, marks)
    }

    @Test
    fun `with motion off Kash is at rest from the start and nothing is marked`() = assertRests(motion = false, played = false)

    @Test
    fun `once played Kash is at rest from the start and nothing is marked`() = assertRests(motion = true, played = true)

    private fun assertRests(motion: Boolean, played: Boolean) {
        val frames = mutableListOf<KashWaveFrame>()
        var marks = 0
        rule.mainClock.autoAdvance = false
        rule.setContent {
            MaterialTheme {
                KashWaveEntrance(motionEnabled = motion, played = played, onPlayed = { marks++ }, onFrame = { frames += it })
            }
        }
        rule.mainClock.advanceTimeBy(600)
        assertTrue(frames.isNotEmpty())
        assertTrue(frames.distinct().toString(), frames.all { it == KashWaveFrame.REST })
        assertEquals(0, marks)
    }
}
