package org.onekash.kashpass.ui.components

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.junit4.createComposeRule
import java.io.File
import kotlin.math.abs
import kotlin.math.roundToInt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Tests Kash's art: a light and a dark drawing per still pose and the wave's two dark layers, the
 * files' pixel sizes and total weight, the wave's shoulder pivot, the fur following the theme's
 * surface, and that the art is decorative.
 */
@RunWith(RobolectricTestRunner::class)
class KashArtTest {

    @get:Rule
    val rule = createComposeRule()

    private val artDir = File(File("..").canonicalFile, "app/src/main/res/drawable-nodpi")

    // Pixel widths at xxxhdpi (4 px per dp): 160 dp for the wave and About, 120 dp beside the
    // empty vault.
    private val widths = mapOf(
        "kash_happy" to 640, "kash_happy_dark" to 640,
        "kash_content" to 480, "kash_content_dark" to 480,
        "kash_wave_arm_dark" to 640, "kash_wave_body_dark" to 640,
    )

    @Test
    fun `every still pose has a light and a dark drawing, and the wave has two layers`() {
        val ids = KashPose.entries.flatMap { listOf(kashDrawable(it, false), kashDrawable(it, true)) } +
            listOf(org.onekash.kashpass.R.drawable.kash_wave_arm_dark, org.onekash.kashpass.R.drawable.kash_wave_body_dark)
        assertEquals(6, ids.size)
        assertEquals("ids are distinct", 6, ids.toSet().size)
        KashPose.entries.forEach { assertNotEquals(kashDrawable(it, false), kashDrawable(it, true)) }
    }

    @Test
    fun `each art file has its pixel width and the art's shape`() {
        for ((name, width) in widths) {
            val file = File(artDir, "$name.webp")
            assertTrue("$file exists", file.isFile)
            val (w, h) = webpSize(file.readBytes())
            assertEquals("$name width", width, w)
            assertTrue("$name height $h", abs(h - (width * 210.0 / 220).roundToInt()) <= 2)
        }
    }

    @Test
    fun `all of Kash's art together stays within 200 KB`() {
        val files = artDir.listFiles { f -> f.name.startsWith("kash_") && f.name.endsWith(".webp") }.orEmpty()
        assertEquals(widths.keys, files.map { it.nameWithoutExtension }.toSet())
        assertTrue("total ${files.sumOf { it.length() }} bytes", files.sumOf { it.length() } <= 200 * 1024)
    }

    @Test
    fun `the arm waves about its shoulder`() {
        assertEquals(0.843f, KASH_WAVE_PIVOT.pivotFractionX, 0.01f)
        assertEquals(0.462f, KASH_WAVE_PIVOT.pivotFractionY, 0.01f)
    }

    @Test
    fun `a dark surface takes the dark fur and a light surface the light fur`() {
        var dark: Boolean? = null
        var light: Boolean? = null
        rule.setContent {
            MaterialTheme(colorScheme = darkColorScheme()) { dark = kashUsesDarkFur() }
            MaterialTheme(colorScheme = lightColorScheme()) { light = kashUsesDarkFur() }
        }
        rule.waitForIdle()
        assertEquals(true, dark)
        assertEquals(false, light)
    }

    @Test
    fun `Kash is decorative and gives TalkBack nothing to read, in light and dark fur`() {
        rule.setContent {
            MaterialTheme(colorScheme = darkColorScheme()) { KashArt(KashPose.CONTENT) }
            MaterialTheme {
                KashArt(KashPose.HAPPY)
                KashWaveEntrance(motionEnabled = false, played = false, onPlayed = {})
            }
        }
        val described = rule.onAllNodes(SemanticsMatcher.keyIsDefined(SemanticsProperties.ContentDescription))
            .fetchSemanticsNodes()
        assertEquals("content descriptions", 0, described.size)
    }

    // Returns a WebP's canvas size from its header (VP8X, VP8L or VP8 chunk).
    private fun webpSize(b: ByteArray): Pair<Int, Int> {
        fun u24(i: Int) = (b[i].toInt() and 0xFF) or ((b[i + 1].toInt() and 0xFF) shl 8) or ((b[i + 2].toInt() and 0xFF) shl 16)
        fun u16(i: Int) = (b[i].toInt() and 0xFF) or ((b[i + 1].toInt() and 0xFF) shl 8)
        assertEquals("RIFF", String(b, 0, 4))
        assertEquals("WEBP", String(b, 8, 4))
        return when (String(b, 12, 4)) {
            "VP8X" -> (u24(24) + 1) to (u24(27) + 1)
            "VP8L" -> {
                val bits = u24(21) or ((b[24].toInt() and 0xFF) shl 24)
                ((bits and 0x3FFF) + 1) to (((bits shr 14) and 0x3FFF) + 1)
            }
            else -> (u16(26) and 0x3FFF) to (u16(28) and 0x3FFF)
        }
    }
}
