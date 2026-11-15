package org.onekash.kashpass.ui.components

import androidx.annotation.DrawableRes
import androidx.compose.foundation.Image
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.TransformOrigin
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.res.painterResource
import org.onekash.kashpass.R

/** Width over height of every Kash drawing: the art is 220 by 210 in shape. */
internal const val KASH_ASPECT_RATIO = 220f / 210f

/**
 * Kash, the mascot, in one of its still poses. Each pose has two drawings, both
 * [KASH_ASPECT_RATIO] in shape: fur for light surfaces and a lighter fur for dark ones, so the
 * fuzzy edge stays visible.
 */
internal enum class KashPose(@DrawableRes val light: Int, @DrawableRes val dark: Int) {
    /** About's hero: eyes open, a small smile. */
    HAPPY(R.drawable.kash_happy, R.drawable.kash_happy_dark),

    /** Above the empty vault's text: eyes closed, a small smile. */
    CONTENT(R.drawable.kash_content, R.drawable.kash_content_dark),
}

/**
 * The test tag every Kash drawing carries where a screen shows one, so tests can find decorative
 * art, which has no text or description.
 */
const val KASH_TAG = "kash"

/** Returns [pose]'s drawing in dark-surface fur when [darkFur], else in light fur. */
@DrawableRes
internal fun kashDrawable(pose: KashPose, darkFur: Boolean): Int =
    if (darkFur) pose.dark else pose.light

/**
 * The waving arm's shoulder, the point it turns about, as fractions of the wave layers' canvas:
 * 30% across and 95% down the arm's bounding box in the drawing. It belongs to the drawings, so
 * it changes only when they do.
 */
internal val KASH_WAVE_PIVOT = TransformOrigin(0.843f, 0.462f)

/** Returns true when the theme's surface is dark, so Kash uses the dark-surface fur. */
@Composable
internal fun kashUsesDarkFur(): Boolean = MaterialTheme.colorScheme.surface.luminance() < 0.5f

/**
 * Draws Kash in [pose]. Kash is decorative: the text beside it says what the screen means, so it
 * has no content description and TalkBack skips it. Callers set the size.
 */
@Composable
internal fun KashArt(pose: KashPose, modifier: Modifier = Modifier) {
    Image(
        painter = painterResource(kashDrawable(pose, kashUsesDarkFur())),
        contentDescription = null,
        modifier = modifier,
    )
}
