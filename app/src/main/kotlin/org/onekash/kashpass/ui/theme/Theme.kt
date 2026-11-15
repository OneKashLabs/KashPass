package org.onekash.kashpass.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalInspectionMode

/** Launcher navy, the lock screen's ground. */
val Navy = Color(0xFF020727)

// Fallback scheme from the icon's indigo, used where dynamic color is not available (previews).
private val IndigoLight = lightColorScheme(primary = Color(0xFF4F5BA8), secondary = Color(0xFF5B5D72), tertiary = Color(0xFF77536D))
private val IndigoDark = darkColorScheme(primary = Color(0xFFBBC3FF), secondary = Color(0xFFC4C5DD), tertiary = Color(0xFFE6BAD7))

/**
 * Applies Material 3 with dynamic color from the wallpaper (minSdk 31 always has it) and the
 * system's light or dark setting. System bar icons are left to `enableEdgeToEdge`, which follows
 * the system setting; only the navy lock screen overrides them.
 */
@Composable
fun KashPassTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val colors = when {
        LocalInspectionMode.current -> if (dark) IndigoDark else IndigoLight
        dark -> dynamicDarkColorScheme(LocalContext.current)
        else -> dynamicLightColorScheme(LocalContext.current)
    }
    MaterialTheme(colorScheme = colors, content = content)
}
