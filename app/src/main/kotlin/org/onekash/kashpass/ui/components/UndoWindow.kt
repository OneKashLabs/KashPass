package org.onekash.kashpass.ui.components

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalAccessibilityManager
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * Returns how long an Undo snackbar shows before its change runs: Material 3's short snackbar
 * duration, extended to the timeout Android's accessibility settings recommend for text with an
 * action.
 */
@Composable
fun rememberUndoWindow(): Duration {
    val accessibility = LocalAccessibilityManager.current
    return remember(accessibility) {
        (accessibility?.calculateRecommendedTimeoutMillis(UNDO_WINDOW_MS, containsIcons = false, containsText = true, containsControls = true) ?: UNDO_WINDOW_MS).milliseconds
    }
}

private const val UNDO_WINDOW_MS = 4_000L
