package org.onekash.kashpass.ui.components

import android.content.ContentResolver
import android.provider.Settings
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.AnimationVector1D
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Easing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.onekash.kashpass.R

// The rows rise in one after another, starting half a second in so the sheet's hero shows first.
private const val ROWS_DELAY_MS = 520L
private const val ROW_STAGGER_MS = 60L
private const val ROW_DURATION_MS = 420
private const val ROW_RISE_DP = 14f

/** The entrance curve: a quick start that eases gently into place. */
internal val EntranceEasing = CubicBezierEasing(0.2f, 0.8f, 0.2f, 1f)

/** Returns false when the system's "Remove animations" sets the animator duration scale to 0. */
internal fun heroMotionEnabled(resolver: ContentResolver): Boolean =
    Settings.Global.getFloat(resolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) != 0f

/** Returns whether entrances move, read once: false with "Remove animations" on. */
@Composable
internal fun rememberHeroMotionEnabled(): Boolean {
    val resolver = LocalContext.current.contentResolver
    return remember(resolver) { heroMotionEnabled(resolver) }
}

/**
 * Returns one progress value per entry of [delaysMs], each going from 0 to 1 over [durationMs]
 * after its delay, along [easing]. [played] is read once, on first composition: when true, or
 * with motion off, every value starts and stays at 1. Otherwise [onPlayed] runs as the entrance
 * starts, so the caller can keep the flag where a rotation does not reach it (no saved state
 * holds it); a later change of [played] leaves a running entrance alone.
 */
@Composable
internal fun rememberEntranceProgress(
    delaysMs: List<Long>,
    durationMs: Int,
    motionEnabled: Boolean,
    played: Boolean,
    onPlayed: () -> Unit,
    easing: Easing = EntranceEasing,
): List<Animatable<Float, AnimationVector1D>> {
    val rest = remember { played || !motionEnabled }
    val progress = remember { List(delaysMs.size) { Animatable(if (rest) 1f else 0f) } }
    LaunchedEffect(Unit) {
        if (rest) return@LaunchedEffect
        onPlayed()
        progress.forEachIndexed { index, value ->
            launch {
                delay(delaysMs[index])
                value.animateTo(1f, tween(durationMs, easing = easing))
            }
        }
    }
    return progress
}

/**
 * Lays out a full-height sheet: [body] as one group centered in the space above [footer], which
 * stays pinned at the bottom. At large font sizes the group scrolls and the footer stays put.
 */
@Composable
internal fun CenteredSheetLayout(
    footer: @Composable () -> Unit,
    body: @Composable ColumnScope.() -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        BoxWithConstraints(modifier = Modifier.weight(1f).fillMaxWidth()) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .heightIn(min = maxHeight)
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
                content = body,
            )
        }
        footer()
    }
}

/**
 * Holds one row's icon, its two texts and what a tap does. [opensBrowser] swaps the chevron for
 * the open-in-new glyph and has TalkBack say the row opens the browser.
 */
internal class SheetRowSpec(
    @DrawableRes val icon: Int,
    @StringRes val title: Int,
    @StringRes val detail: Int,
    val onClick: () -> Unit,
    val opensBrowser: Boolean = false,
)

/**
 * Shows [rows], fading in and rising one after another; [played] and [onPlayed] work as in
 * [rememberEntranceProgress].
 */
@Composable
internal fun RisingRows(
    rows: List<SheetRowSpec>,
    motionEnabled: Boolean,
    played: Boolean,
    onPlayed: () -> Unit,
) {
    val progress = rememberEntranceProgress(
        delaysMs = rows.indices.map { ROWS_DELAY_MS + it * ROW_STAGGER_MS },
        durationMs = ROW_DURATION_MS,
        motionEnabled = motionEnabled,
        played = played,
        onPlayed = onPlayed,
    )
    val risePx = with(LocalDensity.current) { ROW_RISE_DP.dp.toPx() }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        rows.forEachIndexed { index, row ->
            SheetRow(
                icon = row.icon,
                title = stringResource(row.title),
                detail = stringResource(row.detail),
                onClick = row.onClick,
                opensBrowser = row.opensBrowser,
                modifier = Modifier.graphicsLayer {
                    val t = progress[index].value
                    alpha = t
                    translationY = (1f - t) * risePx
                },
            )
        }
    }
}

/** Shows one tappable row: an icon tile, a title and a detail line. */
@Composable
private fun SheetRow(
    @DrawableRes icon: Int,
    title: String,
    detail: String,
    onClick: () -> Unit,
    opensBrowser: Boolean,
    modifier: Modifier = Modifier,
) {
    val opensInBrowser = stringResource(R.string.cd_opens_in_browser)
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
            .clickable(role = Role.Button, onClick = onClick)
            // The open-in-new glyph is the only "leaves the app" cue and TalkBack skips it, so
            // the row's label says it.
            .semantics(mergeDescendants = true) {
                if (opensBrowser) contentDescription = "$title, $detail, $opensInBrowser"
            }
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Icon(painterResource(icon), contentDescription = null, tint = MaterialTheme.colorScheme.onPrimaryContainer)
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Text(
                text = detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Icon(
            painterResource(if (opensBrowser) R.drawable.ic_open_in_new else R.drawable.ic_chevron_right),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
