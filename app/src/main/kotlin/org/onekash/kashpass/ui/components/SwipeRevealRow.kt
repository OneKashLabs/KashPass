package org.onekash.kashpass.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.AnchoredDraggableDefaults
import androidx.compose.foundation.gestures.AnchoredDraggableState
import androidx.compose.foundation.gestures.DraggableAnchors
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.gestures.anchoredDraggable
import androidx.compose.foundation.gestures.animateTo
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import kotlin.math.roundToInt
import org.onekash.kashpass.R

/** Position of a swipeable row. */
enum class RevealValue { CLOSED, REVEALED }

/** Width of the Delete button a swipe reveals. */
private val DELETE_WIDTH = 96.dp

/**
 * Wraps a list row so a swipe toward the start reveals a Delete button at the row's end. The row
 * stays open until [open] turns false. Both anchors use one sign: the drag gesture reverses in
 * right-to-left layouts and [Modifier.offset] mirrors, so the button is at the end in both
 * directions. One haptic tick plays when a drag reaches the reveal; the next plays only after the
 * row closed. [content] gets a modifier carrying [deleteLabel] as a custom accessibility action,
 * because TalkBack and Switch Access can't swipe; it goes on the row's own clickable node, which
 * is the one TalkBack focuses. Without [enabled] the row is plain. [SwipeRevealTest] covers it.
 */
@Composable
fun SwipeRevealRow(
    enabled: Boolean,
    open: Boolean,
    onOpenChange: (Boolean) -> Unit,
    deleteLabel: String,
    onDelete: () -> Unit,
    content: @Composable (Modifier) -> Unit,
) {
    if (!enabled) {
        content(Modifier)
        return
    }
    val width = with(LocalDensity.current) { DELETE_WIDTH.toPx() }
    val state = remember(width) {
        AnchoredDraggableState(
            initialValue = RevealValue.CLOSED,
            anchors = DraggableAnchors {
                RevealValue.CLOSED at 0f
                RevealValue.REVEALED at -width
            },
        )
    }
    val haptics = LocalHapticFeedback.current
    val openChange by rememberUpdatedState(onOpenChange)
    // A row that leaves the list or turns plain (a save started) while open reports closed.
    DisposableEffect(state) { onDispose { openChange(false) } }
    LaunchedEffect(state) {
        var armed = true
        var wasOpen = false
        snapshotFlow { state.targetValue to state.settledValue }.collect { (target, settled) ->
            if (target == RevealValue.REVEALED && armed) {
                haptics.performHapticFeedback(HapticFeedbackType.GestureThresholdActivate)
                armed = false
            }
            if (settled == RevealValue.CLOSED && target == RevealValue.CLOSED) armed = true
            val open = settled == RevealValue.REVEALED
            if (open != wasOpen) {
                wasOpen = open
                openChange(open)
            }
        }
    }
    LaunchedEffect(open) {
        if (!open && state.settledValue != RevealValue.CLOSED) state.animateTo(RevealValue.CLOSED)
    }
    val delete by rememberUpdatedState(onDelete)
    val actions = Modifier.semantics { customActions = listOf(CustomAccessibilityAction(deleteLabel) { delete(); true }) }
    Box(Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
        Box(Modifier.matchParentSize(), contentAlignment = Alignment.CenterEnd) {
            Box(
                Modifier
                    .width(DELETE_WIDTH)
                    .fillMaxHeight()
                    .background(MaterialTheme.colorScheme.error)
                    .clickable(onClickLabel = deleteLabel) { delete() },
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(painterResource(R.drawable.ic_delete), contentDescription = null, tint = MaterialTheme.colorScheme.onError)
                    Text(stringResource(R.string.swipe_delete), color = MaterialTheme.colorScheme.onError, style = MaterialTheme.typography.labelLarge)
                }
            }
        }
        Box(
            Modifier
                .offset { IntOffset(state.requireOffset().roundToInt(), 0) }
                .anchoredDraggable(
                    state = state,
                    orientation = Orientation.Horizontal,
                    flingBehavior = AnchoredDraggableDefaults.flingBehavior(state, positionalThreshold = { it * 0.5f }),
                )
                .background(MaterialTheme.colorScheme.surface),
        ) {
            content(actions)
        }
    }
}

/**
 * Shows the inline confirm a permanent delete puts in place of its row: no dialog, two taps, the
 * second on a solid red Delete.
 */
@Composable
fun InlineDeleteConfirm(onCancel: () -> Unit, onConfirm: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Text(stringResource(R.string.delete_forever), style = MaterialTheme.typography.bodyLarge)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = onCancel) { Text(stringResource(R.string.delete_cancel)) }
            Button(
                onClick = onConfirm,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError,
                ),
                modifier = Modifier.padding(start = 8.dp),
            ) {
                Icon(painterResource(R.drawable.ic_delete), contentDescription = null, modifier = Modifier.size(18.dp))
                Text(stringResource(R.string.delete_confirm_action), modifier = Modifier.padding(start = 6.dp))
            }
        }
    }
}

/**
 * Tracks the one open row of a list, by id, and the row showing its inline permanent-delete
 * confirm.
 * Opening a row closes the other and the confirm.
 */
class RevealedRow {
    var openId: String? by mutableStateOf(null)
        private set

    /** The row showing its inline confirm, or null. */
    var confirmingId: String? by mutableStateOf(null)

    /** Records [id] as open or closed after its row settles. */
    fun set(id: String, open: Boolean) {
        if (open) {
            openId = id
            confirmingId = null
        } else if (openId == id) {
            openId = null
        }
    }

    /** Closes the open row and the confirm; returns true when one of them was showing. */
    fun close(): Boolean {
        val was = openId != null || confirmingId != null
        openId = null
        confirmingId = null
        return was
    }
}
