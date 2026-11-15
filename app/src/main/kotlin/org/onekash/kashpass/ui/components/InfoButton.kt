package org.onekash.kashpass.ui.components

import androidx.compose.material3.AssistChip
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RichTooltip
import androidx.compose.material3.Text
import androidx.compose.material3.TooltipBox
import androidx.compose.material3.TooltipDefaults
import androidx.compose.material3.rememberTooltipState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.size
import kotlinx.coroutines.launch
import org.onekash.kashpass.R

/**
 * Shows an ⓘ button that opens [text] under [title] in a persistent rich tooltip, in place. The
 * button takes its own tap, so it never toggles the row it sits on, and keeps Material's 48dp
 * touch target. [InfoButtonTest] covers it.
 */
@Composable
fun InfoButton(title: String, text: String) {
    InfoTooltip(title, text) { show ->
        IconButton(onClick = show) {
            Icon(
                painterResource(R.drawable.ic_info),
                contentDescription = stringResource(R.string.info_about, title),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

/**
 * Shows an outlined chip labelled [label] that opens [text] under [label] in the same tooltip as
 * [InfoButton]. The chip takes its own tap, so it never opens the card it sits on, and keeps
 * Material's 48dp touch target.
 */
@Composable
fun InfoChip(label: String, text: String) {
    InfoTooltip(label, text) { show ->
        AssistChip(onClick = show, label = { Text(label) })
    }
}

// Anchors a persistent rich tooltip with [title] and [text] to [anchor], which opens it.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun InfoTooltip(title: String, text: String, anchor: @Composable (show: () -> Unit) -> Unit) {
    val tooltip = rememberTooltipState(isPersistent = true)
    val scope = rememberCoroutineScope()
    TooltipBox(
        positionProvider = TooltipDefaults.rememberRichTooltipPositionProvider(),
        tooltip = {
            RichTooltip(title = { Text(title) }) { Text(text) }
        },
        state = tooltip,
    ) {
        anchor { scope.launch { tooltip.show() } }
    }
}
