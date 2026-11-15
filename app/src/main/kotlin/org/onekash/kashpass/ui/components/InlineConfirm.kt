package org.onekash.kashpass.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.onekash.kashpass.R

/**
 * Shows a two-tap confirm in place of a dialog: [text], Cancel and [action], which is off unless
 * [enabled] and red when [destructive].
 */
@Composable
fun InlineConfirm(
    text: String,
    action: String,
    enabled: Boolean,
    onCancel: () -> Unit,
    onConfirm: () -> Unit,
    modifier: Modifier = Modifier,
    destructive: Boolean = true,
) {
    Column(modifier.fillMaxWidth().padding(end = 16.dp, bottom = 8.dp)) {
        Text(text, style = MaterialTheme.typography.bodyMedium)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = onCancel) { Text(stringResource(R.string.delete_cancel)) }
            Button(
                onClick = onConfirm,
                enabled = enabled,
                colors = if (destructive) {
                    ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError)
                } else {
                    ButtonDefaults.buttonColors()
                },
                modifier = Modifier.padding(start = 8.dp),
            ) { Text(action) }
        }
    }
}
