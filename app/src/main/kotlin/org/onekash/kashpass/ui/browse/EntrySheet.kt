package org.onekash.kashpass.ui.browse

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetProperties
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.material3.SuggestionChip
import androidx.compose.ui.platform.LocalResources
import java.time.Instant
import java.time.ZoneId
import kotlinx.coroutines.launch
import org.onekash.kashpass.ui.format.BackupFormat
import org.onekash.kashpass.ui.format.EntryTimes
import org.onekash.kashpass.ui.format.Expiry
import org.onekash.kashpass.ui.components.InlineConfirm
import org.onekash.kashpass.ui.format.WebLink
import org.onekash.kashpass.vault.index.FieldValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.SecureFlagPolicy
import org.onekash.kashpass.R
import org.onekash.kashpass.vault.index.EntryDetails
import org.onekash.kashpass.vault.index.EntryField
import org.onekash.kashpass.vault.index.FieldKind

/** Shown in place of a protected value; the same length for every value, so it hides the length. */
private const val MASK = "••••••••"

/**
 * Shows the details sheet for one entry: title, group, an expiry line when it expired or expires
 * within a week, tags, one row per field with copy (and reveal for masked fields), attachment
 * names, then when it was created and edited. History is never shown. Each field shows its
 * [shown] value, with `{REF:}` references resolved; until [shown] is set the rows show labels
 * only and their buttons are off. A field holding a placeholder after resolution, which KashPass
 * does not fill in, gets an inline note. [onCopy] receives the field and the snackbar messages
 * for success and failure, which name the field and never hold the value; while [confirming]
 * names a field, an inline confirm under it copies through [onConfirmCopy] or closes through
 * [onCancelCopy]. A plain URL that [WebLink] accepts gets an open button; [onOpenUrl] returns
 * false when no app opens it. Tapping a tag calls [onTag]. Times are worded relative to [now] in
 * [zone]. [EntrySheetTest] covers expiry, tags, the open button, references, the confirm and the
 * footer.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntrySheet(
    details: EntryDetails,
    revealed: Set<String>,
    snackbar: SnackbarHostState,
    onDismiss: () -> Unit,
    onToggleReveal: (String) -> Unit,
    onCopy: (field: EntryField, copied: String, failed: String) -> Unit,
    shown: Map<String, ShownField>?,
    confirming: String? = null,
    onConfirmCopy: (field: EntryField, copied: String, failed: String) -> Unit = { _, _, _ -> },
    onCancelCopy: () -> Unit = {},
    onEdit: (() -> Unit)? = null,
    now: Instant = Instant.now(),
    zone: ZoneId = ZoneId.systemDefault(),
    onOpenUrl: ((String) -> Boolean)? = null,
    onTag: ((String) -> Unit)? = null,
) {
    val resources = LocalResources.current
    val scope = rememberCoroutineScope()
    val expiry = EntryTimes.expiry(details.expiry, now, zone)
    val open: ((String) -> Boolean, String) -> Unit = { openUrl, link ->
        if (!openUrl(link)) {
            scope.launch { snackbar.showMessage(resources.getString(R.string.entry_no_browser), resources.getString(R.string.browse_dismiss)) }
        }
    }
    // Full height: long notes and custom fields get room and there is no half-open state.
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        modifier = Modifier.fillMaxHeight(),
        // The sheet is its own window; SecureOn sets FLAG_SECURE on it whatever the activity sets.
        properties = ModalBottomSheetProperties(securePolicy = SecureFlagPolicy.SecureOn),
    ) {
        Box(Modifier.fillMaxSize()) {
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
                val title = details.title ?: stringResource(R.string.browse_untitled)
                Row(Modifier.padding(start = 24.dp, end = 8.dp, top = 8.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
                        details.groupName?.let {
                            Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        if (expiry is Expiry.Expired || expiry is Expiry.Soon) {
                            Text(
                                EntryTimes.expiryLine(resources, expiry, now, zone).orEmpty(),
                                style = MaterialTheme.typography.bodyMedium,
                                color = if (expiry is Expiry.Expired) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary,
                                modifier = Modifier.padding(top = 2.dp),
                            )
                        }
                    }
                    onEdit?.let { edit ->
                        IconButton(onClick = edit) {
                            Icon(painterResource(R.drawable.ic_edit), stringResource(R.string.browse_edit, title))
                        }
                    }
                }
                if (details.tags.isNotEmpty()) {
                    FlowRow(
                        Modifier.padding(horizontal = 24.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        for (tag in details.tags) {
                            SuggestionChip(onClick = { onTag?.invoke(tag) }, label = { Text(tag) }, enabled = onTag != null)
                        }
                    }
                }
                for (field in details.fields) {
                    val label = field.label()
                    val copied = stringResource(R.string.entry_copied, label)
                    val failed = stringResource(R.string.entry_copy_failed, label)
                    val value = shown?.get(field.name)
                    FieldRow(
                        field = field,
                        label = label,
                        value = value,
                        revealed = field.name in revealed,
                        onToggleReveal = { onToggleReveal(field.name) },
                        onCopy = { onCopy(field, copied, failed) },
                        onOpen = webLink(field, value)?.let { link -> onOpenUrl?.let { openUrl -> { open(openUrl, link) } } },
                    )
                    if (value?.keepsPlaceholders == true) {
                        Text(
                            stringResource(R.string.entry_placeholder_note),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(start = 24.dp, end = 24.dp, bottom = 4.dp),
                        )
                    }
                    if (confirming == field.name) {
                        InlineConfirm(
                            text = stringResource(R.string.entry_copy_password_ref, label),
                            action = stringResource(R.string.entry_copy_confirm),
                            enabled = value != null,
                            onCancel = onCancelCopy,
                            onConfirm = { onConfirmCopy(field, copied, failed) },
                            modifier = Modifier.padding(start = 24.dp),
                            destructive = false,
                        )
                    }
                }
                if (details.attachmentNames.isNotEmpty()) {
                    HorizontalDivider(Modifier.padding(vertical = 8.dp))
                    Text(
                        stringResource(R.string.entry_attachments),
                        style = MaterialTheme.typography.labelLarge,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                    )
                    for (name in details.attachmentNames) AttachmentRow(name)
                }
                TimesFooter(details, expiry, now, zone)
            }
            // The sheet window covers the screen's snackbar host, so the sheet shows its own.
            SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter))
        }
    }
}

@Composable
private fun FieldRow(
    field: EntryField,
    label: String,
    value: ShownField?,
    revealed: Boolean,
    onToggleReveal: () -> Unit,
    onCopy: () -> Unit,
    onOpen: (() -> Unit)? = null,
) {
    // A field that inserts a password is masked like a protected one; until resolved, no value
    // shows.
    val maskable = field.isProtected || value?.value is FieldValue.Protected
    val masked = maskable && !revealed
    val hidden = stringResource(R.string.entry_hidden)
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 24.dp, end = 8.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (value != null) {
                Text(
                    text = if (masked) MASK else value.value.reveal(),
                    style = MaterialTheme.typography.bodyLarge,
                    fontFamily = if (maskable) FontFamily.Monospace else null,
                    // Otherwise a screen reader reads out eight bullets.
                    modifier = if (masked) Modifier.semantics { contentDescription = hidden } else Modifier,
                )
            }
        }
        if (maskable) {
            IconButton(onClick = onToggleReveal, enabled = value != null) {
                Icon(
                    painterResource(if (revealed) R.drawable.ic_visibility_off else R.drawable.ic_visibility),
                    stringResource(if (revealed) R.string.entry_hide else R.string.entry_show, label),
                )
            }
        }
        onOpen?.let { open ->
            IconButton(onClick = open) {
                Icon(painterResource(R.drawable.ic_open_in_new), stringResource(R.string.entry_open, label))
            }
        }
        IconButton(onClick = onCopy, enabled = value != null) {
            Icon(painterResource(R.drawable.ic_content_copy), stringResource(R.string.entry_copy, label))
        }
    }
}

// A URL that inserts a password stays masked, so it gets no open button.
private fun webLink(field: EntryField, value: ShownField?): String? =
    if (field.kind == FieldKind.URL) (value?.value as? FieldValue.Plain)?.let { WebLink.of(it.text) } else null

/** Shows created, edited and a later expiry; TalkBack reads full dates and times. */
@Composable
private fun TimesFooter(details: EntryDetails, expiry: Expiry, now: Instant, zone: ZoneId) {
    val resources = LocalResources.current
    val shown = listOfNotNull(
        details.created?.let { resources.getString(R.string.entry_created, EntryTimes.footer(resources, it, now, zone)) },
        details.modified?.let { resources.getString(R.string.entry_edited, EntryTimes.footer(resources, it, now, zone)) },
        (expiry as? Expiry.Later)?.let { EntryTimes.expiryLine(resources, it, now, zone) },
    )
    if (shown.isEmpty()) return
    val spoken = listOfNotNull(
        details.created?.let { resources.getString(R.string.entry_created, BackupFormat.dateTime(it, zone)) },
        details.modified?.let { resources.getString(R.string.entry_edited, BackupFormat.dateTime(it, zone)) },
        (expiry as? Expiry.Later)?.let { resources.getString(R.string.entry_expires_later, BackupFormat.dateTime(it.at, zone)) },
    )
    HorizontalDivider(Modifier.padding(vertical = 8.dp))
    Text(
        shown.joinToString(" · "),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier
            .padding(horizontal = 24.dp, vertical = 4.dp)
            .semantics { contentDescription = spoken.joinToString(". ") },
    )
}

@Composable
private fun AttachmentRow(name: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(painterResource(R.drawable.ic_attach_file), contentDescription = null, modifier = Modifier.size(20.dp))
        Column {
            Text(name, style = MaterialTheme.typography.bodyLarge)
            Text(
                stringResource(R.string.entry_attachment_later),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun EntryField.label(): String = when (kind) {
    FieldKind.USER_NAME -> stringResource(R.string.field_user_name)
    FieldKind.PASSWORD -> stringResource(R.string.field_password)
    FieldKind.URL -> stringResource(R.string.field_url)
    FieldKind.NOTES -> stringResource(R.string.field_notes)
    FieldKind.CUSTOM -> name
}
