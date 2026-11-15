package org.onekash.kashpass.ui.browse

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarResult
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import org.onekash.kashpass.ui.components.InlineDeleteConfirm
import org.onekash.kashpass.ui.components.RevealedRow
import org.onekash.kashpass.ui.components.SwipeRevealRow
import org.onekash.kashpass.ui.format.BackupFormat
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.onekash.kashpass.vault.edit.DeleteKind
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SearchBar
import androidx.compose.material3.SearchBarDefaults
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.snapshotFlow
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import java.time.Instant
import java.time.ZoneId
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.launch
import org.onekash.kashpass.R
import org.onekash.kashpass.ui.components.KashPose
import org.onekash.kashpass.ui.components.KashArt
import org.onekash.kashpass.ui.components.KASH_ASPECT_RATIO
import org.onekash.kashpass.ui.components.KASH_TAG
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.layout.SubcomposeLayout
import org.onekash.kashpass.ui.format.EntryTimes
import org.onekash.kashpass.ui.input.noAutofill
import org.onekash.kashpass.ui.format.UiMessage
import org.onekash.kashpass.ui.format.KdfFormat
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.index.EntryField
import org.onekash.kashpass.vault.index.EntryRow
import org.onekash.kashpass.vault.index.MatchSource
import org.onekash.kashpass.vault.index.SearchMatch
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator

/**
 * Shows the unlocked vault: search bar with the Settings action, the banners, group chips and
 * the entry list. All vault state comes from [state]; the screen keeps only UI state (focus,
 * snackbar, scroll). The search field takes focus once per unlock
 * ([BrowseUiState.searchFocusPending]); a touch on the list or its empty message, opening an
 * entry, picking a chip or opening Settings clears it, so the keyboard doesn't stay up. The
 * details sheet opens while [BrowseUiState.openEntry] is set.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BrowseScreen(
    state: BrowseUiState,
    onQueryChange: (String) -> Unit,
    onSelectChip: (Chip) -> Unit,
    onOpenEntry: (String) -> Unit,
    onCloseEntry: () -> Unit,
    onToggleReveal: (String) -> Unit,
    onCopy: (EntryField) -> CopyOutcome,
    onDismissWeakWarning: () -> Unit,
    onOpenSettings: () -> Unit,
    onSubmitSearch: () -> Unit,
    onSearchFocused: () -> Unit,
    messages: Flow<UiMessage> = emptyFlow(),
    onEdit: (String) -> Unit = {},
    onAdd: () -> Unit = {},
    deletes: Flow<DeleteEvent> = emptyFlow(),
    deleteKind: (String) -> DeleteKind? = { null },
    onDelete: (String) -> Unit = {},
    onDeletePermanently: (String) -> Unit = {},
    onUndoDelete: () -> Unit = {},
    onOpenUrl: ((String) -> Boolean)? = null,
    onSearchTag: (String) -> Unit = {},
    onConfirmCopy: (EntryField) -> Boolean = { false },
    onCancelCopy: () -> Unit = {},
    onSaveAsNewFile: () -> Unit = {},
    /** The remembered vault that Save as new file puts a copy in place of, or null. */
    saveAsNewReplaces: String? = null,
    onCloseBackup: () -> Unit = {},
    onAcceptOlderFile: () -> Unit = {},
    onDismissBytesAfterEnd: () -> Unit = {},
    /** The phone's biometric as a noun ("fingerprint"), for the offer card. */
    offerNoun: String = "",
    onTurnOnBiometric: () -> Unit = {},
    onDismissOffer: () -> Unit = {},
    onOfferShown: () -> Unit = {},
) {
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val keyboard = LocalSoftwareKeyboardController.current
    val focusManager = LocalFocusManager.current
    val searchFocus = remember { FocusRequester() }
    val searching = state.searching
    val dropFocus: () -> Unit = {
        focusManager.clearFocus()
        keyboard?.hide()
    }
    val resources = LocalResources.current
    val dismiss = stringResource(R.string.browse_dismiss)
    LaunchedEffect(messages) {
        messages.collect { message ->
            if (snackbar.showMessage(message.text, dismiss, message.actionLabel)) message.onAction()
        }
    }
    // Show the Undo snackbar while deletes are pending. A new count replaces it; 0 removes it
    // (window over, another save carried the deletes, or Undo). The window runs in the save layer,
    // so a message that replaces this snackbar hides Undo without stopping the save.
    val pending = state.pendingDeletes
    LaunchedEffect(pending) {
        if (pending == 0) return@LaunchedEffect
        snackbar.currentSnackbarData?.dismiss()
        val result = snackbar.showSnackbar(
            resources.getQuantityString(R.plurals.delete_moved_to_bin, pending, pending),
            actionLabel = resources.getString(R.string.delete_undo),
            duration = SnackbarDuration.Indefinite,
        )
        if (result == SnackbarResult.ActionPerformed) onUndoDelete()
    }
    LaunchedEffect(deletes) {
        deletes.collect { event ->
            snackbar.showMessage(resources.getString(event.message()), dismiss)
        }
    }
    val swipe = SwipeActions(
        enabled = state.canEdit,
        revealed = remember { RevealedRow() },
        deleteKind = deleteKind,
        onDelete = onDelete,
        onDeletePermanently = onDeletePermanently,
    )

    Scaffold(
        topBar = {
            SearchBar(
                inputField = {
                    // Initial focus belongs next to the field it targets: the top bar is
                    // composed during measure, so an effect elsewhere can run before the
                    // requester is attached
                    // (developer.android.com/develop/ui/compose/touch-input/focus/request-focus.)
                    if (state.searchFocusPending) {
                        LaunchedEffect(Unit) {
                            // Counted as given only when focus moved, so a failed request retries.
                            if (searchFocus.requestFocus()) {
                                keyboard?.show()
                                onSearchFocused()
                            }
                        }
                    }
                    SearchBarDefaults.InputField(
                        query = state.query,
                        onQueryChange = onQueryChange,
                        onSearch = {
                            dropFocus()
                            onSubmitSearch()
                        },
                        modifier = Modifier.focusRequester(searchFocus).noAutofill(),
                        // Results replace the list below, so the bar never expands over it.
                        expanded = false,
                        onExpandedChange = {},
                        placeholder = { Text(stringResource(R.string.browse_search_placeholder)) },
                        leadingIcon = { Icon(painterResource(R.drawable.ic_search), contentDescription = null) },
                        trailingIcon = {
                            Row {
                                if (state.query.isNotEmpty()) {
                                    IconButton(onClick = { onQueryChange("") }) {
                                        Icon(painterResource(R.drawable.ic_close), stringResource(R.string.browse_clear_search))
                                    }
                                }
                                IconButton(
                                    onClick = {
                                        // Settings replaces this screen: hide the keyboard first.
                                        dropFocus()
                                        onOpenSettings()
                                    },
                                ) {
                                    Icon(painterResource(R.drawable.ic_settings), stringResource(R.string.browse_settings))
                                }
                            }
                        },
                    )
                },
                expanded = false,
                onExpandedChange = {},
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            ) {}
        },
        snackbarHost = { if (state.openEntry == null) SnackbarHost(snackbar) },
        floatingActionButton = {
            if (state.canEdit) {
                FloatingActionButton(onClick = {
                    dropFocus()
                    onAdd()
                }) {
                    Icon(painterResource(R.drawable.ic_add), stringResource(R.string.browse_add))
                }
            }
        },
    ) { padding ->
        // The list scrolls behind the navigation bar, so only its content is inset at the bottom.
        val bottom = padding.calculateBottomPadding()
        Column(Modifier.padding(top = padding.calculateTopPadding()).fillMaxSize()) {
            val clearsFocus = Modifier.clearFocusOnTouch(dropFocus)
            if (state.biometricOffer) {
                LaunchedEffect(Unit) { onOfferShown() }
                BiometricOfferCard(offerNoun, state.enabling, onTurnOnBiometric, onDismissOffer)
            }
            state.readOnly?.let { ReadOnlyBannerRow(it, state.now, !state.working, saveAsNewReplaces, onSaveAsNewFile, onCloseBackup) }
            state.olderThan?.let { OlderFileBannerRow(it, !state.working, onAcceptOlderFile) }
            state.weakKdf?.let { WeakBanner(it, onDismissWeakWarning) }
            if (state.bytesAfterEnd) BytesAfterEndRow(onDismissBytesAfterEnd)
            if (!searching && !state.vaultEmpty) {
                ChipRow(state.chips, state.selectedChip) { chip ->
                    dropFocus()
                    onSelectChip(chip)
                }
                Spacer(Modifier.height(8.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.7f))
                if (state.selectedChip != Chip.All) {
                    Text(
                        pluralStringResource(R.plurals.browse_entry_count, state.rows.size, state.rows.size),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 16.dp, top = 8.dp),
                    )
                }
            }
            when {
                state.vaultEmpty && !searching -> EmptyVault(
                    // No Kash while a warning banner shows above the list.
                    withKash = !state.warningShown,
                    modifier = clearsFocus,
                )
                state.rows.isEmpty() && searching -> Message(stringResource(R.string.browse_no_matches, state.query.trim()), clearsFocus)
                // Opening drops focus too, for clicks that send no touch (TalkBack, a key).
                else -> EntryList(state, swipe, PaddingValues(bottom = bottom), clearsFocus) { id ->
                    dropFocus()
                    onOpenEntry(id)
                }
            }
        }
        // After the content, so it draws over the top edge and the list doesn't move when it shows.
        if (state.working) LinearProgressIndicator(Modifier.padding(top = padding.calculateTopPadding()).fillMaxWidth())
    }

    state.openEntry?.let { details ->
        EntrySheet(
            details = details,
            revealed = state.revealed,
            snackbar = snackbar,
            onDismiss = onCloseEntry,
            onToggleReveal = onToggleReveal,
            shown = state.shownFields,
            confirming = state.copyConfirm,
            onCopy = { field, copied, failed ->
                when (onCopy(field)) {
                    CopyOutcome.COPIED -> scope.launch { snackbar.showMessage(copied, dismiss) }
                    CopyOutcome.FAILED -> scope.launch { snackbar.showMessage(failed, dismiss) }
                    CopyOutcome.CONFIRM -> Unit
                }
            },
            onConfirmCopy = { field, copied, failed ->
                val message = if (onConfirmCopy(field)) copied else failed
                scope.launch { snackbar.showMessage(message, dismiss) }
            },
            onCancelCopy = onCancelCopy,
            onEdit = if (state.canEdit) ({ onEdit(details.id) }) else null,
            now = state.now,
            onOpenUrl = onOpenUrl,
            onTag = onSearchTag,
        )
    }
}

/**
 * Shows the one-time offer of biometric unlock after a password unlock, above the list so it covers
 * nothing; search and the list keep working while it shows.
 */
@Composable
private fun BiometricOfferCard(noun: String, enabling: Boolean, onTurnOn: () -> Unit, onDismiss: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Column(Modifier.padding(start = 16.dp, end = 8.dp, top = 12.dp, bottom = 4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(painterResource(R.drawable.ic_fingerprint), contentDescription = null, modifier = Modifier.size(20.dp))
                Text(stringResource(R.string.offer_title, noun), style = MaterialTheme.typography.titleSmall)
            }
            Text(
                stringResource(R.string.offer_body),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 4.dp, end = 8.dp),
            )
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End, verticalAlignment = Alignment.CenterVertically) {
                // Making the key takes seconds in StrongBox; both buttons are disabled until it
                // ends.
                if (enabling) CircularProgressIndicator(Modifier.padding(end = 8.dp).size(20.dp), strokeWidth = 2.dp)
                TextButton(onClick = onDismiss, enabled = !enabling) { Text(stringResource(R.string.offer_not_now)) }
                FilledTonalButton(onClick = onTurnOn, enabled = !enabling) { Text(stringResource(R.string.offer_turn_on)) }
            }
        }
    }
}

/**
 * Shows the older-file banner: the file is older than a version KashPass saw before, which a
 * restore from the provider's version history causes. Editing keeps working; "Use this version"
 * accepts it.
 */
@Composable
private fun OlderFileBannerRow(seen: Instant, enabled: Boolean, onAccept: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 4.dp)) {
            Text(
                stringResource(R.string.banner_older_file, BackupFormat.dateTime(seen)),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            TextButton(onClick = onAccept, enabled = enabled) { Text(stringResource(R.string.banner_use_this_version)) }
        }
    }
}

/**
 * Shows the read-only banner; it has no dismiss, so it shows for as long as nothing can be saved.
 * A copy's age is relative to [now]. With [replaces] set, the hint names the remembered vault the
 * new file takes the place of, before Save as new file is tapped.
 */
@Composable
private fun ReadOnlyBannerRow(banner: ReadOnlyBanner, now: Instant, enabled: Boolean, replaces: String?, onSaveAsNew: () -> Unit, onClose: () -> Unit) {
    val backup = banner.backup
    val copyText = when (banner.reason) {
        ReadOnlyReason.LAST_COPY -> R.string.banner_last_copy
        ReadOnlyReason.LAST_COPY_CORRUPTED -> R.string.banner_last_copy_corrupted
        ReadOnlyReason.LAST_COPY_CORRUPTED_AFTER_HEADER -> R.string.banner_last_copy_repair
        ReadOnlyReason.BACKUP -> R.string.banner_backup
        else -> null
    }
    // A file read-only for its grant can be copied as it is, like a backup.
    val grantReadOnly = banner.reason == ReadOnlyReason.PROVIDER_READ_ONLY || banner.reason == ReadOnlyReason.OPENED_FROM_APP
    val text = when {
        copyText != null && backup != null ->
            stringResource(copyText, EntryTimes.past(LocalResources.current, backup.createdAt, now, ZoneId.systemDefault()))
        banner.reason == ReadOnlyReason.PROVIDER_READ_ONLY -> stringResource(R.string.banner_provider_read_only)
        banner.reason == ReadOnlyReason.OPENED_FROM_APP -> stringResource(R.string.banner_opened_from_app)
        else -> stringResource(R.string.banner_unsaveable)
    }
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 4.dp)) {
            Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            // Every copy and every file read-only for its grant can become a new file; none is
            // written over the file. Closing a last copy reopens a file that can't be opened and
            // locks, so only a backup has Close.
            if (backup != null || grantReadOnly) {
                Text(
                    replaces?.let { stringResource(R.string.banner_save_as_new_replaces, it) } ?: stringResource(R.string.banner_save_as_new_hint),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 4.dp),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = onSaveAsNew, enabled = enabled) { Text(stringResource(R.string.banner_save_as_new)) }
                    if (banner.reason == ReadOnlyReason.BACKUP) {
                        TextButton(onClick = onClose, enabled = enabled) { Text(stringResource(R.string.banner_close_backup)) }
                    }
                }
            }
        }
    }
}

/**
 * Replaces the shown snackbar with [text] for [SnackbarDuration.Short], the shortest Material
 * duration (Android lengthens it when the user set a longer accessibility timeout). The button
 * on the right is [actionLabel], or [dismissLabel] when the message has no action of its own.
 * Returns true when [actionLabel] was tapped. The Undo snackbar doesn't use this: its delete
 * window sets when it closes.
 */
internal suspend fun SnackbarHostState.showMessage(text: String, dismissLabel: String, actionLabel: String? = null): Boolean {
    currentSnackbarData?.dismiss()
    val result = showSnackbar(text, actionLabel = actionLabel ?: dismissLabel, duration = SnackbarDuration.Short)
    return actionLabel != null && result == SnackbarResult.ActionPerformed
}

private fun DeleteEvent.message(): Int = when (this) {
    DeleteEvent.Deleted -> R.string.delete_deleted
    DeleteEvent.NotSaved -> R.string.save_failed_generic
}

@Composable
private fun ChipRow(chips: List<Chip>, selected: Chip, onSelect: (Chip) -> Unit) {
    LazyRow(
        contentPadding = PaddingValues(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(chips, key = { it.key() }) { chip ->
            FilterChip(
                selected = chip == selected,
                onClick = { onSelect(chip) },
                label = { Text(chip.label(), maxLines = 1, overflow = TextOverflow.Ellipsis) },
            )
        }
    }
}

/** Runs swipe-to-delete for the list; [revealed] holds the open row and the inline confirm. */
class SwipeActions(
    val enabled: Boolean,
    val revealed: RevealedRow,
    val deleteKind: (String) -> DeleteKind?,
    val onDelete: (String) -> Unit,
    val onDeletePermanently: (String) -> Unit,
) {
    /** Runs the Delete button or action for [id]: to the bin at once, permanent after a confirm. */
    fun delete(id: String) {
        revealed.close()
        when (deleteKind(id)) {
            DeleteKind.TO_RECYCLE_BIN -> onDelete(id)
            DeleteKind.PERMANENT -> revealed.confirmingId = id
            null -> Unit
        }
    }
}

// Contacts-style list with pinned letter headers (developer.android.com/develop/ui/compose/lists).
@Composable
private fun EntryList(state: BrowseUiState, swipe: SwipeActions, contentPadding: PaddingValues, modifier: Modifier, onOpen: (String) -> Unit) {
    val entries = if (state.letterHeaders) withLetterHeaders(state.rows) else state.rows.map { ListEntry.Row(it) }
    val style = matchStyle(MaterialTheme.colorScheme.primaryContainer)
    val listState = rememberLazyListState()
    // Scrolling closes an open row.
    LaunchedEffect(listState) {
        snapshotFlow { listState.isScrollInProgress }.collect { if (it) swipe.revealed.close() }
    }
    // A tap with a row open only closes it.
    val open: (String) -> Unit = { id -> if (!swipe.revealed.close()) onOpen(id) }
    LazyColumn(modifier.fillMaxSize().testTag(LIST_TAG), state = listState, contentPadding = contentPadding) {
        for (entry in entries) {
            when (entry) {
                is ListEntry.Header -> stickyHeader(key = entry.key) { LetterHeader(entry.letter) }
                is ListEntry.Row -> item(key = entry.key) {
                    val row = entry.row
                    if (swipe.enabled && swipe.revealed.confirmingId == row.id) {
                        InlineDeleteConfirm(
                            onCancel = { swipe.revealed.confirmingId = null },
                            onConfirm = {
                                swipe.revealed.confirmingId = null
                                swipe.onDeletePermanently(row.id)
                            },
                        )
                    } else {
                        SwipeRevealRow(
                            enabled = swipe.enabled,
                            open = swipe.revealed.openId == row.id,
                            onOpenChange = { swipe.revealed.set(row.id, it) },
                            deleteLabel = stringResource(R.string.browse_delete, row.title ?: stringResource(R.string.browse_untitled)),
                            onDelete = { swipe.delete(row.id) },
                        ) { actions ->
                            EntryRowItem(
                                row, state.groupInRows, state.matches[row.id], style,
                                expired = EntryTimes.isExpired(row.expiry, state.now), actions = actions, onOpen = open,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LetterHeader(letter: String) {
    Text(
        letter,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(start = 16.dp, top = 10.dp, bottom = 2.dp)
            .semantics { heading() },
    )
}

/**
 * Shows one entry row. While searching, [match] says why it matched: a match in the title, user
 * name or group is highlighted in place (only in that field, so a protected title is never
 * marked); a match in a field the row doesn't show replaces the second line with
 * "<field> · <snippet>".
 */
@Composable
private fun EntryRowItem(
    row: EntryRow,
    showGroup: Boolean,
    match: SearchMatch?,
    style: SpanStyle,
    expired: Boolean,
    actions: Modifier,
    onOpen: (String) -> Unit,
) {
    val title = row.title ?: stringResource(R.string.browse_untitled)
    val group = when {
        !showGroup -> null
        row.inRecycleBin -> stringResource(R.string.browse_chip_recycle_bin)
        else -> row.groupName
    }
    // The match's textRange is in the same string the row shows for these three sources.
    fun inPlace(text: String, source: MatchSource) = highlighted(text, match?.textRange?.takeIf { match.source == source }, style)
    val reasonLabel = match?.let { offRowLabel(it) }
    val supporting: AnnotatedString? = if (match != null && reasonLabel != null) {
        highlighted(match.snippet, match.highlight, style, prefix = stringResource(R.string.browse_match_prefix, reasonLabel))
    } else {
        val parts = listOfNotNull(
            row.userName.ifEmpty { null }?.let { inPlace(it, MatchSource.USER_NAME) },
            group?.let { inPlace(it, MatchSource.GROUP) },
        )
        if (parts.isEmpty()) null else buildAnnotatedString { parts.forEachIndexed { i, p -> if (i > 0) append(" · "); append(p) } }
    }
    // Expired entries are struck through. TalkBack doesn't announce strikethrough, so the second
    // line also starts with "Expired".
    val expiredWord = stringResource(R.string.browse_expired)
    val error = MaterialTheme.colorScheme.error
    val secondLine = if (!expired) supporting else buildAnnotatedString {
        withStyle(SpanStyle(color = error)) { append(expiredWord) }
        supporting?.let {
            append(" · ")
            append(it)
        }
    }
    ListItem(
        leadingContent = { Initial(row.title) },
        headlineContent = {
            Text(
                inPlace(title, MatchSource.TITLE),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                textDecoration = if (expired) TextDecoration.LineThrough else null,
            )
        },
        supportingContent = secondLine?.let { { Text(it, maxLines = 1, overflow = TextOverflow.Ellipsis) } },
        modifier = Modifier.clickable { onOpen(row.id) }.then(actions),
    )
}

/** Returns the label for a match in a field the row doesn't show; null for title, user, group. */
@Composable
private fun offRowLabel(match: SearchMatch): String? = when (match.source) {
    MatchSource.TITLE, MatchSource.USER_NAME, MatchSource.GROUP -> null
    MatchSource.URL -> stringResource(R.string.field_url)
    MatchSource.TAG -> stringResource(R.string.browse_match_tag)
    MatchSource.NOTES -> stringResource(R.string.field_notes)
    MatchSource.CUSTOM_NAME -> stringResource(R.string.browse_match_field)
    MatchSource.CUSTOM_VALUE -> match.fieldName.orEmpty()
}

/** Tag of the entry list, for tests. */
const val LIST_TAG = "entry_list"

/**
 * Runs [onTouch] when a touch starts anywhere in this element, before its children (a row's click,
 * the list's scroll) see it, and without consuming it.
 */
private fun Modifier.clearFocusOnTouch(onTouch: () -> Unit) = pointerInput(Unit) {
    awaitEachGesture {
        awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
        onTouch()
    }
}

/** Tag of the round initial on each row, for tests. */
const val INITIAL_TAG = "entry_initial"

// The same title always gets the same color; the three container colors follow dynamic color.
@Composable
private fun Initial(title: String?) {
    val colors = MaterialTheme.colorScheme
    val (background, foreground) = when (Math.floorMod((title ?: "").hashCode(), 3)) {
        0 -> colors.primaryContainer to colors.onPrimaryContainer
        1 -> colors.secondaryContainer to colors.onSecondaryContainer
        else -> colors.tertiaryContainer to colors.onTertiaryContainer
    }
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(CircleShape)
            .background(background)
            .testTag(INITIAL_TAG)
            // Decoration: the title next to it is what a screen reader should say.
            .clearAndSetSemantics {},
        contentAlignment = Alignment.Center,
    ) {
        Text(initialOf(title), color = foreground, style = MaterialTheme.typography.titleMedium)
    }
}

/**
 * Returns the width Kash takes above the empty vault's text: 120 dp, or less to fit [width] and
 * [heightLeft] (the height the text leaves, Kash being [KASH_ASPECT_RATIO] in shape); null, so
 * Kash is left out, below 48 dp. BrowseScreenTest pins it.
 */
internal fun emptyVaultKashSize(heightLeft: Dp, width: Dp): Dp? =
    minOf(120.dp, width, heightLeft * KASH_ASPECT_RATIO).takeIf { it >= 48.dp }

// The empty vault's text, with Kash above it when [withKash] and there is room: the text is
// measured first and always shows.
@Composable
private fun EmptyVault(withKash: Boolean, modifier: Modifier) {
    val text = stringResource(R.string.browse_empty_vault)
    SubcomposeLayout(modifier.fillMaxSize().padding(32.dp)) { constraints ->
        val loose = constraints.copy(minWidth = 0, minHeight = 0)
        val label = subcompose("text") {
            Text(text, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge)
        }.map { it.measure(loose) }
        val labelHeight = label.maxOfOrNull { it.height } ?: 0
        val gap = 16.dp.roundToPx()
        // The parent is a full-size Column that doesn't scroll, so the height is bounded.
        val heightLeft = (constraints.maxHeight - labelHeight - gap).coerceAtLeast(0).toDp()
        val kashWidth = if (withKash) emptyVaultKashSize(heightLeft, constraints.maxWidth.toDp()) else null
        val kash = kashWidth?.let { w ->
            subcompose("kash") { KashArt(KashPose.CONTENT, Modifier.testTag(KASH_TAG)) }
                .map { it.measure(Constraints.fixed(w.roundToPx(), (w / KASH_ASPECT_RATIO).roundToPx())) }
        }.orEmpty()
        val kashHeight = kash.maxOfOrNull { it.height } ?: 0
        val total = labelHeight + if (kash.isEmpty()) 0 else kashHeight + gap
        val width = constraints.maxWidth
        val height = constraints.maxHeight
        layout(width, height) {
            var y = (height - total) / 2
            kash.forEach { it.place((width - it.width) / 2, y) }
            if (kash.isNotEmpty()) y += kashHeight + gap
            label.forEach { it.place((width - it.width) / 2, y) }
        }
    }
}

@Composable
private fun Message(text: String, modifier: Modifier) {
    Box(modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Text(text, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyLarge)
    }
}

/** Shows the weak-settings warning as a dismissible banner (tertiary container colors). */
@Composable
private fun WeakBanner(kdf: KdfSettings, onDismiss: () -> Unit) = DismissibleBanner(
    text = weakText(kdf),
    container = MaterialTheme.colorScheme.tertiaryContainer,
    content = MaterialTheme.colorScheme.onTertiaryContainer,
    icon = R.drawable.ic_warning,
    onDismiss = onDismiss,
)

// A dismissible note; the next save removes the data, so the row offers no other action.
@Composable
private fun BytesAfterEndRow(onDismiss: () -> Unit) = DismissibleBanner(
    text = stringResource(R.string.browse_bytes_after_end),
    container = MaterialTheme.colorScheme.secondaryContainer,
    content = MaterialTheme.colorScheme.onSecondaryContainer,
    icon = null,
    onDismiss = onDismiss,
)

@Composable
private fun DismissibleBanner(text: String, container: Color, content: Color, icon: Int?, onDismiss: () -> Unit) {
    Surface(color = container, contentColor = content, tonalElevation = 1.dp, modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            icon?.let { Icon(painterResource(it), contentDescription = null, modifier = Modifier.size(18.dp)) }
            Text(text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.browse_dismiss)) }
        }
    }
}

@Composable
private fun weakText(kdf: KdfSettings): String = when (kdf) {
    is KdfSettings.AesKdf -> pluralStringResource(R.plurals.browse_weak_aes, quantity(kdf.rounds), KdfFormat.count(kdf.rounds))
    is KdfSettings.Argon2 ->
        pluralStringResource(R.plurals.browse_weak_argon2, quantity(kdf.iterations), KdfFormat.count(kdf.iterations), KdfFormat.mib(kdf.memoryBytes))
}

// Plural rules take an Int; a count past Int.MAX_VALUE is clamped, which reads as plural.
private fun quantity(n: ULong): Int = n.coerceAtMost(Int.MAX_VALUE.toULong()).toInt()

@Composable
private fun Chip.label(): String = when (this) {
    Chip.All -> stringResource(R.string.browse_chip_all)
    is Chip.Group -> label
    Chip.RecycleBin -> stringResource(R.string.browse_chip_recycle_bin)
}

private fun Chip.key(): String = when (this) {
    Chip.All -> "all"
    is Chip.Group -> "group:$id"
    Chip.RecycleBin -> "bin"
}
