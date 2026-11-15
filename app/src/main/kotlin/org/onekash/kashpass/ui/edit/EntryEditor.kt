package org.onekash.kashpass.ui.edit

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.TextObfuscationMode
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import kotlin.math.roundToInt
import org.onekash.kashpass.R
import org.onekash.kashpass.ui.input.NoPersonalizedLearning
import org.onekash.kashpass.ui.input.noAutofill
import org.onekash.kashpass.ui.format.SaveProblem
import org.onekash.kashpass.vault.generate.PasswordGenerator
import org.onekash.kashpass.vault.save.SaveResult
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.foundation.layout.size

/**
 * Shows the entry editor: the five standard fields, a password generator, and for a new entry the
 * group it goes into. While a save runs, every control is disabled and "Saving…" replaces Save in
 * the top bar; a refusal the editor can explain shows in place. A close with unsaved changes
 * shows "Discard?" in the close button's place ([EditorUiState.discardConfirm]). Everything comes
 * from [state] and the [password] field.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryEditor(
    state: EditorUiState,
    password: TextFieldState,
    onTitle: (String) -> Unit,
    onUserName: (String) -> Unit,
    onUrl: (String) -> Unit,
    onNotes: (String) -> Unit,
    onGroup: (String?) -> Unit,
    onLength: (Int) -> Unit,
    onSymbols: (Boolean) -> Unit,
    onGenerate: () -> Unit,
    onSave: () -> Unit,
    onClose: () -> Unit,
) {
    val enabled = !state.saving
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(if (state.adding) R.string.editor_title_new else R.string.editor_title_edit)) },
                navigationIcon = {
                    // A close with unsaved changes turns the button into a tonal error box reading
                    // "Discard?", so the second tap is an answer to a visible question.
                    if (state.discardConfirm) {
                        Button(
                            onClick = onClose,
                            enabled = enabled,
                            modifier = Modifier.padding(start = 8.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.errorContainer,
                                contentColor = MaterialTheme.colorScheme.onErrorContainer,
                            ),
                            elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp),
                        ) {
                            Text(stringResource(R.string.editor_discard_confirm), maxLines = 1, softWrap = false)
                        }
                    } else {
                        IconButton(onClick = onClose, enabled = enabled) {
                            Icon(painterResource(R.drawable.ic_close), stringResource(R.string.editor_close))
                        }
                    }
                },
                actions = {
                    // In the top bar, which doesn't scroll, so the save shows wherever the form is.
                    if (state.saving) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.padding(end = 16.dp),
                        ) {
                            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                            Text(
                                stringResource(R.string.editor_saving),
                                style = MaterialTheme.typography.labelLarge,
                                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                            )
                        }
                    } else {
                        TextButton(onClick = onSave, modifier = Modifier.testTag(SAVE_TAG)) {
                            Text(stringResource(R.string.editor_save))
                        }
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().imePadding().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Refusals the editor can explain; the other results show their choices in a sheet.
            state.problem?.takeIf(SaveProblem::inline)?.let { Problem(it) }
            if (state.adding) GroupField(state, enabled, onGroup)
            Field(state.title, onTitle, R.string.field_title, "Title" in state.protectedKeys, enabled)
            Field(state.userName, onUserName, R.string.field_user_name, "UserName" in state.protectedKeys, enabled)
            PasswordField(password, enabled)
            Generator(state, enabled, onLength, onSymbols, onGenerate)
            Field(state.url, onUrl, R.string.field_url, "URL" in state.protectedKeys, enabled)
            Field(state.notes, onNotes, R.string.field_notes, "Notes" in state.protectedKeys, enabled, Modifier.padding(bottom = 24.dp), singleLine = false)
        }
    }
}

/**
 * Shows a standard field other than the password, in clear whatever the vault stores. One the
 * vault stores protected gets no autocorrect or keyboard learning. Autofill fills and saves no
 * field.
 */
@Composable
private fun Field(
    value: String,
    onChange: (String) -> Unit,
    label: Int,
    protected: Boolean,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    singleLine: Boolean = true,
) {
    val field = @Composable {
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            modifier = modifier.fillMaxWidth().noAutofill(),
            enabled = enabled,
            label = { Text(stringResource(label)) },
            singleLine = singleLine,
            minLines = if (singleLine) 1 else 3,
            keyboardOptions = if (protected) KeyboardOptions(autoCorrectEnabled = false) else KeyboardOptions.Default,
        )
    }
    if (protected) NoPersonalizedLearning(field) else field()
}

@Composable
private fun PasswordField(password: TextFieldState, enabled: Boolean) = NoPersonalizedLearning {
    var revealed by remember { mutableStateOf(false) }
    OutlinedSecureTextField(
        state = password,
        modifier = Modifier.fillMaxWidth().noAutofill(),
        enabled = enabled,
        label = { Text(stringResource(R.string.field_password)) },
        textObfuscationMode = if (revealed) TextObfuscationMode.Visible else TextObfuscationMode.RevealLastTyped,
        trailingIcon = {
            val description = stringResource(if (revealed) R.string.editor_hide_password else R.string.editor_show_password)
            IconButton(onClick = { revealed = !revealed }, modifier = Modifier.semantics { contentDescription = description }) {
                Icon(painterResource(if (revealed) R.drawable.ic_visibility_off else R.drawable.ic_visibility), contentDescription = null)
            }
        },
    )
}

@Composable
private fun Generator(state: EditorUiState, enabled: Boolean, onLength: (Int) -> Unit, onSymbols: (Boolean) -> Unit, onGenerate: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            FilledTonalButton(onClick = onGenerate, enabled = enabled) {
                Icon(painterResource(R.drawable.ic_refresh), contentDescription = null, modifier = Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.editor_generate))
            }
            Text(pluralStringResource(R.plurals.editor_length, state.length, state.length), style = MaterialTheme.typography.bodyMedium)
        }
        val lengthLabel = stringResource(R.string.editor_length_label)
        Slider(
            value = state.length.toFloat(),
            onValueChange = { onLength(it.roundToInt()) },
            enabled = enabled,
            valueRange = PasswordGenerator.MIN_LENGTH.toFloat()..PasswordGenerator.MAX_LENGTH.toFloat(),
            steps = PasswordGenerator.MAX_LENGTH - PasswordGenerator.MIN_LENGTH - 1,
            modifier = Modifier.semantics {
                contentDescription = lengthLabel
                stateDescription = state.length.toString()
            },
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.editor_symbols), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
            Switch(checked = state.symbols, onCheckedChange = onSymbols, enabled = enabled)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GroupField(state: EditorUiState, enabled: Boolean, onGroup: (String?) -> Unit) {
    var open by remember { mutableStateOf(false) }
    val top = state.groups.firstOrNull { it.isTopLevel }
    val selected = state.groups.firstOrNull { it.id == state.groupId && !it.isTopLevel }
    val topLabel = stringResource(R.string.editor_group_top_level)
    ExposedDropdownMenuBox(expanded = open, onExpandedChange = { if (enabled) open = it }) {
        OutlinedTextField(
            value = selected?.label ?: topLabel,
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            label = { Text(stringResource(R.string.editor_group)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = open) },
            modifier = Modifier.fillMaxWidth().menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable, enabled).noAutofill(),
        )
        ExposedDropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            for (choice in state.groups) {
                DropdownMenuItem(
                    text = { Text(if (choice.isTopLevel) topLabel else choice.label) },
                    onClick = {
                        onGroup(if (choice === top) null else choice.id)
                        open = false
                    },
                )
            }
        }
    }
}

@Composable
private fun Problem(result: SaveResult) {
    Text(
        stringResource(SaveProblem.message(result)),
        color = MaterialTheme.colorScheme.error,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
    )
}

/** Tag of the editor's Save action, for tests. */
const val SAVE_TAG = "editor_save"
