package org.onekash.kashpass.ui.browse

import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertIsNotFocused
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.click
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isHeading
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.assertLeftPositionInRootIsEqualTo
import androidx.compose.ui.test.swipeLeft
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onLast
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performImeAction
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeUp
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.onekash.kashpass.ui.components.KASH_ASPECT_RATIO
import org.onekash.kashpass.ui.components.KASH_TAG
import org.onekash.kashpass.vault.doc.ReadOnlyReason
import org.junit.Assert.assertNull
import androidx.compose.ui.unit.dp
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import androidx.compose.ui.test.assertAll
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.platform.ClipboardDeadlineStore
import org.onekash.kashpass.platform.SensitiveClipboard
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.Unlocked
import org.onekash.kashpass.testing.RecordingAlarm
import org.onekash.kashpass.testing.TouchModeRule
import org.onekash.kashpass.ui.browse.INITIAL_TAG
import org.onekash.kashpass.ui.browse.LIST_TAG
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.header.Argon2Variant
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.index.Chip
import org.onekash.kashpass.vault.testing.FakeVaultOpener
import org.onekash.kashpass.vault.testing.TestVaults
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.test.hasProgressBarRangeInfo
import androidx.compose.ui.test.assertIsNotEnabled

// A phone-sized screen, so every row and sheet field is laid out.
@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class BrowseScreenTest {

    @get:Rule(order = 0)
    val touchMode = TouchModeRule()

    @get:Rule(order = 1)
    val rule = createComposeRule()

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val clipboardManager = context.getSystemService(ClipboardManager::class.java)
    private val sessions = SessionHolder()
    private val opener = FakeVaultOpener()
    private val clipboard = SensitiveClipboard(
        clipboard = clipboardManager,
        deadlines = ClipboardDeadlineStore(context),
        alarm = RecordingAlarm(),
        scope = CoroutineScope(Dispatchers.Unconfined),
        isForeground = { true },
    )
    private var locks = 0

    private lateinit var vm: BrowseViewModel

    private fun show(bytes: ByteArray = browser, copy: (String) -> Boolean = clipboard::copy, bytesAfterEnd: Boolean = false) {
        val result = runBlocking { TestVaults.unlock(bytes) }
        sessions.set(Unlocked(TestVaults.LOCATION, result.session, result.kdf, result.showWeakWarning, bytesAfterEnd = bytesAfterEnd))
        vm = BrowseViewModel(sessions, opener, copyToClipboard = copy)
        rule.setContent {
            KashPassTheme {
                val state by vm.uiState.collectAsState()
                state?.let {
                    BrowseScreen(
                        state = it,
                        onQueryChange = vm::setQuery,
                        onSelectChip = vm::selectChip,
                        onOpenEntry = vm::openEntry,
                        onCloseEntry = vm::closeEntry,
                        onToggleReveal = vm::toggleReveal,
                        onCopy = vm::copy,
                        onDismissWeakWarning = vm::dismissWeakWarning,
                        onDismissBytesAfterEnd = vm::dismissBytesAfterEnd,
                        onOpenSettings = { locks++ },
                        onSubmitSearch = vm::openSingleResult,
                        onSearchFocused = vm::consumeSearchFocus,
                    )
                }
            }
        }
    }

    private fun search(text: String) = field.performTextInput(text)

    @Test
    fun `data after the end of the file shows a dismissible row`() {
        show(bytesAfterEnd = true)
        rule.onNodeWithText("This file has extra data after its end; saving removes it").assertExists()
        rule.onAllNodesWithText("Dismiss").onLast().performClick()
        rule.onNodeWithText("This file has extra data after its end; saving removes it").assertDoesNotExist()
    }

    @Test
    fun `rows show title, user name and group, untitled entries read (untitled), All is selected`() {
        show()
        rule.onNodeWithText("Example Mail").assertExists()
        rule.onNodeWithText("alice · Email").assertExists()
        rule.onNodeWithText("admin").assertExists()
        rule.onNodeWithText("(untitled)").assertExists()
        rule.onNodeWithText("nobody · Banking").assertExists()
        rule.onNodeWithText("All").assertIsSelected()
        rule.onNodeWithText("Old Bank").assertDoesNotExist()
    }

    @Test
    fun `All shows letter headers and a decorative initial on every row`() {
        show()
        for (letter in listOf("E", "R", "W", "#")) rule.onNode(hasText(letter) and isHeading()).assertExists()
        rule.onAllNodesWithTag(INITIAL_TAG, useUnmergedTree = true).assertCountEquals(5)
        // The initial is decoration; a screen reader reads the title.
        rule.onAllNodesWithText("E").assertCountEquals(1)
    }

    @Test
    fun `a selected group drops headers and the repeated group name, and shows a count`() {
        show()
        rule.onNodeWithText("Banking").performClick()
        rule.onNode(isHeading() and hasText("E")).assertDoesNotExist()
        rule.onNodeWithText("2 entries").assertExists()
        rule.onNodeWithText("bob").assertExists()
        rule.onNodeWithText("bob · Banking").assertDoesNotExist()
    }

    @Test
    fun `search results have no headers and name each entry's group`() {
        show()
        search("mail")
        rule.onNode(isHeading() and hasText("E")).assertDoesNotExist()
        rule.onNodeWithText("alice · Email").assertExists()
        rule.onNodeWithText("carol · Email").assertExists()
    }

    private fun highlightedText(text: String): List<String> {
        val node = rule.onNode(hasText(text), useUnmergedTree = true).fetchSemanticsNode()
        return node.config[SemanticsProperties.Text].flatMap { s -> s.spanStyles.map { s.text.substring(it.start, it.end) } }
    }

    @Test
    fun `a match in a field the row doesn't show names the field and highlights the match`() {
        show()
        for ((query, line, highlight) in listOf(
            Triple("mail.example", "URL · https://mail.example.com", "mail.example"),
            Triple("recovery", "Notes · Recovery hint: ünïcödé", "Recovery"),
            Triple("personal", "Tag · personal", "personal"),
            Triple("a-1234", "Account ID · A-1234", "A-1234"),
            Triple("account", "Field · Account ID", "Account"),
        )) {
            field.performTextClearance()
            search(query)
            rule.onNodeWithText(line).assertExists()
            assertEquals(query, listOf(highlight), highlightedText(line))
        }
    }

    @Test
    fun `a match in the title or user name is highlighted in place`() {
        show()
        search("alice")
        assertEquals(listOf("alice"), highlightedText("alice · Email"))
        assertEquals(emptyList<String>(), highlightedText("Example Mail"))
        field.performTextClearance()
        search("router")
        assertEquals(listOf("Router"), highlightedText("Router"))
    }

    @Test
    fun `a title stored protected is searched and highlighted`() {
        show(TestVaults.protectedTitleVault())
        search("bank")
        rule.onNodeWithText("Notes · bank login").assertDoesNotExist()
        assertEquals(listOf("bank"), highlightedText("Secret bank"))
    }

    @Test
    fun `a query that only a password matches shows no results`() {
        show()
        search("mail-pass")
        rule.onNodeWithText("No matches for \"mail-pass\"").assertExists()
    }

    private val field get() = rule.onNode(hasSetTextAction())

    @Test
    fun `the search field has focus when the browser first appears`() {
        show()
        field.assertIsFocused()
    }

    @Test
    fun `Enter with exactly one result opens it, and the field stays unfocused after the sheet closes`() {
        show()
        search("a-1234")
        field.performImeAction()
        rule.onNode(hasText("Example Mail") and isHeading()).assertExists()
        rule.runOnIdle { vm.closeEntry() }
        rule.onNode(hasText("Example Mail") and isHeading()).assertDoesNotExist()
        field.assertIsNotFocused()
    }

    @Test
    fun `Enter with several results opens nothing and clears the field's focus`() {
        show()
        search("mail")
        field.performImeAction()
        rule.onNode(hasText("Example Mail") and isHeading()).assertDoesNotExist()
        field.assertIsNotFocused()
    }

    @Test
    fun `an accessibility click on a row and a chip tap also clear the field's focus`() {
        show()
        rule.onNodeWithText("Router").performSemanticsAction(SemanticsActions.OnClick)
        field.assertIsNotFocused()
        rule.runOnIdle { vm.closeEntry() }
        field.performClick()
        field.assertIsFocused()
        rule.onNodeWithText("Banking").performClick()
        field.assertIsNotFocused()
    }

    @Test
    fun `opening Settings clears the field's focus`() {
        show()
        field.assertIsFocused()
        rule.onNodeWithContentDescription("Settings").performClick()
        field.assertIsNotFocused()
    }

    @Test
    fun `a match in the group name is highlighted in place`() {
        show()
        search("banking")
        assertEquals(listOf("Banking"), highlightedText("bob · Banking"))
    }

    @Test
    fun `tapping a row, tapping empty list space, or swiping the list clears the field's focus`() {
        show()
        rule.onNodeWithText("Router").performClick()
        field.assertIsNotFocused()
        rule.runOnIdle { vm.closeEntry() }

        field.performClick()
        field.assertIsFocused()
        rule.onNodeWithTag(LIST_TAG).performTouchInput { click(bottomCenter.copy(y = bottom - 20f)) }
        field.assertIsNotFocused()

        field.performClick()
        rule.onNodeWithTag(LIST_TAG).performTouchInput { swipeUp() }
        field.assertIsNotFocused()
    }

    @Test
    fun `a group chip filters the list, Parent and Name chips tell same-named groups apart`() {
        show()
        rule.onNodeWithText("Root / Email").assertExists()
        rule.onNodeWithText("Work / Email").performClick()
        rule.onNodeWithText("Work Mail").assertExists()
        rule.onNodeWithText("Example Mail").assertDoesNotExist()
        rule.onNodeWithText("All").performClick()
        rule.onNodeWithText("Example Mail").assertExists()
    }

    @Test
    fun `the Recycle bin chip shows only the bin's entries, with a count`() {
        show()
        rule.onNodeWithText("Recycle bin").performClick()
        rule.onNodeWithText("Old Bank").assertExists()
        rule.onNodeWithText("dave").assertExists()
        rule.onNodeWithText("1 entry").assertExists()
        rule.onNodeWithText("Example Mail").assertDoesNotExist()
    }

    @Test
    fun `a vault with no entries shows the empty state with Kash`() {
        show(empty)
        rule.onNodeWithText("No entries in this vault").assertExists()
        rule.onNodeWithTag(KASH_TAG).assertExists()
    }

    @Test
    fun `an empty vault under the weak-KDF banner shows the text without Kash`() =
        assertEmptyWithoutKash(emptyState().copy(weakKdf = org.onekash.kashpass.vault.header.KdfSettings.AesKdf(6_000UL)))

    @Test
    fun `an empty vault under the older-file banner shows the text without Kash`() =
        assertEmptyWithoutKash(emptyState().copy(olderThan = java.time.Instant.EPOCH))

    @Test
    fun `an empty vault under the bytes-after-the-end notice shows the text without Kash`() =
        assertEmptyWithoutKash(emptyState().copy(bytesAfterEnd = true))

    @Test
    fun `an empty vault under the read-only banner shows the text without Kash`() =
        assertEmptyWithoutKash(emptyState().copy(readOnly = ReadOnlyBanner(ReadOnlyReason.LAST_COPY, null)))

    @Test
    fun `the biometric offer is not a warning and leaves Kash above the empty vault`() {
        rule.setContent { KashPassTheme { showState(emptyState().copy(biometricOffer = true)) } }
        rule.onNodeWithText("No entries in this vault").assertExists()
        rule.onNodeWithTag(KASH_TAG).assertExists()
    }

    @Test
    fun `at twice the font size the empty vault shows its text`() {
        rule.setContent {
            val density = androidx.compose.ui.platform.LocalDensity.current
            androidx.compose.runtime.CompositionLocalProvider(
                androidx.compose.ui.platform.LocalDensity provides androidx.compose.ui.unit.Density(density.density, 2f),
            ) { KashPassTheme { showState(emptyState()) } }
        }
        rule.onNodeWithText("No entries in this vault").assertExists()
    }

    private fun assertEmptyWithoutKash(state: BrowseUiState) {
        rule.setContent { KashPassTheme { showState(state) } }
        rule.onNodeWithText("No entries in this vault").assertExists()
        rule.onNodeWithTag(KASH_TAG).assertDoesNotExist()
    }

    @androidx.compose.runtime.Composable
    private fun showState(state: BrowseUiState) =
        BrowseScreen(state, {}, {}, {}, {}, {}, { CopyOutcome.FAILED }, {}, onOpenSettings = {}, onSubmitSearch = {}, onSearchFocused = {})

    @Test
    fun `no matches has no Kash`() {
        show()
        search("zzz")
        rule.onNodeWithText("No matches for \"zzz\"").assertExists()
        rule.onNodeWithTag(KASH_TAG).assertDoesNotExist()
    }

    @Test
    fun `Kash sizes to the space left and is left out below 48 dp`() {
        assertEquals(120.dp, emptyVaultKashSize(heightLeft = 400.dp, width = 360.dp))
        assertEquals(84.dp, emptyVaultKashSize(heightLeft = 84.dp / KASH_ASPECT_RATIO, width = 360.dp))
        assertEquals(60.dp, emptyVaultKashSize(heightLeft = 400.dp, width = 60.dp))
        assertNull(emptyVaultKashSize(heightLeft = 40.dp, width = 360.dp))
        assertNull(emptyVaultKashSize(heightLeft = 400.dp, width = 40.dp))
    }

    private fun emptyState() = BrowseUiState(
        chips = listOf(Chip.All), selectedChip = Chip.All, query = "", searching = false, letterHeaders = false,
        groupInRows = true, rows = emptyList(), vaultEmpty = true, weakKdf = null, openEntry = null, revealed = emptySet(),
    )

    @Test
    fun `typing filters, no match says so, and clearing returns to the chip`() {
        show()
        search("a-1234")
        rule.onNodeWithText("Example Mail").assertExists()
        rule.onNodeWithText("Router").assertDoesNotExist()
        rule.onNodeWithContentDescription("Clear search").performClick()
        search("zzz")
        rule.onNodeWithText("No matches for \"zzz\"").assertExists()
        rule.onNodeWithContentDescription("Clear search").performClick()
        rule.onNodeWithText("Router").assertExists()
    }

    @Test
    fun `the sheet lists fields in order with protected values masked and no history`() {
        show()
        rule.onNodeWithText("Example Mail").performClick()
        val labels = listOf("User name", "Password", "URL", "Account ID", "otp", "Notes")
        val tops = labels.map { rule.onNodeWithText(it).fetchSemanticsNode().positionInRoot.y }
        assertEquals(tops.sorted(), tops)
        rule.onNodeWithText("https://mail.example.com").assertExists()
        rule.onNodeWithText("Recovery hint: ünïcödé").assertExists()
        rule.onNodeWithText("mail-pass").assertDoesNotExist()
        rule.onAllNodesWithText("••••••••").assertCountEquals(2)
        rule.onNodeWithText("Example Mail (old)").assertDoesNotExist()
        rule.onNodeWithText("alice-old").assertDoesNotExist()
    }

    @Test
    fun `screen readers hear Hidden for masked values and the entry title as a heading`() {
        show()
        rule.onNodeWithText("Example Mail").performClick()
        rule.onAllNodesWithContentDescription("Hidden").assertCountEquals(2)
        rule.onNode(hasText("Example Mail") and isHeading()).assertExists()
    }

    @Test
    fun `reveal shows the value and the button toggles back`() {
        show()
        rule.onNodeWithText("Example Mail").performClick()
        rule.onNodeWithContentDescription("Show Password").performClick()
        rule.onNodeWithText("mail-pass").assertExists()
        rule.onNodeWithContentDescription("Hide Password").performClick()
        rule.onNodeWithText("mail-pass").assertDoesNotExist()
        rule.onNodeWithContentDescription("Show Password").assertExists()
    }

    @Test
    fun `copy puts the value on the clipboard marked sensitive and the snackbar names only the field`() {
        show()
        rule.onNodeWithText("Example Mail").performClick()
        rule.onNodeWithContentDescription("Copy Password").performClick()
        rule.waitForIdle()
        assertEquals("mail-pass", clipboardManager.primaryClip?.getItemAt(0)?.text?.toString())
        assertTrue(clipboardManager.primaryClipDescription!!.extras!!.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE))
        rule.onNodeWithText("Password copied. Clears in 30 s.").assertExists()
        rule.onNodeWithText("mail-pass").assertDoesNotExist()
    }

    @Test
    fun `copying a custom field keeps its vault-defined name out of the clip label and stored state`() {
        show()
        rule.onNodeWithText("Example Mail").performClick()
        rule.onNodeWithContentDescription("Copy Account ID").performScrollTo().performClick()
        rule.waitForIdle()
        assertEquals("A-1234", clipboardManager.primaryClip?.getItemAt(0)?.text?.toString())
        assertFalse(clipboardManager.primaryClipDescription!!.label.contains("Account ID"))
        val stored = context.getSharedPreferences(ClipboardDeadlineStore.FILE, Context.MODE_PRIVATE).all
        assertFalse(stored.toString(), stored.values.any { it.toString().contains("Account ID") })
        rule.onNodeWithText("Account ID copied. Clears in 30 s.").assertExists()
    }

    @Test
    fun `a copy the system refuses says so instead of claiming it was copied`() {
        show(copy = { false })
        rule.onNodeWithText("Example Mail").performClick()
        rule.onNodeWithContentDescription("Copy Notes").performScrollTo().performClick()
        rule.onNodeWithText("Couldn't copy Notes.").assertExists()
        rule.onNodeWithText("Notes copied. Clears in 30 s.").assertDoesNotExist()
    }

    @Test
    fun `a vault with repeated entry and group ids lists every entry and opens the right one`() {
        show(TestVaults.repeatedIdsVault())
        rule.onNodeWithText("First").assertExists()
        rule.onNodeWithText("Second").performClick()
        rule.onNodeWithText("second-user").assertExists()
    }

    @Test
    fun `attachments are listed as not openable yet and cannot be opened`() {
        show()
        rule.onNodeWithText("Example Bank").performClick()
        rule.onNodeWithText("recovery-codes.txt").assertExists().assert(SemanticsMatcher.keyNotDefined(SemanticsActions.OnClick))
        rule.onNodeWithText("Can't be opened in KashPass").assertExists()
    }

    @Test
    fun `weak AES-KDF settings show the banner and Dismiss hides it`() {
        show(weak)
        rule.onNodeWithText("Weak security settings: AES-KDF with 6,000 iterations. KeePass 2 recommends at least 600,000. Change it in KeePass 2 under File, Database Settings, Security.").assertExists()
        rule.onNodeWithText("Dismiss").performClick()
        rule.onNodeWithText("Dismiss").assertDoesNotExist()
        assertEquals(1, opener.dismissed.size)
    }

    @Test
    fun `weak Argon2 settings use the iterations and MiB wording, and the gear opens Settings`() {
        val state = BrowseUiState(
            chips = listOf(Chip.All),
            selectedChip = Chip.All,
            query = "",
            searching = false,
            letterHeaders = false,
            groupInRows = true,
            rows = emptyList(),
            vaultEmpty = true,
            weakKdf = KdfSettings.Argon2(Argon2Variant.ARGON2ID, 1UL, 33_554_432UL, 2U, 19U),
            openEntry = null,
            revealed = emptySet(),
        )
        rule.setContent {
            KashPassTheme {
                BrowseScreen(state, {}, {}, {}, {}, {}, { CopyOutcome.FAILED }, {}, onOpenSettings = { locks++ }, onSubmitSearch = {}, onSearchFocused = {})
            }
        }
        rule.onNodeWithText(
            "Weak security settings: Argon2 with 1 iteration and 32 MiB. KeePass 2 recommends at least 2 iterations and 64 MiB. Change it in KeePass 2 under File, Database Settings, Security.",
        ).assertExists()
        rule.onNodeWithContentDescription("Lock").assertDoesNotExist()
        rule.onNodeWithContentDescription("Backups").assertDoesNotExist()
        rule.onNodeWithContentDescription("Settings").performClick()
        assertEquals(1, locks)
    }

    @Test
    fun `the Undo snackbar follows the pending count and Undo restores`() {
        val base = BrowseUiState(
            chips = listOf(Chip.All), selectedChip = Chip.All, query = "", searching = false, letterHeaders = false,
            groupInRows = true, rows = emptyList(), vaultEmpty = true, weakKdf = null, openEntry = null, revealed = emptySet(),
        )
        var state by mutableStateOf(base.copy(pendingDeletes = 1))
        var undos = 0
        rule.setContent {
            KashPassTheme {
                BrowseScreen(state, {}, {}, {}, {}, {}, { CopyOutcome.FAILED }, {}, onOpenSettings = {}, onSubmitSearch = {}, onSearchFocused = {}, onUndoDelete = { undos++ })
            }
        }
        rule.onNodeWithText("Moved to the recycle bin").assertExists()
        state = base.copy(pendingDeletes = 2)
        rule.waitForIdle()
        rule.onNodeWithText("2 moved to the recycle bin").assertExists()
        rule.onNodeWithText("Moved to the recycle bin").assertDoesNotExist()
        rule.onAllNodesWithText("Undo").assertCountEquals(1)
        rule.onNodeWithText("Undo").performClick()
        assertEquals(1, undos)
        state = base.copy(pendingDeletes = 1)
        rule.waitForIdle()
        rule.onNodeWithText("Moved to the recycle bin").assertExists()
        // The window ended or another save carried the deletes.
        state = base.copy(pendingDeletes = 0)
        rule.waitForIdle()
        rule.onNodeWithText("Moved to the recycle bin").assertDoesNotExist()
        rule.onNodeWithText("Undo").assertDoesNotExist()
    }

    @Test
    fun `an expired entry is struck through and says Expired, a later one doesn't`() {
        val now = java.time.Instant.parse("2026-10-21T12:00:00Z")
        val rows = listOf(
            org.onekash.kashpass.vault.index.EntryRow("1", "Old card", "bob", null, false, expiry = now.minusSeconds(60)),
            org.onekash.kashpass.vault.index.EntryRow("2", "New card", "amy", null, false, expiry = now.plusSeconds(86_400 * 30L)),
        )
        val state = BrowseUiState(
            chips = listOf(Chip.All), selectedChip = Chip.All, query = "", searching = false, letterHeaders = false,
            groupInRows = false, rows = rows, vaultEmpty = false, weakKdf = null, openEntry = null, revealed = emptySet(), now = now,
        )
        rule.setContent {
            KashPassTheme {
                BrowseScreen(state, {}, {}, {}, {}, {}, { CopyOutcome.FAILED }, {}, onOpenSettings = {}, onSubmitSearch = {}, onSearchFocused = {})
            }
        }
        rule.onNodeWithText("Expired · bob").assertExists()
        rule.onNodeWithText("amy").assertExists()
        rule.onNodeWithText("Expired · amy").assertDoesNotExist()
    }

    @Test
    fun `another message hides Undo while the deletes stay pending`() {
        val base = BrowseUiState(
            chips = listOf(Chip.All), selectedChip = Chip.All, query = "", searching = false, letterHeaders = false,
            groupInRows = true, rows = emptyList(), vaultEmpty = true, weakKdf = null, openEntry = null, revealed = emptySet(),
            pendingDeletes = 1,
        )
        val messages = kotlinx.coroutines.flow.MutableSharedFlow<org.onekash.kashpass.ui.format.UiMessage>(extraBufferCapacity = 1)
        rule.setContent {
            KashPassTheme {
                BrowseScreen(base, {}, {}, {}, {}, {}, { CopyOutcome.FAILED }, {}, onOpenSettings = {}, onSubmitSearch = {}, onSearchFocused = {}, messages = messages)
            }
        }
        rule.onNodeWithText("Undo").assertExists()
        messages.tryEmit(org.onekash.kashpass.ui.format.UiMessage("Saved"))
        rule.waitForIdle()
        rule.onNodeWithText("Saved").assertExists()
        rule.onNodeWithText("Undo").assertDoesNotExist()
    }

    private fun showMessages(): kotlinx.coroutines.flow.MutableSharedFlow<org.onekash.kashpass.ui.format.UiMessage> {
        val state = BrowseUiState(
            chips = listOf(Chip.All), selectedChip = Chip.All, query = "", searching = false, letterHeaders = false,
            groupInRows = true, rows = emptyList(), vaultEmpty = true, weakKdf = null, openEntry = null, revealed = emptySet(),
        )
        val messages = kotlinx.coroutines.flow.MutableSharedFlow<org.onekash.kashpass.ui.format.UiMessage>(extraBufferCapacity = 1)
        rule.setContent {
            KashPassTheme {
                BrowseScreen(state, {}, {}, {}, {}, {}, { CopyOutcome.FAILED }, {}, onOpenSettings = {}, onSubmitSearch = {}, onSearchFocused = {}, messages = messages)
            }
        }
        return messages
    }

    @Test
    fun `a message has Dismiss on the right and Dismiss hides it`() {
        val messages = showMessages()
        messages.tryEmit(org.onekash.kashpass.ui.format.UiMessage("Saved"))
        rule.waitForIdle()
        rule.onNodeWithText("Saved").assertExists()
        rule.onNodeWithText("Dismiss").performClick()
        rule.onNodeWithText("Saved").assertDoesNotExist()
    }

    @Test
    fun `a message closes after the short duration`() {
        val messages = showMessages()
        rule.mainClock.autoAdvance = false
        messages.tryEmit(org.onekash.kashpass.ui.format.UiMessage("Saved"))
        rule.mainClock.advanceTimeBy(1_000)
        rule.onNodeWithText("Saved").assertExists()
        rule.mainClock.advanceTimeBy(5_000)
        rule.onNodeWithText("Saved").assertDoesNotExist()
    }

    @Test
    fun `a message with its own action shows that action, not Dismiss`() {
        val messages = showMessages()
        var tries = 0
        messages.tryEmit(org.onekash.kashpass.ui.format.UiMessage("Timed out", "Try again") { tries++ })
        rule.waitForIdle()
        rule.onNodeWithText("Dismiss").assertDoesNotExist()
        rule.onNodeWithText("Try again").performClick()
        rule.waitForIdle()
        assertEquals(1, tries)
    }

    @Test
    fun `scrolling the list closes an open row`() {
        show()
        rule.onNodeWithText("Example Mail").performTouchInput { swipeLeft() }
        rule.waitForIdle()
        val closedLeft = rule.onNodeWithText("admin").getUnclippedBoundsInRoot().left
        assertTrue("the swipe opened the row", rule.onNodeWithText("Example Mail").getUnclippedBoundsInRoot().left < closedLeft)
        rule.onNodeWithTag(LIST_TAG).performTouchInput { swipeUp() }
        rule.waitForIdle()
        rule.onNodeWithText("Example Mail").assertLeftPositionInRootIsEqualTo(closedLeft)
    }

    @Test
    fun `settings KeePass 2 accepts show no banner`() {
        show()
        rule.onNodeWithText("Dismiss").assertDoesNotExist()
    }

    private companion object {
        val browser: ByteArray by lazy { TestVaults.browserVault() }
        val weak: ByteArray by lazy { TestVaults.browserVault(aesRounds = 6_000UL) }
        val empty: ByteArray by lazy { TestVaults.bytes(entries = emptyList()) }
    }

    @Test
    fun `the search field opts out of autofill`() {
        show()
        rule.onAllNodes(androidx.compose.ui.test.hasSetTextAction()).assertAll(androidx.compose.ui.test.SemanticsMatcher.expectValue(androidx.compose.ui.semantics.SemanticsProperties.ContentDataType, androidx.compose.ui.autofill.ContentDataType.None))
    }

    @Test
    fun `the fingerprint offer shows with Not now and Turn on, and the list stays usable`() {
        var turnOn = 0
        var notNow = 0
        var shown = 0
        val state = BrowseUiState(
            chips = listOf(Chip.All), selectedChip = Chip.All, query = "", searching = false, letterHeaders = false, groupInRows = true,
            rows = emptyList(), vaultEmpty = true, weakKdf = null, openEntry = null, revealed = emptySet(), biometricOffer = true,
        )
        rule.setContent {
            KashPassTheme {
                BrowseScreen(
                    state, {}, {}, {}, {}, {}, { CopyOutcome.FAILED }, {}, onOpenSettings = {}, onSubmitSearch = {}, onSearchFocused = {},
                    offerNoun = "fingerprint", onTurnOnBiometric = { turnOn++ }, onDismissOffer = { notNow++ }, onOfferShown = { shown++ },
                )
            }
        }
        rule.onNodeWithText("Unlock with your fingerprint next time?").assertExists()
        rule.onNodeWithText("Skip typing the vault password on this device. Turn it off in Settings.").assertExists()
        rule.onNodeWithText("Turn on").performClick()
        rule.onNodeWithText("Not now").performClick()
        assertEquals(1, turnOn)
        assertEquals(1, notNow)
        assertEquals(1, shown)
    }

    private fun showWorking(working: Boolean, enabling: Boolean = false) {
        val state = BrowseUiState(
            chips = listOf(Chip.All), selectedChip = Chip.All, query = "", searching = false, letterHeaders = false, groupInRows = true,
            rows = emptyList(), vaultEmpty = true, weakKdf = null, openEntry = null, revealed = emptySet(),
            biometricOffer = enabling, working = working, enabling = enabling,
        )
        rule.setContent {
            KashPassTheme {
                BrowseScreen(state, {}, {}, {}, {}, {}, { CopyOutcome.FAILED }, {}, onOpenSettings = {}, onSubmitSearch = {}, onSearchFocused = {}, offerNoun = "fingerprint")
            }
        }
    }

    @Test
    fun `a bar under the search bar shows while the app works on the file`() {
        showWorking(working = true)
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
    }

    @Test
    fun `no bar shows while the app is idle`() {
        showWorking(working = false)
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertDoesNotExist()
    }

    @Test
    fun `while fingerprint unlock turns on, the card shows a spinner and its buttons are disabled`() {
        showWorking(working = false, enabling = true)
        rule.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
        rule.onNodeWithText("Turn on").assertIsNotEnabled()
        rule.onNodeWithText("Not now").assertIsNotEnabled()
    }
}
