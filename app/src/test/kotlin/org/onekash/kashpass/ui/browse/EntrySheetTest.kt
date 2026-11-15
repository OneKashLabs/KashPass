package org.onekash.kashpass.ui.browse

import androidx.compose.material3.SnackbarHostState
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import java.time.Instant
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.ui.format.EntryTimes
import org.onekash.kashpass.ui.theme.KashPassTheme
import org.onekash.kashpass.vault.index.EntryDetails
import org.onekash.kashpass.vault.index.EntryField
import org.onekash.kashpass.vault.index.FieldKind
import org.onekash.kashpass.vault.index.FieldValue
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@Config(qualifiers = "w411dp-h891dp")
@RunWith(RobolectricTestRunner::class)
class EntrySheetTest {

    @get:Rule
    val rule = createComposeRule()

    private val zone = ZoneOffset.UTC
    private val now = Instant.parse("2026-10-21T12:00:00Z")
    private val opened = mutableListOf<String>()
    private val tags = mutableListOf<String>()

    private fun details(url: FieldValue = FieldValue.Plain("https://bank.example/login"), expiry: Instant? = null) = EntryDetails(
        id = "1",
        title = "Bank",
        groupName = "Banking",
        fields = listOf(EntryField("URL", FieldKind.URL, url)),
        attachmentNames = emptyList(),
        created = Instant.parse("2024-03-12T09:30:00Z"),
        modified = Instant.parse("2026-10-18T12:00:00Z"),
        expiry = expiry,
        tags = listOf("work", "money"),
    )

    private val copied = mutableListOf<String>()
    private val confirmed = mutableListOf<String>()
    private var cancels = 0

    // Each field shown as stored, as when it holds no reference.
    private fun asStored(details: EntryDetails) = details.fields.associate { it.name to ShownField(it.value, false, false) }

    private fun show(
        details: EntryDetails,
        shown: Map<String, ShownField>? = asStored(details),
        confirming: String? = null,
        revealed: Set<String> = emptySet(),
    ) = rule.setContent {
        KashPassTheme {
            EntrySheet(
                details = details,
                revealed = revealed,
                snackbar = SnackbarHostState(),
                onDismiss = {},
                onToggleReveal = {},
                onCopy = { field, _, _ -> copied += field.name },
                shown = shown,
                confirming = confirming,
                onConfirmCopy = { field, _, _ -> confirmed += field.name },
                onCancelCopy = { cancels++ },
                now = now,
                zone = zone,
                onOpenUrl = { opened += it; true },
                onTag = { tags += it },
            )
        }
    }

    @Test
    fun `the footer says when it was created and edited`() {
        show(details())
        val created = EntryTimes.date(Instant.parse("2024-03-12T09:30:00Z"), zone)
        rule.onNodeWithText("Created $created · Edited 3 days ago").performScrollTo().assertExists()
    }

    @Test
    fun `an expired entry says so under the title`() {
        show(details(expiry = Instant.parse("2026-10-01T00:00:00Z")))
        rule.onNodeWithText("Expired 2 weeks ago · ${EntryTimes.date(Instant.parse("2026-10-01T00:00:00Z"), zone)}").assertExists()
    }

    @Test
    fun `an expiry within the week counts the days`() {
        val soon = Instant.parse("2026-10-24T12:00:00Z")
        show(details(expiry = soon))
        rule.onNodeWithText("Expires in 3 days · ${EntryTimes.date(soon, zone)}").assertExists()
    }

    @Test
    fun `a later expiry joins the footer`() {
        val later = Instant.parse("2027-12-01T00:00:00Z")
        show(details(expiry = later))
        rule.onNodeWithText("Expires ${EntryTimes.date(later, zone)}", substring = true).performScrollTo().assertExists()
    }

    @Test
    fun `tapping a tag chip searches for that tag`() {
        show(details())
        rule.onNodeWithText("money").performClick()
        assertEquals(listOf("money"), tags)
    }

    @Test
    fun `a web URL opens in the browser`() {
        show(details())
        rule.onNodeWithContentDescription("Open URL").performClick()
        assertEquals(listOf("https://bank.example/login"), opened)
    }

    @Test
    fun `a command URL has no open button`() {
        show(details(url = FieldValue.Plain("cmd://calc.exe")))
        rule.onNodeWithContentDescription("Open URL").assertDoesNotExist()
    }

    @Test
    fun `an unresolved field reference has no open button`() {
        show(details(url = FieldValue.Plain("{REF:U@I:1234}")))
        rule.onNodeWithContentDescription("Open URL").assertDoesNotExist()
    }

    private fun holder() = EntryDetails(
        id = "14",
        title = "Reference Holder",
        groupName = null,
        fields = listOf(
            EntryField("UserName", FieldKind.USER_NAME, FieldValue.Plain("{REF:U@T:Example Bank}")),
            EntryField("URL", FieldKind.URL, FieldValue.Plain("https://{REF:U@T:Example Bank}.example")),
            EntryField("Notes", FieldKind.NOTES, FieldValue.Plain("pw {REF:P@T:Example Bank} and {S:Account}")),
        ),
        attachmentNames = emptyList(),
    )

    private fun resolved(notes: String = "pw bank-pass and {S:Account}") = mapOf(
        "UserName" to ShownField(FieldValue.Plain("bob"), insertsPassword = false, keepsPlaceholders = false),
        "URL" to ShownField(FieldValue.Plain("https://bob.example"), insertsPassword = false, keepsPlaceholders = false),
        "Notes" to ShownField(protectedValue(notes), insertsPassword = true, keepsPlaceholders = true),
    )

    private fun protectedValue(text: String): FieldValue = FieldValue.Protected(org.onekash.kashpass.vault.doc.ProtectedText.of(text))

    @Test
    fun `fields show their resolved values, a value inserting a password masked until revealed`() {
        show(holder(), shown = resolved())
        rule.onNodeWithText("bob").assertExists()
        rule.onNodeWithText("{REF:U@T:Example Bank}").assertDoesNotExist()
        rule.onNodeWithText("pw bank-pass and {S:Account}").assertDoesNotExist()
        rule.onNodeWithContentDescription("Show Notes").assertExists()
    }

    @Test
    fun `a revealed field inserting a password shows the resolved text`() {
        show(holder(), shown = resolved(), revealed = setOf("Notes"))
        rule.onNodeWithText("pw bank-pass and {S:Account}").performScrollTo().assertExists()
    }

    @Test
    fun `a field keeping another placeholder says KeePass 2 fills it in`() {
        show(holder(), shown = resolved())
        rule.onNodeWithText("Filled in by KeePass 2 when used. KashPass shows it as stored.").performScrollTo().assertExists()
    }

    @Test
    fun `the open button uses the resolved URL`() {
        show(holder(), shown = resolved())
        rule.onNodeWithContentDescription("Open URL").performClick()
        assertEquals(listOf("https://bob.example"), opened)
    }

    @Test
    fun `a URL inserting a password has no open button`() {
        val shown = resolved() + ("URL" to ShownField(protectedValue("https://bank-pass.example"), insertsPassword = true, keepsPlaceholders = false))
        show(holder(), shown = shown)
        rule.onNodeWithContentDescription("Open URL").assertDoesNotExist()
    }

    @Test
    fun `the inline confirm names the field and copies or cancels`() {
        show(holder(), shown = resolved(), confirming = "Notes")
        rule.onNodeWithText("Notes inserts another entry's password. Copy it?").performScrollTo().assertExists()
        rule.onNodeWithText("Copy").performScrollTo().performClick()
        assertEquals(listOf("Notes"), confirmed)
        rule.onNodeWithText("Cancel").performScrollTo().performClick()
        assertEquals(1, cancels)
    }

    @Test
    fun `before resolution no value shows and copy and reveal are off`() {
        show(holder(), shown = null)
        rule.onNodeWithText("{REF:U@T:Example Bank}").assertDoesNotExist()
        rule.onNodeWithText("bob").assertDoesNotExist()
        rule.onNodeWithContentDescription("Copy User name").assertIsNotEnabled()
        rule.onNodeWithContentDescription("Copy User name").performClick()
        assertEquals(emptyList<String>(), copied)
        rule.onNodeWithContentDescription("Open URL").assertDoesNotExist()
    }
}
