package org.onekash.kashpass.vault.property

import io.kotest.property.Arb
import io.kotest.property.arbitrary.element
import io.kotest.property.checkAll
import java.time.Instant
import kotlin.test.assertEquals
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.EntryView
import org.onekash.kashpass.vault.doc.FieldText
import org.onekash.kashpass.vault.doc.ProtectedText
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.doc.VaultXmlCodec
import org.onekash.kashpass.vault.doc.encodeBytes
import org.onekash.kashpass.vault.edit.EditResult
import org.onekash.kashpass.vault.edit.EntryDraft
import org.onekash.kashpass.vault.edit.EntryEdits
import org.onekash.kashpass.vault.index.documentOf
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.VaultModel
import org.onekash.kashpass.vault.testing.VaultModel.Value
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * Any text set in a field and saved reads back from the save as [KeePassText] gives it: a field
 * written in clear as [KeePassText.clear], a field written protected as [KeePassText.protected].
 */
class TextProperties {

    @Test
    fun `any text set in a field reads back as KeePass 2 reads the save`() = runBlocking<Unit> {
        checkAll(PropertyRuns.config(400), Generators.anyText, Arb.element(FIELDS)) { text, field ->
            val back = setAndReadBack(field, text)
            val expected = if (field in PROTECTED) KeePassText.protected(text) else KeePassText.clear(text)
            assertEquals(expected.escaped(), back.escaped(), "$field set to ${text.escaped()}")
        }
    }

    @Test
    fun `a lone surrogate in a protected Title reads back as KeePass 2 writes it`() {
        assertEquals(KeePassText.protected("\uDC00").escaped(), setAndReadBack("Title", "\uDC00").escaped())
    }

    @Test
    fun `a clear value of whitespace alone reads back as KeePass 2 reads it`() {
        assertEquals("", setAndReadBack("UserName", "   ").escaped())
        // The property's shrunk case.
        assertEquals("", setAndReadBack("Notes", "\t\r").escaped())
    }

    internal companion object {

        /** The fields the property sets; the entry stores Title protected, Password always is. */
        val FIELDS = listOf("Title", "UserName", "Password", "URL", "Notes")
        val PROTECTED = setOf("Title", "Password")

        // One entry whose Title is stored protected, so the edit keeps it protected (EntryEdits
        // protectedKeys); Meta protects only the password, the default.
        private val VAULT: ByteArray = VaultModel.write(
            VaultModel.Doc(VaultModel.Group("Root", entries = listOf(VaultModel.Entry(listOf(
                "Title" to Value.Protected("t"), "UserName" to Value.Plain("u"), "Password" to Value.Protected("p"),
                "URL" to Value.Plain("w"), "Notes" to Value.Plain("n"),
            ))))),
            aesRounds = 1UL,
        )

        /**
         * Sets [field] of the vault's entry to [text] through the editor's path (the password from
         * the typed characters, ProtectedText.of(CharArray)), saves, reopens with KashPass and
         * returns the field as read.
         */
        fun setAndReadBack(field: String, text: String): String {
            val document = documentOf(VAULT)
            val id = DocumentIds.entries(document).keys.single()
            val d = EntryEdits.draftOf(document, id)!!
            val draft = when (field) {
                "Title" -> EntryDraft(text, d.userName, d.password, d.url, d.notes)
                "UserName" -> EntryDraft(d.title, text, d.password, d.url, d.notes)
                "Password" -> EntryDraft(d.title, d.userName, ProtectedText.of(text.toCharArray()), d.url, d.notes)
                "URL" -> EntryDraft(d.title, d.userName, d.password, text, d.notes)
                else -> EntryDraft(d.title, d.userName, d.password, d.url, text)
            }
            val edited = when (val r = EntryEdits.edit(document, id, draft, Instant.parse("2030-01-01T00:00:00Z"))) {
                is EditResult.Changed -> r.document
                else -> document
            }
            return read(documentOf(VaultXmlCodec.encodeBytes(edited)), field)
        }

        private fun read(document: VaultDocument, field: String): String = fieldText(document, DocumentIds.entries(document).values.single(), field)

        /** Returns [entry]'s [field] as KashPass reads it: the key's last String, or "". */
        fun fieldText(document: VaultDocument, entry: XmlElement, field: String): String =
            when (val v = EntryView(entry, document).fields().lastOrNull { it.key == field }?.value) {
                null -> ""
                is FieldText.Plain -> v.text
                is FieldText.Protected -> v.value.reveal()
            }
    }
}

/** Returns how a saved field value reads back, for the text properties. */
internal object KeePassText {

    /** True when [text] holds a surrogate code unit that is not part of a valid pair. */
    fun hasLoneSurrogate(text: String): Boolean = text.indices.any { i ->
        val c = text[i]
        c.isSurrogate() && !(c.isHighSurrogate() && i + 1 < text.length && text[i + 1].isLowSurrogate()) &&
            !(c.isLowSurrogate() && i > 0 && text[i - 1].isHighSurrogate())
    }

    /**
     * A value written in clear keeps tab, LF, CR, U+0020-U+D7FF, U+E000-U+FFFD and valid
     * surrogate pairs and drops every other code unit; a value left with XML whitespace alone
     * (space, tab, CR, LF) reads as empty, since the reader ignores whitespace-only text.
     */
    fun clear(text: String): String = if (isWhitespaceOnly(text)) "" else safeXml(text)

    /** True when [text], cleaned as [clear] cleans it, is XML whitespace alone. */
    fun isWhitespaceOnly(text: String): Boolean = safeXml(text).let { s -> s.isNotEmpty() && s.all { it == ' ' || it == '\t' || it == '\r' || it == '\n' } }

    /**
     * A value written protected: its UTF-8 bytes, with each lone surrogate turned into U+FFFD.
     */
    fun protected(text: String): String {
        val out = StringBuilder(text.length)
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                c.isHighSurrogate() && i + 1 < text.length && text[i + 1].isLowSurrogate() -> { out.append(c).append(text[i + 1]); i++ }
                c.isSurrogate() -> out.append('\uFFFD')
                else -> out.append(c)
            }
            i++
        }
        return out.toString()
    }

    private fun safeXml(text: String): String {
        val out = StringBuilder(text.length)
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                c in ' '..'\uD7FF' || c == '\t' || c == '\n' || c == '\r' || c in '\uE000'..'\uFFFD' -> out.append(c)
                c.isHighSurrogate() && i + 1 < text.length && text[i + 1].isLowSurrogate() -> { out.append(c).append(text[i + 1]); i++ }
            }
            i++
        }
        return out.toString()
    }
}

/** [this] with every code unit outside printable ASCII written as \uXXXX, for readable failures. */
internal fun String.escaped(): String = buildString { for (c in this@escaped) if (c in ' '..'~') append(c) else append("\\u%04X".format(c.code)) }
