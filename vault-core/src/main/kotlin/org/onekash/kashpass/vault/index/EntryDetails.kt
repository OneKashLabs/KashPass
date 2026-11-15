package org.onekash.kashpass.vault.index

import java.time.Instant
import org.onekash.kashpass.vault.doc.ProtectedText

/** Everything the details sheet shows for one entry, in display order. */
data class EntryDetails(
    val id: String,
    val title: String?,
    val groupName: String?,
    val fields: List<EntryField>,
    val attachmentNames: List<String>,
    /** Times/CreationTime; null when missing or unreadable. */
    val created: Instant? = null,
    /** Times/LastModificationTime; null when missing or unreadable. */
    val modified: Instant? = null,
    /** Times/ExpiryTime when Times/Expires is True, else null: the time does not apply then. */
    val expiry: Instant? = null,
    /** Tags, split on ',' and ';', trimmed, with no empty tags. */
    val tags: List<String> = emptyList(),
)

/** Which field a row is; standard kinds get localized labels in the app. */
enum class FieldKind { USER_NAME, PASSWORD, URL, CUSTOM, NOTES }

/** One field of an entry. [name] is the field's key, shown as the label for custom fields. */
data class EntryField(val name: String, val kind: FieldKind, val value: FieldValue) {
    /**
     * True when the field is masked as stored: the password, or a protected custom field
     * ([VaultIndex]). The entry sheet also masks a value that inserts a password.
     */
    val isProtected: Boolean get() = value is FieldValue.Protected
}

/** A field value; protected values stay masked in memory and out of every `toString`. */
sealed interface FieldValue {

    /** Returns the text to display or copy. */
    fun reveal(): String

    /** A value shown in clear. */
    data class Plain(val text: String) : FieldValue {
        override fun reveal() = text
    }

    /** A value shown masked; it stays masked in memory until [reveal]. */
    class Protected(private val value: ProtectedText) : FieldValue {
        override fun reveal(): String = value.reveal()
        override fun toString() = "Protected(****)"
        override fun equals(other: Any?) = other is Protected && other.reveal() == reveal()
        override fun hashCode() = 0
    }
}
