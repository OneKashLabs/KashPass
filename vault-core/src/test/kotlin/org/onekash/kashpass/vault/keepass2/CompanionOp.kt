package org.onekash.kashpass.vault.keepass2

/**
 * One user action the parity tests run on both sides: KashPass through [CompanionRig], KeePass 2
 * through the replay tool that reads [line]. Entries and groups are named by the Base64 UUID the
 * KDBX XML holds.
 */
internal sealed interface CompanionOp {

    /**
     * The tab-separated action line the KeePass 2 replay tool reads; text is percent-encoded
     * ([KeePass2Report.escape]).
     */
    val line: String

    /** Saves without an edit. */
    data object NoEdit : CompanionOp {
        override val line = "none"
    }

    /** Sets one of the five standard fields of [entry] in the entry editor and saves. */
    data class Edit(val entry: String, val field: String, val value: String) : CompanionOp {
        init {
            require(field in STANDARD) { field }
        }

        override val line get() = listOf("edit", entry, field, KeePass2Report.escape(value)).joinToString("\t")
    }

    /**
     * Adds an entry with [uuid] to [group] (the top level when null) with these fields and an empty
     * user name, so each side fills the vault's default user name by its own rule.
     */
    data class Add(val group: String?, val uuid: String, val title: String, val password: String, val url: String, val notes: String) : CompanionOp {
        override val line get() = listOf("add", group ?: "-", uuid, KeePass2Report.escape(title), KeePass2Report.escape(password), KeePass2Report.escape(url), KeePass2Report.escape(notes)).joinToString("\t")
    }

    /**
     * Deletes [entry]: to the recycle bin when it is on and the entry is outside it, permanently
     * otherwise.
     */
    data class Delete(val entry: String) : CompanionOp {
        override val line get() = listOf("delete", entry).joinToString("\t")
    }

    /**
     * Deletes the custom data item [key] of [entry] in KeePass 2's entry dialog and clicks OK. Only
     * the desktop side runs it: KeePass 2's UI deletes plugin data items but never sets them, and
     * KashPass offers no custom data editing.
     */
    data class DeleteCustomData(val entry: String, val key: String) : CompanionOp {
        override val line get() = listOf("delete-custom-data", entry, KeePass2Report.escape(key)).joinToString("\t")
    }

    companion object {
        val STANDARD = listOf("Title", "UserName", "Password", "URL", "Notes")

        /** The UUID of every entry the parity tests add: the 16 bytes "COMPANION-ADD-01". */
        const val ADDED = "Q09NUEFOSU9OLUFERC0wMQ=="
    }
}
