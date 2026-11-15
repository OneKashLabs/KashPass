package org.onekash.kashpass.vault.doc

/**
 * The context machine of the KDBX 4 XML reader: for an element named `name` met in [Context]
 * `ctx`, [action] says whether the reader switches context, reads the element as a value (and
 * how), or skips it as unknown. Names are compared as written, prefix included.
 * [ContainerDecode] walks the tree with it; [KdbxXmlContextTest] pins every transition.
 */
internal object KdbxXmlContext {

    /** The element the reader is inside. */
    enum class Context {
        NULL, KEEPASS_FILE, META, MEMORY_PROTECTION, CUSTOM_ICONS, CUSTOM_ICON, BINARIES, CUSTOM_DATA, CUSTOM_DATA_ITEM,
        ROOT, GROUP, GROUP_TIMES, GROUP_CUSTOM_DATA, GROUP_CUSTOM_DATA_ITEM,
        ENTRY, ENTRY_TIMES, ENTRY_STRING, ENTRY_BINARY, ENTRY_AUTO_TYPE, ENTRY_AUTO_TYPE_ITEM, ENTRY_CUSTOM_DATA,
        ENTRY_CUSTOM_DATA_ITEM, ENTRY_HISTORY, ROOT_DELETED_OBJECTS, DELETED_OBJECT,
    }

    /** How the reader reads a value element; every one is read from the element's text. */
    enum class Value {
        /** A string, bool or number; a value that does not parse falls back to a default. */
        TEXT,

        /** Empty, or Base64 of 16 bytes. */
        UUID,

        /** A time. */
        TIME,

        /** A colour in HTML notation, when not empty. */
        COLOR,

        /** A custom icon's Data: Base64 ([ConvertBase64]) when not empty. */
        ICON_DATA,

        /** Meta/HeaderHash, checked against the header's SHA-256 when not empty. */
        HEADER_HASH,

        /** An entry String's Key. */
        STRING_KEY,

        /** An entry String's Value, protected or plain. */
        STRING_VALUE,

        /** An entry Binary's Key. */
        BINARY_KEY,

        /** An entry Binary's Value: a Ref to a pool item, or inline data, protected or plain. */
        BINARY_VALUE,

        /** A Meta/Binaries item with an ID attribute, protected or plain. */
        META_BINARY,

        /** An auto-type Association's Window. */
        WINDOW,

        /** An auto-type Association's KeystrokeSequence. */
        KEYSTROKES,
    }

    /** What the reader does with an element. */
    sealed interface Action {
        /**
         * Switches to [to], unless the element is self-closing, in which case the context stays
         * and no end runs. The side effects before the switch run either way.
         */
        data class Switch(val to: Context) : Action

        data class Read(val value: Value) : Action

        /** Skipped, with every non-empty protected element in it read as protected. */
        data object Unknown : Action
    }

    private fun switch(to: Context) = Action.Switch(to)
    private fun read(value: Value) = Action.Read(value)
    private val TEXT = read(Value.TEXT)
    private val UUID = read(Value.UUID)
    private val TIME = read(Value.TIME)

    /**
     * Returns the reader's action for an element named [name] in [ctx]. [inHistory] is whether
     * the element is inside an entry's History; [hasId] is whether it has an `ID` attribute.
     */
    fun action(ctx: Context, name: String, inHistory: Boolean, hasId: Boolean): Action = when (ctx) {
        Context.NULL -> if (name == "KeePassFile") switch(Context.KEEPASS_FILE) else Action.Unknown
        Context.KEEPASS_FILE -> when (name) {
            "Meta" -> switch(Context.META)
            "Root" -> switch(Context.ROOT)
            else -> Action.Unknown
        }
        Context.META -> when (name) {
            "Generator", "DatabaseName", "DatabaseDescription", "DefaultUserName", "MaintenanceHistoryDays", "MasterKeyChangeRec",
            "MasterKeyChangeForce", "MasterKeyChangeForceOnce", "RecycleBinEnabled", "HistoryMaxItems", "HistoryMaxSize",
            -> TEXT
            "HeaderHash" -> read(Value.HEADER_HASH)
            "SettingsChanged", "DatabaseNameChanged", "DatabaseDescriptionChanged", "DefaultUserNameChanged", "MasterKeyChanged",
            "RecycleBinChanged", "EntryTemplatesGroupChanged",
            -> TIME
            "Color" -> read(Value.COLOR)
            "RecycleBinUUID", "EntryTemplatesGroup", "LastSelectedGroup", "LastTopVisibleGroup" -> UUID
            "MemoryProtection" -> switch(Context.MEMORY_PROTECTION)
            "CustomIcons" -> switch(Context.CUSTOM_ICONS)
            "Binaries" -> switch(Context.BINARIES)
            "CustomData" -> switch(Context.CUSTOM_DATA)
            else -> Action.Unknown
        }
        Context.MEMORY_PROTECTION -> when (name) {
            "ProtectTitle", "ProtectUserName", "ProtectPassword", "ProtectURL", "ProtectNotes" -> TEXT
            else -> Action.Unknown
        }
        Context.CUSTOM_ICONS -> if (name == "Icon") switch(Context.CUSTOM_ICON) else Action.Unknown
        Context.CUSTOM_ICON -> when (name) {
            "UUID" -> UUID
            "Data" -> read(Value.ICON_DATA)
            "Name" -> TEXT
            "LastModificationTime" -> TIME
            else -> Action.Unknown
        }
        Context.BINARIES -> if (name == "Binary" && hasId) read(Value.META_BINARY) else Action.Unknown
        Context.CUSTOM_DATA -> if (name == "Item") switch(Context.CUSTOM_DATA_ITEM) else Action.Unknown
        Context.CUSTOM_DATA_ITEM -> when (name) {
            "Key", "Value" -> TEXT
            "LastModificationTime" -> TIME
            else -> Action.Unknown
        }
        Context.ROOT -> when (name) {
            "Group" -> switch(Context.GROUP)
            "DeletedObjects" -> switch(Context.ROOT_DELETED_OBJECTS)
            else -> Action.Unknown
        }
        Context.GROUP -> when (name) {
            "UUID", "CustomIconUUID", "LastTopVisibleEntry", "PreviousParentGroup" -> UUID
            "Name", "Notes", "IconID", "IsExpanded", "DefaultAutoTypeSequence", "EnableAutoType", "EnableSearching", "Tags" -> TEXT
            "Times" -> switch(Context.GROUP_TIMES)
            "CustomData" -> switch(Context.GROUP_CUSTOM_DATA)
            "Group" -> switch(Context.GROUP)
            "Entry" -> switch(Context.ENTRY)
            else -> Action.Unknown
        }
        Context.GROUP_CUSTOM_DATA, Context.ENTRY_CUSTOM_DATA ->
            if (name == "Item") switch(if (ctx == Context.GROUP_CUSTOM_DATA) Context.GROUP_CUSTOM_DATA_ITEM else Context.ENTRY_CUSTOM_DATA_ITEM) else Action.Unknown
        Context.GROUP_CUSTOM_DATA_ITEM, Context.ENTRY_CUSTOM_DATA_ITEM -> if (name == "Key" || name == "Value") TEXT else Action.Unknown
        Context.ENTRY -> when (name) {
            "UUID", "CustomIconUUID", "PreviousParentGroup" -> UUID
            "IconID", "OverrideURL", "QualityCheck", "Tags" -> TEXT
            "ForegroundColor", "BackgroundColor" -> read(Value.COLOR)
            "Times" -> switch(Context.ENTRY_TIMES)
            "String" -> switch(Context.ENTRY_STRING)
            "Binary" -> switch(Context.ENTRY_BINARY)
            "AutoType" -> switch(Context.ENTRY_AUTO_TYPE)
            "CustomData" -> switch(Context.ENTRY_CUSTOM_DATA)
            "History" -> if (inHistory) Action.Unknown else switch(Context.ENTRY_HISTORY)
            else -> Action.Unknown
        }
        Context.GROUP_TIMES, Context.ENTRY_TIMES -> when (name) {
            "CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime", "LocationChanged" -> TIME
            "Expires", "UsageCount" -> TEXT
            else -> Action.Unknown
        }
        Context.ENTRY_STRING -> when (name) {
            "Key" -> read(Value.STRING_KEY)
            "Value" -> read(Value.STRING_VALUE)
            else -> Action.Unknown
        }
        Context.ENTRY_BINARY -> when (name) {
            "Key" -> read(Value.BINARY_KEY)
            "Value" -> read(Value.BINARY_VALUE)
            else -> Action.Unknown
        }
        Context.ENTRY_AUTO_TYPE -> when (name) {
            "Enabled", "DataTransferObfuscation", "DefaultSequence" -> TEXT
            "Association" -> switch(Context.ENTRY_AUTO_TYPE_ITEM)
            else -> Action.Unknown
        }
        Context.ENTRY_AUTO_TYPE_ITEM -> when (name) {
            "Window" -> read(Value.WINDOW)
            "KeystrokeSequence" -> read(Value.KEYSTROKES)
            else -> Action.Unknown
        }
        Context.ENTRY_HISTORY -> if (name == "Entry") switch(Context.ENTRY) else Action.Unknown
        Context.ROOT_DELETED_OBJECTS -> if (name == "DeletedObject") switch(Context.DELETED_OBJECT) else Action.Unknown
        Context.DELETED_OBJECT -> when (name) {
            "UUID" -> UUID
            "DeletionTime" -> TIME
            else -> Action.Unknown
        }
    }
}
