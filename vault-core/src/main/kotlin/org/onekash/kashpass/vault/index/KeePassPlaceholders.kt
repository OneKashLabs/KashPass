package org.onekash.kashpass.vault.index

import java.util.Locale

/**
 * Lists the KeePass placeholders that the desktop fills in when it uses a field (copy, open URL),
 * other than `{REF:}`, which [FieldRefs] resolves. KashPass shows them as stored. Names are
 * compared ignoring case. Auto-type keys such as `{TAB}` and `%VARIABLE%` forms are not listed:
 * keys are sent only in auto-type, and an environment variable depends on the desktop.
 * [KeePassPlaceholdersTest] pins the list.
 */
internal object KeePassPlaceholders {

    /** Whole placeholders, by kind. */
    private val EXACT: Set<String> = buildSet {
        // Standard entry fields and {UUID}.
        addAll(listOf("{TITLE}", "{USERNAME}", "{PASSWORD}", "{URL}", "{NOTES}", "{UUID}"))
        // URL parts, also for {BASE}.
        for (base in listOf("URL", "BASE")) {
            for (part in listOf("RMVSCM", "SCM", "HOST", "PORT", "PATH", "QUERY", "USERINFO", "USERNAME", "PASSWORD")) add("{$base:$part}")
        }
        add("{BASE}")
        // Groups.
        for (group in listOf("GROUP", "GROUP_SEL")) addAll(listOf("{$group}", "{${group}_PATH}", "{${group}_NOTES}"))
        // Paths and environment.
        addAll(listOf("{APPDIR}", "{DOCDIR}", "{DB_PATH}", "{DB_DIR}", "{DB_NAME}", "{DB_BASENAME}", "{DB_EXT}", "{ENV_DIRSEP}", "{ENV_PROGRAMFILES_X86}"))
        // Date and time.
        for (prefix in listOf("DT_", "DT_UTC_")) {
            for (part in listOf("YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND", "SIMPLE")) add("{$prefix$part}")
        }
        // Browsers.
        addAll(listOf("{INTERNETEXPLORER}", "{FIREFOX}", "{OPERA}", "{GOOGLECHROME}", "{SAFARI}", "{EDGE}"))
        // Interactive and stateful ones.
        addAll(listOf("{PICKCHARS}", "{PICKPASSWORDCHARS}", "{PICKFIELD}", "{NEWPASSWORD}", "{PASSWORD_ENC}", "{HMACOTP}", "{TIMEOTP}", "{CLIPBOARD}"))
    }

    /**
     * Placeholders that take a parameter after the prefix, up to the closing brace; `{S:` is
     * checked separately ([containsOther]).
     */
    private val PREFIXES = listOf(
        "{C:", "{CMD:", "{CLIPBOARD-SET:", "{T-REPLACE-RX:", "{T-CONV:",
        "{PICKCHARS:", "{NEWPASSWORD:",
    )

    /**
     * True when [text] holds one of the placeholders listed here, or `{S:name}` for a name in
     * [customNames] (ignoring case): `{S:}` is filled only for a custom field the entry has, and a
     * standard field only by its own name, so other `{S:}` text stays as written on the desktop
     * too.
     */
    fun containsOther(text: String, customNames: Collection<String>): Boolean {
        var at = text.indexOf('{')
        while (at >= 0) {
            val close = text.indexOf('}', at + 1)
            if (close < 0) return false
            val token = text.substring(at, close + 1).uppercase(Locale.ROOT)
            if (token in EXACT || PREFIXES.any { token.startsWith(it) }) return true
            if (token.startsWith("{S:")) {
                val name = text.substring(at + 3, close)
                if (customNames.any { it.equals(name, ignoreCase = true) }) return true
            }
            at = text.indexOf('{', at + 1)
        }
        return false
    }
}
