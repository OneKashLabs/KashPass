package org.onekash.kashpass.vault.index

import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/**
 * The KeePass placeholders filled in outside auto-type.
 */
class KeePassPlaceholdersTest {

    @ParameterizedTest
    @ValueSource(
        strings = [
            "{TITLE}", "{UserName}", "{password}", "{URL}", "{NOTES}", "{UUID}", "{S:Account}", "{s:pin}",
            "{URL:RMVSCM}", "{URL:HOST}", "{url:userinfo}", "{BASE}", "{BASE:PATH}",
            "{GROUP}", "{GROUP_PATH}", "{GROUP_NOTES}", "{GROUP_SEL}", "{GROUP_SEL_PATH}", "{GROUP_SEL_NOTES}",
            "{APPDIR}", "{DOCDIR}", "{DB_PATH}", "{DB_DIR}", "{DB_NAME}", "{DB_BASENAME}", "{DB_EXT}", "{ENV_DIRSEP}", "{ENV_PROGRAMFILES_X86}",
            "{DT_YEAR}", "{DT_SIMPLE}", "{DT_UTC_SECOND}", "{INTERNETEXPLORER}", "{FIREFOX}", "{OPERA}", "{GOOGLECHROME}", "{SAFARI}", "{EDGE}",
            "{PICKCHARS}", "{PICKCHARS:Password:C=3}", "{PICKPASSWORDCHARS}", "{PICKFIELD}", "{NEWPASSWORD}", "{NEWPASSWORD:/Profile/}",
            "{PASSWORD_ENC}", "{HMACOTP}", "{TIMEOTP}", "{CLIPBOARD}", "{CLIPBOARD-SET:/x/}", "{C:comment}", "{CMD:/notepad/}",
            "{T-REPLACE-RX:/a/b/c/}", "{T-CONV:/x/U/}", "user {USERNAME} at {URL:HOST}",
        ],
    )
    fun `each placeholder KeePass 2 fills in is found, ignoring case`(text: String) {
        assertTrue(KeePassPlaceholders.containsOther(text, CUSTOM), text)
    }

    @ParameterizedTest
    @ValueSource(strings = ["", "plain", "{REF:U@T:x}", "{TAB}", "{ENTER}", "{DELAY 500}", "%USERNAME%", "50% off", "{", "}{", "{TITLE", "{unknown}", "{S}", "{URL:PARAMETER:q}"])
    fun `references, auto-type keys, environment variables and other braces are not`(text: String) {
        assertFalse(KeePassPlaceholders.containsOther(text, CUSTOM), text)
    }

    // {S:name} is filled only for a custom field the entry has, matched ignoring case; standard
    // fields are filled only by their own names ({TITLE}, never {S:Title}).
    @Test
    fun `S placeholders count only for a custom field the entry has`() {
        assertTrue(KeePassPlaceholders.containsOther("{S:Account}", CUSTOM))
        assertTrue(KeePassPlaceholders.containsOther("{s:ACCOUNT}", CUSTOM))
        assertFalse(KeePassPlaceholders.containsOther("{S:Missing}", CUSTOM))
        assertFalse(KeePassPlaceholders.containsOther("{S:Title}", CUSTOM))
        assertFalse(KeePassPlaceholders.containsOther("{S:Account}", emptyList()))
        assertTrue(KeePassPlaceholders.containsOther("{S:Missing} {TITLE}", CUSTOM))
    }

    private companion object {
        val CUSTOM = listOf("Account", "PIN")
    }
}
