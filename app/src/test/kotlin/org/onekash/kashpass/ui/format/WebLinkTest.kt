package org.onekash.kashpass.ui.format

import org.junit.Assert.assertEquals
import org.junit.Test

class WebLinkTest {

    @Test
    fun `only http and https links open, and a bare host gets https`() {
        val cases = listOf(
            "https://example.com/login" to "https://example.com/login",
            "http://example.com" to "http://example.com",
            "HTTPS://Example.com" to "https://Example.com",
            "https://example.com:8443/a?b=c#d" to "https://example.com:8443/a?b=c#d",
            "  https://example.com  " to "https://example.com",
            "example.com" to "https://example.com",
            "example.com/path?q=1" to "https://example.com/path?q=1",
            "example.com:8443" to "https://example.com:8443",
            "localhost:8080" to "https://localhost:8080",
            "localhost" to "https://localhost",
            // A cmd:// URL runs a program on the desktop; only http and https open.
            "cmd://calc.exe" to null,
            "CMD://calc.exe" to null,
            "file:///sdcard/a.txt" to null,
            "javascript:alert(1)" to null,
            "intent://scan#Intent;scheme=zxing;end" to null,
            "data:text/html,hi" to null,
            "content://media/1" to null,
            "mailto:a@example.com" to null,
            "ftp://example.com" to null,
            "kdbx://other.kdbx" to null,
            // A URL holding a placeholder or field reference does not open.
            "{REF:U@I:1234}" to null,
            "https://example.com/{USERNAME}" to null,
            // User info would show one host and open another; an email address isn't a link.
            "https://bank.example@evil.example" to null,
            "user@example.com" to null,
            "https://" to null,
            "https:example.com" to null,
            "" to null,
            "   " to null,
            "two words.com" to null,
            "https://exa mple.com" to null,
            "bank" to null,
            "//example.com" to null,
        )
        for ((input, expected) in cases) assertEquals(input, expected, WebLink.of(input))
    }
}
