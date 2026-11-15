package org.onekash.kashpass.vault.doc

import kotlin.test.assertContentEquals
import kotlin.test.assertNull
import org.junit.jupiter.api.Test

class ConvertBase64Test {

    @Test
    fun `decodes as dot NET does, skipping space, tab, CR and LF`() {
        assertContentEquals(byteArrayOf(1, 2, 3), ConvertBase64.decode("AQID"))
        assertContentEquals(byteArrayOf(1, 2, 3), ConvertBase64.decode(" A Q\tI\r\nD "))
        assertContentEquals(byteArrayOf(1, 2), ConvertBase64.decode("AQI="))
        assertContentEquals(byteArrayOf(1), ConvertBase64.decode("AQ=="))
        assertContentEquals(byteArrayOf(), ConvertBase64.decode(""))
        assertContentEquals(byteArrayOf(), ConvertBase64.decode(" \n"))
    }

    @Test
    fun `refuses what dot NET refuses`() {
        for (bad in listOf("AQI", "AQ", "A", "AQ=I", "A===", "====", "AQ*D", "AQID=", "2026-10-25T12:00:00Z", "AQ\u000BI=")) {
            assertNull(ConvertBase64.decode(bad), bad)
        }
    }
}
