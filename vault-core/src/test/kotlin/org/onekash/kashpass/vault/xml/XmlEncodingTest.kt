package org.onekash.kashpass.vault.xml

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class XmlEncodingTest {

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    @Test
    fun `the first four bytes pick the encoding as the desktop runtime's DetectEncoding does`() {
        assertEquals(XmlEncoding.UTF_16LE, XmlEncoding.detect(bytes(0xFF, 0xFE, 0x3C, 0x00)))
        assertEquals(XmlEncoding.UTF_16BE, XmlEncoding.detect(bytes(0xFE, 0xFF, 0x00, 0x3C)))
        assertEquals(XmlEncoding.UTF_16LE_UNMARKED, XmlEncoding.detect(bytes(0x3C, 0x00, 0x3F, 0x00)))
        assertEquals(XmlEncoding.UTF_16LE_UNMARKED, XmlEncoding.detect(bytes(0x3C, 0x00, 0x4B, 0x00)), "any '<', not only '<?'")
        assertEquals(XmlEncoding.UTF_16BE_UNMARKED, XmlEncoding.detect(bytes(0x00, 0x3C, 0x00, 0x3F)))
        assertEquals(XmlEncoding.UTF_8, XmlEncoding.detect(bytes(0xEF, 0xBB, 0xBF, 0x3C)))
        assertEquals(XmlEncoding.UTF_8, XmlEncoding.detect("<?xml".toByteArray()))
        assertEquals(XmlEncoding.UTF_8, XmlEncoding.detect(bytes(0x3C)))
        assertEquals(XmlEncoding.UTF_8, XmlEncoding.detect(ByteArray(0)))
        assertEquals(2, XmlEncoding.UTF_16LE.bomBytes)
        assertEquals(0, XmlEncoding.UTF_16BE_UNMARKED.bomBytes)
    }

    @Test
    fun `UCS-4 is detected and not read`() {
        for (head in listOf(bytes(0x00, 0x00, 0xFE, 0xFF), bytes(0x00, 0x00, 0x00, 0x3C), bytes(0x00, 0x00, 0xFF, 0xFE), bytes(0x00, 0x00, 0x3C, 0x00), bytes(0xFF, 0xFE, 0x00, 0x00), bytes(0xFE, 0xFF, 0x00, 0x00), bytes(0x3C, 0x00, 0x00, 0x00), bytes(0x00, 0x3C, 0x00, 0x00))) {
            assertNull(XmlEncoding.detect(head), head.joinToString { "%02X".format(it) })
        }
    }

    @Test
    fun `UTF-16 becomes UTF-8 without its byte order mark, a lone surrogate as U+FFFD`() {
        // A String can't hold the lone surrogate through the JDK's encoder, so its bytes are
        // written out: D800 with no low surrogate after it.
        val le = bytes(0xFF, 0xFE) + "<a>é😀".toByteArray(Charsets.UTF_16LE) + bytes(0x00, 0xD8) + "x</a>".toByteArray(Charsets.UTF_16LE)
        assertContentEquals("<a>é😀\uFFFDx</a>".toByteArray(), XmlEncoding.detect(le)!!.toUtf8(le))
        val be = "<a>é😀".toByteArray(Charsets.UTF_16BE) + bytes(0xD8, 0x00) + "x</a>".toByteArray(Charsets.UTF_16BE)
        assertContentEquals("<a>é😀\uFFFDx</a>".toByteArray(), XmlEncoding.detect(be)!!.toUtf8(be))
    }

    @Test
    fun `a UTF-16 document keeps a declaration naming UTF-16 or no encoding, and no other`() {
        fun utf8(declaration: String): ByteArray? {
            val doc = ("$declaration<a/>").toByteArray(Charsets.UTF_16LE)
            return XmlEncoding.detect(doc)!!.toUtf8(doc)
        }
        for (kept in listOf("", "<?xml version=\"1.0\"?>", "<?xml version='1.0' encoding='UTF-16'?>", "<?xml version=\"1.0\" encoding=\"ucs-2\"?>", "<?xml version=\"1.0\" encoding=\"ISO-10646-UCS-2\"?>", "<?xml version=\"1.0\" encoding=\"ucs-4\"?>")) {
            assertContentEquals("$kept<a/>".toByteArray(), utf8(kept), kept)
        }
        for (other in listOf("<?xml version=\"1.0\" encoding=\"utf-8\"?>", "<?xml version=\"1.0\" encoding=\"windows-1252\"?>")) {
            assertNull(utf8(other), other)
        }
    }

    @Test
    fun `the root name is found past white space, declarations, processing instructions and comments`() {
        val prolog = "﻿<?xml version=\"1.0\"?>\r\n<!-- <Other/> -->\t<?pi <Other/>?> \n"
        for (encoding in listOf(Charsets.UTF_8, Charsets.UTF_16LE, Charsets.UTF_16BE)) {
            fun rootIs(text: String): Boolean {
                val doc = text.toByteArray(encoding)
                return XmlEncoding.detect(doc)!!.rootIs(doc, "KeyFile")
            }
            assertTrue(rootIs("$prolog<KeyFile>"), "$encoding")
            assertTrue(rootIs("<KeyFile/>"), "$encoding")
            assertTrue(rootIs("<KeyFile\n a=\"1\">"), "$encoding")
            assertFalse(rootIs("$prolog<KeyFiles>"), "$encoding")
            assertFalse(rootIs("<Other><KeyFile>"), "$encoding")
            assertFalse(rootIs("x<KeyFile>"), "$encoding")
            assertFalse(rootIs("<!-- <KeyFile>"), "$encoding")
            assertFalse(rootIs("<KeyFile"), "$encoding")
            assertFalse(rootIs(""), "$encoding")
        }
    }
}
