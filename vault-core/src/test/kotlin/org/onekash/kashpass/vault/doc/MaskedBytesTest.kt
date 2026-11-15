package org.onekash.kashpass.vault.doc

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class MaskedBytesTest {

    @Test
    fun `the given array is masked in place and the plaintext comes back as a fresh copy`() {
        val plain = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)
        val given = plain.copyOf()
        val masked = MaskedBytes.of(given)
        assertFalse(given.contentEquals(plain), "the caller's array holds no plaintext")
        val first = masked.plain()
        assertContentEquals(plain, first)
        first.fill(0)
        assertContentEquals(plain, masked.plain(), "zero-filling a copy leaves the value intact")
        assertEquals(16, masked.byteLength)
    }

    @Test
    fun `two values compare by content and print no content`() {
        val a = MaskedBytes.of("secret".toByteArray())
        assertTrue(a.contentEquals(MaskedBytes.of("secret".toByteArray())))
        assertFalse(a.contentEquals(MaskedBytes.of("secreT".toByteArray())))
        assertFalse(a.contentEquals(MaskedBytes.of("secret!".toByteArray())))
        assertFalse("secret" in a.toString())
    }

    @Test
    fun `an empty value is empty`() {
        val empty = MaskedBytes.of(ByteArray(0))
        assertEquals(0, empty.byteLength)
        assertContentEquals(ByteArray(0), empty.plain())
    }
}
