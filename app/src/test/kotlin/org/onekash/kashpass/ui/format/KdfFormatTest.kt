package org.onekash.kashpass.ui.format

import java.util.Locale
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class KdfFormatTest {

    private val saved = Locale.getDefault()

    @Before
    fun english() = Locale.setDefault(Locale.US)

    @After
    fun restore() = Locale.setDefault(saved)

    @Test
    fun `counts are grouped and never wrap negative`() {
        assertEquals("6,000", KdfFormat.count(6_000UL))
        assertEquals("18,446,744,073,709,551,615", KdfFormat.count(ULong.MAX_VALUE))
    }

    @Test
    fun `MiB rounds down, with two decimals from 1 MiB and four below, and drops trailing zeros`() {
        assertEquals("64", KdfFormat.mib(64UL * 1024UL * 1024UL))
        assertEquals("0.5", KdfFormat.mib(512UL * 1024UL))
        assertEquals("0.0078", KdfFormat.mib(8UL * 1024UL))
        assertEquals("63.99", KdfFormat.mib(64UL * 1024UL * 1024UL - 1UL))
        assertEquals("0", KdfFormat.mib(0UL))
    }

    @Test
    fun `units are thousandths shown with up to three decimals, grouped, never wrapping negative`() {
        assertEquals("1", KdfFormat.units(1_000UL))
        assertEquals("1.001", KdfFormat.units(1_001UL))
        assertEquals("0.01", KdfFormat.units(10UL))
        assertEquals("100,000", KdfFormat.units(100_000_000UL))
        assertEquals("18,446,744,073,709,551.615", KdfFormat.units(ULong.MAX_VALUE))
    }
}
