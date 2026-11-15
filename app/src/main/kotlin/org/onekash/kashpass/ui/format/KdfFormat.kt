package org.onekash.kashpass.ui.format

import java.math.BigDecimal
import java.math.BigInteger
import java.math.RoundingMode
import java.text.NumberFormat

/** Formats key-derivation numbers the same way on every screen. */
object KdfFormat {

    private val MIB = BigDecimal(1024L * 1024L)

    /** Formats [n] with the locale's grouping, as an unsigned 64-bit value. */
    fun count(n: ULong): String = NumberFormat.getIntegerInstance().format(BigInteger(n.toString()))

    /**
     * Formats [thousandths] of a key-derivation work unit with the locale's grouping and up to
     * three decimals, trailing zeros dropped; exact, as the value has no more decimals.
     */
    fun units(thousandths: ULong): String {
        val format = NumberFormat.getNumberInstance().apply { maximumFractionDigits = 3 }
        return format.format(BigDecimal(BigInteger(thousandths.toString())).movePointLeft(3))
    }

    /**
     * Formats [bytes] as MiB, rounded down so a value just under a policy threshold never reads as
     * the threshold: two decimals from 1 MiB, four below it, trailing zeros dropped.
     */
    fun mib(bytes: ULong): String {
        val value = BigDecimal(BigInteger(bytes.toString()))
        val scale = if (value < MIB) 4 else 2
        return value.divide(MIB, scale, RoundingMode.DOWN).stripTrailingZeros().toPlainString()
    }
}
