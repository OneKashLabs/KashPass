package org.onekash.kashpass.vault.kdbx

import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.testing.PrimitiveVectors

class PrimitiveVectorsTest {

    @Test
    fun `every published vector and edge case passes on the host JVM`() {
        assertEquals(emptyList(), PrimitiveVectors.failures())
    }

    @Test
    fun `a corrupted expected value is reported by name`() {
        val good = PrimitiveVectors.hmac
        val bad = good.mapIndexed { i, v -> if (i == 2) PrimitiveVectors.Hmac(v.name, v.key, v.data, "00" + v.mac.drop(2)) else v }
        assertEquals(listOf(good[2].name), PrimitiveVectors.failures(bad))
    }
}
