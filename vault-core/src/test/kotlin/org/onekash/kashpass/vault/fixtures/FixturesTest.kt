package org.onekash.kashpass.vault.fixtures

import java.io.File
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test

class FixturesTest {

    @Test
    fun `the catalogue lists every vault and key file in the fixtures folder`() {
        val folder = File(TestFiles.root, "vault-core/src/test/resources/fixtures")
        val onDisk = folder.list()!!.filter { it.endsWith(".kdbx") }.toSortedSet()
        assertEquals(onDisk, Fixtures.kdbx4.map { it.name }.toSortedSet())
        val keyFiles = folder.list()!!.filter { it.endsWith(".key") || it.endsWith(".keyx") }.toSortedSet()
        assertEquals(keyFiles, Fixtures.kdbx4.mapNotNull { it.keyFile }.toSortedSet())
    }
}
