package org.onekash.kashpass.vault.kdbx

import kotlin.random.Random
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.KdbxToolkit

/**
 * KashPass's composite key and key schedule against the test toolkit's composite key and the
 * header and block HMACs KeePass 2 stored in each fixture it opens. Keys are compared with
 * contentEquals so that a failure message names the fixture and the key, never key bytes.
 * ContainerDecodeTest pins that the Argon2 0x12 fixture is refused before any derivation.
 */
class KeyScheduleFixturesTest {

    @ParameterizedTest
    @MethodSource("fixtures")
    fun `composite key and key schedule give the stored MACs`(name: String) {
        val fixture = Fixtures.named(name)
        val file = Fixtures.file(fixture)
        val split = KdbxToolkit.split(file.bytes)
        val effective = KdbxToolkit.effective(split.header)

        val key = KdbxToolkit.Key(TestFiles.password(fixture.mode), TestFiles.keyFilePart(file))
        val passwordHash = TestFiles.password(fixture.mode)?.let { KdbxToolkit.sha256(it.encodeToByteArray()) }
        val composite = CompositeKey.compute(passwordHash, TestFiles.keyFilePart(file))
        assertTrue(key.composite().contentEquals(composite), "$name: composite key")

        val transformed = KdbxToolkit.derive(effective.kdf, key)
        val seed = effective.seed!!
        KeySchedule(seed, transformed).use { k ->
            val headerMac = k.headerMac(split.headerBytes, 0, split.headerBytes.size)
            assertTrue(Bytes.constantTimeEquals(split.storedHmac, headerMac), "$name: stored header MAC")
            split.blocks.forEachIndexed { i, block ->
                assertTrue(Bytes.constantTimeEquals(block.hmac, k.blockMac(i.toLong(), block.data, 0, block.data.size)), "$name: stored MAC of block $i")
            }
        }
        assertTrue(split.blocks.size >= 2, "$name: at least one data block and the end block")
    }

    // An XML key file's data can have any non-empty length; no fixture
    // has such a part, so random ones are checked against the toolkit's composite key.
    @Test
    fun `a key-file part that is not 32 bytes gives KeePass 2's composite key`() {
        val r = Random(1)
        val passwordHash = KdbxToolkit.sha256(TestFiles.password.encodeToByteArray())
        for (size in listOf(1, 16, 33, 65, 128)) {
            val part = r.nextBytes(size)
            assertTrue(KdbxToolkit.Key(null, part).composite().contentEquals(CompositeKey.compute(null, part)), "part of $size bytes")
            assertTrue(KdbxToolkit.Key(TestFiles.password, part).composite().contentEquals(CompositeKey.compute(passwordHash, part)), "password and part of $size bytes")
        }
    }

    companion object {
        @JvmStatic
        fun fixtures(): List<String> = Fixtures.kdbx4Opening.map { it.name }
    }
}
