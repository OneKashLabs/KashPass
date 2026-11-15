package org.onekash.kashpass.vault.kdbx

import kotlin.random.Random
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.Seen
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.InnerStream
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RecordingBuffers

class ArcFourVariantTest {

    private fun Keystream.apply(data: ByteArray): ByteArray = data.copyOf().also { xor(it, 0, it.size) }

    @Test
    fun `equals the test toolkit's copy for keys of many lengths`() {
        val r = Random(1)
        for (length in listOf(1, 2, 31, 32, 64, 255, 256, 300)) {
            val key = r.nextBytes(length)
            val plain = r.nextBytes(3000)
            assertContentEquals(InnerStream.create(KdbxToolkit.ARCFOUR_VARIANT, key).process(plain), ArcFourVariant(key).apply(plain), "key of $length bytes")
        }
    }

    @Test
    fun `a stream split at any boundary gives the one-call result`() {
        val key = Random(2).nextBytes(64)
        val whole = ArcFourVariant(key).apply(ByteArray(700))
        val data = ByteArray(700)
        val a = ArcFourVariant(key)
        var at = 0
        for (n in listOf(0, 1, 63, 0, 200, 436)) {
            a.xor(data, at, n)
            at += n
        }
        assertContentEquals(whole, data)
    }

    // KeePass 2 opened these cases with the same content as their base case, so its ArcFour
    // variant decrypted their protected values to the base case's plaintext.
    @Test
    fun `decrypts every corpus case KeePass 2 opened with the ArcFour variant to its base content`() {
        val key = KdbxToolkit.Key(TestFiles.password)
        val byName = Corpus.all.associateBy { it.name }
        val checked = Corpus.all.filter { it.keepass2 == Seen.OPEN && it.sameContentAs != null && "bomb" !in it.name }.mapNotNull { case ->
            val opened = runCatching { KdbxToolkit.open(case.bytes, key) }.getOrNull() ?: return@mapNotNull null
            val effective = KdbxToolkit.effective(opened.layers.header)
            val inner = opened.layers.inner
            val id = inner.lastOrNull { it.id == KdbxToolkit.INNER_STREAM_ID && it.data.size >= 4 }?.let { Bytes.readLe32(it.data, 0) }
                ?: effective.outerStreamId ?: KdbxToolkit.ARCFOUR_VARIANT
            if (id != KdbxToolkit.ARCFOUR_VARIANT) return@mapNotNull null
            val streamKey = inner.lastOrNull { it.id == KdbxToolkit.INNER_STREAM_KEY }?.data ?: effective.outerStreamKey!!
            val stream = ArcFourVariant(streamKey)
            val decrypted = KdbxToolkit.protectedCiphertexts(opened.layers.xml).map { stream.apply(it) }
            val base = KdbxToolkit.open(byName.getValue(case.sameContentAs!!).bytes, key).layers.protectedValues
            assertEquals(base.map { it.toList() }, decrypted.map { it.toList() }, case.name)
            case.name
        }
        assertEquals(listOf("inner-stream-arcfour-variant", "inner-stream-id-missing"), checked.sorted())
    }

    @Test
    fun `an empty key is refused`() {
        assertEquals(KdbxException.Field.ARCFOUR_KEY, assertThrows<KdbxException.InvalidLength> { ArcFourVariant(ByteArray(0)) }.field)
    }

    @Test
    fun `close zero-fills the state and refuses later use`() {
        val buffers = RecordingBuffers()
        val a = ArcFourVariant(Random(3).nextBytes(32), buffers)
        a.xor(ByteArray(100), 0, 100)
        a.close()
        buffers.assertRecorded(bytes = listOf(256))
        buffers.assertAllZero()
        assertThrows<KdbxException.Closed> { a.xor(ByteArray(1), 0, 1) }
        assertThrows<KdbxException.InvalidLength> { ArcFourVariant(ByteArray(1)).xor(ByteArray(1), 1, 1) }
    }
}
