package org.onekash.kashpass.vault.property

import io.kotest.property.checkAll
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.index.documentOf
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.VaultModel

class GeneratorsTest {

    @Test
    fun `every generated vault opens with KashPass and the toolkit, and the generator covers each shape`() = runBlocking<Unit> {
        var withBin = 0
        var withHistory = 0
        var withProtectedCustom = 0
        var savesAs41 = 0
        checkAll(PropertyRuns.config(40), Generators.doc) { doc ->
            val bytes = VaultModel.write(doc, aesRounds = 1UL)
            val document = documentOf(bytes)
            KdbxToolkit.open(bytes, KdbxToolkit.Key(TestVaults.PASSWORD))
            if (doc.recycleBin != null) withBin++
            if (Generators.entries(doc.root).any { it.history.isNotEmpty() }) withHistory++
            if (Generators.entries(doc.root).any { e -> e.fields.any { (k, v) -> k !in Generators.STANDARD && v is VaultModel.Value.Protected } }) withProtectedCustom++
            if (document.savedMinor() == 1) savesAs41++
        }
        assertTrue(withBin > 0 && withHistory > 0 && withProtectedCustom > 0 && savesAs41 > 0, "bin $withBin, history $withHistory, protected custom $withProtectedCustom, 4.1 $savesAs41")
    }

    @Test
    fun `generated text is XML-safe, CR-free and never whitespace alone, and any-text reaches lone surrogates and controls`() = runBlocking<Unit> {
        checkAll(PropertyRuns.config(200), Generators.safeText) { s ->
            assertTrue(s.none { it == '\r' || (it < ' ' && it != '\t' && it != '\n') } && !KeePassText.hasLoneSurrogate(s), s)
            assertTrue(s.isEmpty() || s.isNotBlank(), "whitespace alone")
        }
        var lone = 0
        var control = 0
        checkAll(PropertyRuns.config(200), Generators.anyText) { s ->
            if (KeePassText.hasLoneSurrogate(s)) lone++
            if (s.any { it < ' ' && it != '\t' && it != '\n' }) control++
        }
        assertTrue(lone > 0 && control > 0, "lone $lone, control $control")
    }
}
