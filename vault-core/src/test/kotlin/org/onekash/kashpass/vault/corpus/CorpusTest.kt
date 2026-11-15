package org.onekash.kashpass.vault.corpus

import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

/**
 * The corpus is deterministic, its names are unique, and its expectations follow the KeePass 2
 * rule.
 */
class CorpusTest {

    @Test
    fun `building the corpus twice gives the same bytes for every case`() {
        val first = Corpus.all.associate { it.name to it.bytes }
        for (case in Corpus.rebuild()) assertContentEquals(first.getValue(case.name), case.bytes, case.name)
    }

    // Every case keeps a KeePass 2 outcome ([CorpusCase.keepass2] is not nullable); a change that
    // drops cases has to lower this floor on purpose.
    @Test
    fun `the corpus holds at least 2411 cases`() {
        assertTrue(Corpus.all.size >= 2411, "${Corpus.all.size} cases")
    }

    @Test
    fun `case names are unique`() {
        val names = Corpus.all.map { it.name }
        assertEquals(names.size, names.toSet().size, names.groupBy { it }.filterValues { it.size > 1 }.keys.toString())
    }

    @Test
    fun `the spec opens what KeePass 2 opens and refuses what it refuses, outside the approved exceptions`() {
        val opens = setOf(Spec.OPENS, Spec.OPENS_READ_ONLY)
        val exceptions = setOf(Spec.REFUSED_BY_POLICY, Spec.NOT_ENOUGH_MEMORY)
        val wrong = Corpus.all.filterNot { c ->
            if (c.reference == Seen.OPEN) c.spec in opens || c.spec in exceptions else c.spec !in opens && c.spec != Spec.NOT_ENOUGH_MEMORY
        }
        assertTrue(wrong.isEmpty(), wrong.joinToString { "${it.name}: KeePass 2 ${it.reference}, spec ${it.spec}" })
    }

    @Test
    fun `every recorded damage layer names a case of the corpus`() {
        assertEquals(emptySet(), CorpusRecipes().unknownRecordedNames(Corpus.all.map { it.name }.toSet()))
    }

    @Test
    fun `a Windows outcome differs from the Mono one and has a reason`() {
        val bad = Corpus.all.filter { c -> (c.windows != null) != (c.windowsReason != null) || (c.windows != null && c.windows == c.keepass2) }
        assertTrue(bad.isEmpty(), bad.joinToString { it.name })
        assertEquals(setOf("gzip-flag-zlib-content", "spec-meta-binary-compressed-zlib"), Corpus.all.filter { it.windows != null }.map { it.name }.toSet())
    }

    @Test
    fun `every damaged case names its damage layer and no other case does`() {
        val layers = org.onekash.kashpass.vault.kdbx.KdbxDamage.entries.map { it.name }.toSet()
        val bad = Corpus.all.filter { c -> (c.spec == Spec.DAMAGED) != (c.damage != null) || (c.damage != null && c.damage !in layers) }
        assertTrue(bad.isEmpty(), bad.joinToString { "${it.name}: ${it.spec} ${it.damage}" })
    }

    @Test
    fun `every policy refusal names its approved exception and no other case names one`() {
        val wrong = Corpus.all.filter { c -> (c.spec == Spec.REFUSED_BY_POLICY) != (c.policyException in 1..4) }
        assertTrue(wrong.isEmpty(), wrong.joinToString { "${it.name}: spec ${it.spec}, exception ${it.policyException}" })
    }

    @Test
    fun `every content base is a case KeePass 2 opens`() {
        val byName = Corpus.all.associateBy { it.name }
        val wrong = Corpus.all.filter { c -> c.sameContentAs?.let { byName[it]?.keepass2 != Seen.OPEN } ?: false }
        assertTrue(wrong.isEmpty(), wrong.joinToString { "${it.name}: base ${it.sameContentAs}" })
    }
}
