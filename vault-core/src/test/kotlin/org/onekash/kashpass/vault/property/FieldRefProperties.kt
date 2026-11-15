package org.onekash.kashpass.vault.property

import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.checkAll
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.onekash.kashpass.vault.index.FieldRefs
import org.onekash.kashpass.vault.index.FieldValue
import org.onekash.kashpass.vault.index.documentOf
import org.onekash.kashpass.vault.testing.Generators
import org.onekash.kashpass.vault.testing.PropertyRuns
import org.onekash.kashpass.vault.testing.VaultModel
import org.onekash.kashpass.vault.testing.VaultModel.Value

/**
 * Field references resolve by these rules: a chain of n references by UUID ends in its last
 * entry's text below 12 levels and in nothing from 12 on, a cycle or a self-reference resolves to
 * nothing, a reference to no entry stays as written, text without `{REF:` is itself, and the work
 * stays within the bound the pass and level limits set, counted by searches and entries read.
 */
class FieldRefProperties {

    private fun hex(u: UUID) = "%016X%016X".format(u.mostSignificantBits, u.leastSignificantBits)

    private fun ref(u: UUID) = "{REF:N@I:${hex(u)}}"

    private fun entry(uuid: UUID, notes: String) = VaultModel.Entry(listOf("Title" to Value.Plain("e"), "Notes" to Value.Plain(notes)), uuid = uuid)

    private fun refs(entries: List<VaultModel.Entry>) =
        FieldRefs.from(documentOf(VaultModel.write(VaultModel.Doc(VaultModel.Group("Root", entries = entries)), aesRounds = 1UL)))

    @Test
    fun `a chain of n references ends in its last text below 12 levels and in nothing from 12 on`() = runBlocking<Unit> {
        checkAll(PropertyRuns.config(40), Arb.int(1..16), Arb.int(0..1_000_000)) { n, salt ->
            val ids = List(n + 1) { UUID(salt.toLong(), it.toLong()) }
            val entries = ids.mapIndexed { i, u -> entry(u, if (i < n) ref(ids[i + 1]) else "end text") }
            val resolved = refs(entries).resolve(FieldValue.Plain(ref(ids[1])))
            // The value holds the first reference; resolving it inserts entry 1's notes at level 1,
            // which hold the next reference, so the chain's end text is inserted at level n.
            val expected = if (n < 12) "end text" else ""
            assertEquals(expected, resolved.value.reveal(), "chain of $n")
            assertTrue(resolved.entriesRead <= entries.size, "entries read ${resolved.entriesRead}")
            assertTrue(resolved.searches <= 20 * (1 + 12 * n), "searches ${resolved.searches} for $n distinct references")
        }
    }

    @Test
    fun `a cycle or a self-reference resolves to nothing, a missing target stays, plain text is itself`() = runBlocking<Unit> {
        checkAll(PropertyRuns.config(40), Arb.int(2..6), Generators.safeText) { size, text ->
            val ids = List(size) { UUID(7L, it.toLong()) }
            val cycle = ids.mapIndexed { i, u -> entry(u, ref(ids[(i + 1) % size])) }
            val self = UUID(8L, 0L)
            val r = refs(cycle + entry(self, ref(self)))
            assertEquals("", r.resolve(FieldValue.Plain(ref(ids[0]))).value.reveal(), "cycle of $size")
            assertEquals("", r.resolve(FieldValue.Plain(ref(self))).value.reveal(), "self-reference")
            val missing = ref(UUID(9L, 9L))
            assertEquals("a $missing b", r.resolve(FieldValue.Plain("a $missing b")).value.reveal(), "missing target")
            if (!text.contains("{REF:", ignoreCase = true)) assertEquals(text, r.resolve(FieldValue.Plain(text)).value.reveal(), "plain text")
        }
    }
}
