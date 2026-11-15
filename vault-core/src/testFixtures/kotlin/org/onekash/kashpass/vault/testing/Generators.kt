package org.onekash.kashpass.vault.testing

import io.kotest.property.Arb
import io.kotest.property.arbitrary.arbitrary
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.map
import java.time.Instant
import java.util.UUID
import kotlin.random.Random
import org.onekash.kashpass.vault.header.Argon2Variant
import org.onekash.kashpass.vault.header.KdfSettings
import org.onekash.kashpass.vault.testing.VaultModel.Value

/** Generators the property tests share: vaults, field text and KDF settings. */
object Generators {

    /** The five standard fields of an entry, in their standard order. */
    val STANDARD = listOf("Title", "UserName", "Password", "URL", "Notes")

    // Text units for XML-safe text: ASCII letters and punctuation, the five XML specials, tab and
    // LF, non-ASCII letters and one surrogate pair (kept whole). No CR: VaultModel writes it raw
    // and both readers turn it into LF.
    private val SAFE_UNITS = ('a'..'z').map { "$it" } + ('A'..'Z').map { "$it" } + ('0'..'9').map { "$it" } +
        listOf(" ", "-", "_", ".", "@", "/", "&", "<", ">", "\"", "'", "\t", "\n", "é", "ü", "ß", "漢", "字", "\uD83D\uDE00")

    // Code units the KDBX XML rules treat specially, for [anyText].
    private val EDGE_UNITS = listOf("\u0000", "\u0001", "\u001F", "\r", "\uD800", "\uDBFF", "\uDC00", "\uDFFF", "\uFFFE", "\uFFFF", "\u007F")

    /**
     * XML-safe text up to 20 units, without CR and never whitespace alone (a whitespace-only plain
     * value is a separate case of the text properties).
     */
    val safeText: Arb<String> = Arb.list(Arb.element(SAFE_UNITS), 0..20).map { units ->
        units.joinToString("").let { if (it.isNotEmpty() && it.isBlank()) "x$it" else it }
    }

    /**
     * Any UTF-16 text up to 20 units (the safe units' surrogate pair counts as one), controls, CR,
     * lone surrogates and noncharacters included, and text of XML whitespace alone (space, tab, CR,
     * LF).
     */
    val anyText: Arb<String> = Arb.choice(
        Arb.list(Arb.choice(Arb.element(SAFE_UNITS), Arb.element(EDGE_UNITS), Arb.int(0..0xFFFF).map { it.toChar().toString() }), 0..20)
            .map { it.joinToString("") },
        Arb.list(Arb.element(" ", "\t", "\r", "\n"), 1..6).map { it.joinToString("") },
    )

    /**
     * A vault: a root with up to three subgroups (some with tags, which make a KashPass save KDBX
     * 4.1) and a recycle bin, entries with standard and custom fields (plain or protected), tags,
     * attachments and history, and history limits the starting history keeps. The recycle bin is a
     * group (enabled or not), enabled with no group yet (the setting of a new database),
     * or absent. History is in ascending modification time, or in another order with a repeated
     * time. The vault itself does not shrink; a property's other inputs do.
     */
    val doc: Arb<VaultModel.Doc> = arbitrary { rs -> doc(rs.random) }

    /** Every entry under [group], outside history, depth first. */
    fun entries(group: VaultModel.Group): List<VaultModel.Entry> = group.entries + group.groups.flatMap { entries(it) }

    // A fixed origin, so a seed gives the same vault on every run.
    private val ORIGIN: Instant = Instant.parse("2024-01-01T00:00:00Z")

    private fun doc(r: Random): VaultModel.Doc {
        val attachments = List(r.nextInt(0, 3)) { ByteArray(r.nextInt(0, 64)) { r.nextInt().toByte() } }
        val maxItems = listOf(-1, 0, 1, 2, 3, 10).random(r)
        val ctx = Ctx(r, attachments.size, maxItems)
        val groups = MutableList(r.nextInt(0, 4)) { i ->
            VaultModel.Group(word(r, "Group$i"), entries = List(r.nextInt(0, 4)) { ctx.entry() }, uuid = uuid(r), tags = if (r.nextInt(4) == 0) listOf(word(r, "tag")) else emptyList())
        }
        var bin: UUID? = null
        val binKind = r.nextInt(4)
        if (binKind == 0) {
            bin = uuid(r)
            groups += VaultModel.Group("Recycle Bin", entries = List(r.nextInt(0, 3)) { ctx.entry() }, uuid = bin)
        }
        val root = VaultModel.Group("Root", entries = List(r.nextInt(0, 4)) { ctx.entry() }, groups = groups, uuid = uuid(r))
        val enabled = when (binKind) {
            0 -> r.nextInt(5) != 0
            1 -> true
            else -> false
        }
        return VaultModel.Doc(
            root, recycleBin = bin, attachments = attachments, historyMaxItems = maxItems,
            historyMaxSize = listOf(-1L, 6_291_456L).random(r), recycleBinEnabled = enabled,
        )
    }

    private class Ctx(val r: Random, val attachments: Int, val maxItems: Int) {
        var minutes = 0L

        fun entry(): VaultModel.Entry {
            val id = uuid(r)
            var times = List(r.nextInt(0, 4).let { if (maxItems >= 0) minOf(it, maxItems) else it }) { next() }
            // History trims by oldest time, not by order: some histories are out of time order
            // and some repeat a time.
            if (times.size > 1 && r.nextInt(3) == 0) times = times.shuffled(r)
            if (times.size > 1 && r.nextInt(4) == 0) times = times.toMutableList().also { it[1] = it[0] }
            val history = times.map { t -> VaultModel.Entry(fields(entryWithBinaries = false), times = VaultModel.Times.at(t), uuid = id) }
            val binaries = if (attachments > 0 && r.nextBoolean()) listOf("file-${r.nextInt(100)}.txt" to r.nextInt(attachments)) else emptyList()
            return VaultModel.Entry(
                fields(entryWithBinaries = true), tags = List(r.nextInt(0, 3)) { word(r, "t") }, history = history,
                binaries = binaries, times = VaultModel.Times.at(next()), uuid = id,
            )
        }

        private fun next(): Instant = ORIGIN.plusSeconds(60 * ++minutes)

        private fun fields(entryWithBinaries: Boolean): List<Pair<String, Value>> {
            val standard = STANDARD.map { key ->
                val text = text(r)
                key to when {
                    key == "Password" -> if (r.nextInt(10) == 0) Value.Plain(text) else Value.Protected(text)
                    r.nextInt(7) == 0 -> Value.Protected(text)
                    else -> Value.Plain(text)
                }
            }
            val custom = List(r.nextInt(0, 3)) { i -> "Field$i ${word(r, "k")}" to (if (r.nextInt(5) < 2) Value.Protected(text(r)) else Value.Plain(text(r))) }
            return standard + custom.distinctBy { it.first }
        }
    }

    private fun text(r: Random): String =
        List(r.nextInt(0, 21)) { SAFE_UNITS.random(r) }.joinToString("").let { if (it.isNotEmpty() && it.isBlank()) "x$it" else it }

    private fun word(r: Random, prefix: String) = prefix + List(r.nextInt(1, 6)) { ('a'..'z').random(r) }.joinToString("")

    private fun uuid(r: Random) = UUID(r.nextLong(), r.nextLong())

    // Values at, just inside and just outside each KdfPolicy bound, Int and UInt edges included.
    private val ROUNDS = listOf(0UL, 1UL, 2UL, 1_000UL, 0x7FFF_FFFFUL, 0x8000_0000UL, 0xFFFF_FFFFUL, ULong.MAX_VALUE)
    private val ITERATIONS = listOf(0UL, 1UL, 2UL, 3UL, 0x7FFF_FFFFUL, 0x8000_0000UL, 0xFFFF_FFFFUL, ULong.MAX_VALUE)
    private val LANES = listOf(0U, 1U, 2U, 4U, 0xFF_FFFFU, 0x100_0000U, UInt.MAX_VALUE)
    private val MEMORY = listOf(0UL, 1_024UL, 8_191UL, 8_192UL, 16_384UL, 1_048_576UL, 0x7FFF_FFFFUL, 0x8000_0000UL, ULong.MAX_VALUE)
    private val VERSIONS = listOf(0x00U, 0x10U, 0x12U, 0x13U, 0x14U, UInt.MAX_VALUE)

    /**
     * Argon2 settings KdfPolicy accepts and a unit test can derive: 1-3 iterations, 1, 2 or 4
     * lanes, memory from 8 KiB (below 8 KiB per lane when there are several lanes, which derives
     * with 8 KiB per lane) to 1 MiB, version 0x10 or 0x13, either variant.
     */
    val acceptedArgon2: Arb<KdfSettings.Argon2> = arbitrary { rs ->
        val r = rs.random
        KdfSettings.Argon2(
            if (r.nextBoolean()) Argon2Variant.ARGON2D else Argon2Variant.ARGON2ID,
            r.nextLong(1, 4).toULong(), listOf(8_192UL, 16_384UL, 65_536UL, 1_048_576UL).random(r),
            listOf(1U, 2U, 4U).random(r), listOf(0x10U, 0x13U).random(r),
        )
    }

    /** KDF settings around every KdfPolicy bound, mixed with random values. */
    val kdfSettings: Arb<KdfSettings> = Arb.choice(
        Arb.choice(Arb.element(ROUNDS), Arb.long().map { it.toULong() }).map { KdfSettings.AesKdf(it) },
        arbitrary { rs ->
            val r = rs.random
            fun <T> pick(edges: List<T>, random: () -> T) = if (r.nextInt(4) == 0) random() else edges.random(r)
            KdfSettings.Argon2(
                if (r.nextBoolean()) Argon2Variant.ARGON2D else Argon2Variant.ARGON2ID,
                pick(ITERATIONS) { r.nextLong().toULong() }, pick(MEMORY) { r.nextLong().toULong() },
                pick(LANES) { r.nextInt().toUInt() }, pick(VERSIONS) { r.nextInt().toUInt() },
            )
        },
    )
}
