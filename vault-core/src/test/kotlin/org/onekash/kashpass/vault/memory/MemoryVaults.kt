package org.onekash.kashpass.vault.memory

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Base64
import java.util.Random
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.TestFiles
import org.onekash.kashpass.vault.testing.KdbxToolkit
import org.onekash.kashpass.vault.testing.RawField

/**
 * Builds large test vaults for the memory tests from a KeePass 2 fixture's header and key, with
 * generated XML and attachments. Content comes from a seeded [Random], so a vault's content is the
 * same on every run; AES-KDF at 6,000 rounds, so unlocking stays fast.
 */
internal object MemoryVaults {

    const val MIB = 1024 * 1024

    /** What fills a vault. */
    enum class Shape(val slug: String) {
        /**
         * One random attachment of at most 4 MiB per entry; gzip can't shrink it, so the file is
         * as large as its content.
         */
        ATTACHMENTS("attach-random"),

        /**
         * Text attachments that gzip shrinks to about a third, so the decompressed content is
         * larger than the file.
         */
        TEXT_ATTACHMENTS("attach-text"),

        /** Entries written indented, each with five strings and a protected password. */
        ENTRIES("entries"),

        /** Entries of 100 one-character custom fields each, written without indentation. */
        FIELDS("fields"),
    }

    /**
     * One generated vault: [shape] with about [kib] KiB of content (attachment bytes for the
     * attachment shapes; XML bytes for the others, which pass it by at most one entry and the
     * closing tags), gzip-compressed when [gzip].
     */
    data class Spec(val shape: Shape, val gzip: Boolean, val kib: Int) {
        val name: String get() = "${shape.slug}-${if (gzip) "gzip" else "none"}-${if (kib % 1024 == 0) "${kib / 1024}m" else "${kib}k"}.kdbx"

        companion object {
            /** A spec of [mib] MiB of content. */
            fun mib(shape: Shape, gzip: Boolean, mib: Int) = Spec(shape, gzip, mib * 1024)

            /** Reads a spec back from [name]; null for a name [Spec.name] doesn't produce. */
            fun parse(name: String): Spec? {
                val match = Regex("""(.+)-(gzip|none)-(\d+)([mk])\.kdbx""").matchEntire(name) ?: return null
                val shape = Shape.entries.firstOrNull { it.slug == match.groupValues[1] } ?: return null
                val size = match.groupValues[3].toInt()
                val spec = Spec(shape, match.groupValues[2] == "gzip", if (match.groupValues[4] == "m") size * 1024 else size)
                return spec.takeIf { it.name == name }
            }
        }
    }

    /** Returns the bytes of the vault [spec] describes, unlocked with the fixture password. */
    fun build(spec: Spec): ByteArray {
        val base = KdbxToolkit.open(
            Fixtures.bytes(if (spec.gzip) "keepass2-weak-aeskdf-6000.kdbx" else "keepass2-compression-none.kdbx"),
            KdbxToolkit.Key(TestFiles.password),
        ).layers
        val target = spec.kib.toLong() * 1024
        val random = Random(spec.name.hashCode().toLong())
        val attachments = when (spec.shape) {
            Shape.ATTACHMENTS -> pieces(target).map { ByteArray(it).also(random::nextBytes) }
            Shape.TEXT_ATTACHMENTS -> pieces(target).map { text(it, random) }
            Shape.ENTRIES, Shape.FIELDS -> emptyList()
        }
        val protected = ArrayList<ByteArray>()
        val xml = when (spec.shape) {
            Shape.ATTACHMENTS, Shape.TEXT_ATTACHMENTS -> document { out ->
                attachments.indices.forEach { i -> entry(out, i, random, protected, attachment = i) }
            }
            Shape.ENTRIES -> document { out ->
                var i = 0
                while (out.size() < target) entry(out, i++, random, protected, attachment = null)
            }
            Shape.FIELDS -> document { out ->
                var i = 0
                while (out.size() < target) fieldsEntry(out, i++)
            }
        }
        val inner = base.inner.filter { it.id == KdbxToolkit.INNER_STREAM_ID || it.id == KdbxToolkit.INNER_STREAM_KEY } +
            attachments.map { RawField(KdbxToolkit.INNER_BINARY, byteArrayOf(0) + it) } +
            RawField(KdbxToolkit.INNER_END, ByteArray(0))
        return KdbxToolkit.build(base.copy(inner = inner, xml = xml, protectedValues = protected))
    }

    // Splits [total] bytes into pieces of at most 4 MiB.
    private fun pieces(total: Long): List<Int> {
        val piece = 4L * MIB
        return (0 until (total + piece - 1) / piece).map { minOf(piece, total - it * piece).toInt() }
    }

    // Lines of words and numbers, as an exported log or text file reads.
    private fun text(size: Int, random: Random): ByteArray {
        val words = listOf("alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel")
        val out = ByteArrayOutputStream(size + 64)
        var line = 0
        while (out.size() < size) {
            out.write("${line++} ${words[random.nextInt(words.size)]} ${random.nextInt(1000)}\n".toByteArray())
        }
        return out.toByteArray().copyOf(size)
    }

    private fun document(body: (ByteArrayOutputStream) -> Unit): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(
            ("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile>\n\t<Meta>\n\t\t<Generator>KeePass</Generator>\n" +
                "\t\t<DatabaseName>Memory</DatabaseName>\n\t</Meta>\n\t<Root>\n\t\t<Group>\n\t\t\t<UUID>${uuid(0)}</UUID>\n" +
                "\t\t\t<Name>Root</Name>\n").toByteArray(),
        )
        body(out)
        out.write("\t\t</Group>\n\t\t<DeletedObjects />\n\t</Root>\n</KeePassFile>".toByteArray())
        return out.toByteArray()
    }

    // An indented entry, with [attachment] as a binary reference when not null.
    private fun entry(out: ByteArrayOutputStream, i: Int, random: Random, protected: MutableList<ByteArray>, attachment: Int?) {
        val time = TIME
        val password = ByteArray(20) { ('a' + random.nextInt(26)).code.toByte() }
        protected += password
        val binary = attachment?.let { "\t\t\t\t<Binary>\n\t\t\t\t\t<Key>file-$it.bin</Key>\n\t\t\t\t\t<Value Ref=\"$it\" />\n\t\t\t\t</Binary>\n" } ?: ""
        out.write(
            ("\t\t\t<Entry>\n\t\t\t\t<UUID>${uuid(i + 1)}</UUID>\n\t\t\t\t<IconID>0</IconID>\n\t\t\t\t<ForegroundColor />\n" +
                "\t\t\t\t<BackgroundColor />\n\t\t\t\t<OverrideURL />\n\t\t\t\t<Tags />\n\t\t\t\t<Times>\n" +
                "\t\t\t\t\t<CreationTime>$time</CreationTime>\n\t\t\t\t\t<LastModificationTime>$time</LastModificationTime>\n" +
                "\t\t\t\t\t<LastAccessTime>$time</LastAccessTime>\n\t\t\t\t\t<ExpiryTime>$time</ExpiryTime>\n" +
                "\t\t\t\t\t<Expires>False</Expires>\n\t\t\t\t\t<UsageCount>0</UsageCount>\n" +
                "\t\t\t\t\t<LocationChanged>$time</LocationChanged>\n\t\t\t\t</Times>\n" +
                "\t\t\t\t<String>\n\t\t\t\t\t<Key>Notes</Key>\n\t\t\t\t\t<Value>Notes of entry $i</Value>\n\t\t\t\t</String>\n" +
                "\t\t\t\t<String>\n\t\t\t\t\t<Key>Password</Key>\n\t\t\t\t\t<Value Protected=\"True\">x</Value>\n\t\t\t\t</String>\n" +
                "\t\t\t\t<String>\n\t\t\t\t\t<Key>Title</Key>\n\t\t\t\t\t<Value>Entry $i</Value>\n\t\t\t\t</String>\n" +
                "\t\t\t\t<String>\n\t\t\t\t\t<Key>URL</Key>\n\t\t\t\t\t<Value>https://example.com/$i</Value>\n\t\t\t\t</String>\n" +
                "\t\t\t\t<String>\n\t\t\t\t\t<Key>UserName</Key>\n\t\t\t\t\t<Value>user$i</Value>\n\t\t\t\t</String>\n" +
                binary +
                "\t\t\t\t<AutoType>\n\t\t\t\t\t<Enabled>True</Enabled>\n\t\t\t\t\t<DataTransferObfuscation>0</DataTransferObfuscation>\n" +
                "\t\t\t\t</AutoType>\n\t\t\t\t<History />\n\t\t\t</Entry>\n").toByteArray(),
        )
    }

    // An entry of 100 custom fields with one-character values and no whitespace between elements.
    private fun fieldsEntry(out: ByteArrayOutputStream, i: Int) {
        val fields = StringBuilder()
        for (k in 0 until 100) fields.append("<String><Key>$k</Key><Value>v</Value></String>")
        out.write("<Entry><UUID>${uuid(i + 1)}</UUID>$fields</Entry>\n".toByteArray())
    }

    private fun uuid(n: Int): String =
        Base64.getEncoder().encodeToString(ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN).putLong(0x4b61736850617373L).putLong(n.toLong()).array())

    // 2026-01-01T00:00:00Z as KDBX 4 writes a time: seconds since 0001-01-01, 8 bytes LE, Base64.
    private val TIME: String =
        Base64.getEncoder().encodeToString(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(63_902_822_400L).array())
}
