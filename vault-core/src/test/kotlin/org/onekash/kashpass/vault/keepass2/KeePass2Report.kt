package org.onekash.kashpass.vault.keepass2

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * One reader's report of one vault file, in the canonical text form that KeePass 2's report mode
 * writes and [DocumentReport] builds: format version, cipher, KDF, compression, database name, the
 * group tree in document order, and per entry its fields and attachments as HMAC-SHA-256 under a
 * per-run key, never as values.
 */
sealed interface KeePass2Report {

    /** The reader opened the file. [lines] is the report as written, one item per line. */
    data class Opened(val lines: List<String>) : KeePass2Report {
        /**
         * Returns the value of the header line starting with [key], such as `version` or `cipher`.
         */
        fun header(key: String): String? = lines.firstOrNull { it.startsWith("$key ") }?.substringAfter(' ')

        /**
         * Returns the tokens the reader leaves out, from its `capabilities` line: `no-group-tags`
         * (group lines without their tags token) and `no-quality-check` (entry lines without
         * theirs), written by a KeePass 2 version without KDBX 4.1. Empty for every other reader.
         */
        fun capabilities(): Set<String> =
            header("capabilities")?.split(',')?.filter { it.isNotEmpty() }?.toSet().orEmpty()

        /** Returns each entry's group path (names, escaped) and the HMAC of its Title field. */
        fun entryPaths(): List<EntryPath> = walk().filterIsInstance<Item.Entry>().map { EntryPath(it.groups, it.titleMac) }

        // One pass over the group tree in document order; entries are listed after their group.
        internal fun walk(): List<Item> {
            val groups = ArrayList<String>()
            val result = mutableListOf<Item>()
            var inHistory = false
            for (line in lines) {
                val parts = line.split(' ')
                when (parts[0]) {
                    "group" -> {
                        val depth = parts[1].toInt()
                        while (groups.size > depth) groups.removeAt(groups.size - 1)
                        groups += parts[2]
                        inHistory = false
                        result += Item.Group(groups.toList(), line)
                    }
                    "entry" -> {
                        inHistory = false
                        result += Item.Entry(groups.toList(), parts[2], null)
                    }
                    "history" -> inHistory = true
                    "field" -> if (!inHistory && parts[1] == "Title") {
                        val at = result.indexOfLast { it is Item.Entry }
                        result[at] = (result[at] as Item.Entry).copy(titleMac = parts[3])
                    }
                }
            }
            return result
        }
    }

    /** A group or an entry of the tree, with the group path it sits in. */
    sealed interface Item {
        data class Group(val path: List<String>, val line: String) : Item
        data class Entry(val groups: List<String>, val uuid: String, val titleMac: String?) : Item
    }

    /** The reader refused the file; [reason] is its error, for the log only. */
    data class Refused(val reason: String) : KeePass2Report

    /** An entry's group names from the root down and the HMAC of its title, null without one. */
    data class EntryPath(val groups: List<String>, val titleMac: String?)

    companion object {
        /** Parses a report as KeePass 2's report mode writes it. */
        fun parse(text: String): KeePass2Report {
            val lines = text.lines().filter { it.isNotEmpty() }
            val first = lines.firstOrNull() ?: return Refused("empty report")
            return if (first.startsWith("REFUSE ")) Refused(first.removePrefix("REFUSE ")) else Opened(lines)
        }

        /**
         * Lists the differences between [expected] and [actual], one line each, empty when they are
         * equal: the header lines, the groups and entries in document order with their group paths,
         * and each entry's lines keyed by its group path and UUID.
         */
        fun diff(expected: KeePass2Report, actual: KeePass2Report): List<String> = diff(expected, actual, contentOnly = false)

        /**
         * Lists the differences in content only: as [diff], without the format version, cipher, KDF
         * and compression lines, so a re-encrypted or re-keyed copy compares equal to its original.
         */
        fun contentDiff(expected: KeePass2Report, actual: KeePass2Report): List<String> = diff(expected, actual, contentOnly = true)

        private val CONTAINER_LINES = listOf("version ", "cipher ", "kdf ", "compression ")

        private fun diff(expected: KeePass2Report, actual: KeePass2Report, contentOnly: Boolean): List<String> {
            if (expected is Refused || actual is Refused) {
                return if (expected::class == actual::class) emptyList() else listOf("expected $expected, got $actual")
            }
            // Each side drops the tokens either reader leaves out, and the capabilities line.
            val unseen = (expected as Opened).capabilities() + (actual as Opened).capabilities()
            val a = sections(masked(expected, unseen), contentOnly)
            val b = sections(masked(actual, unseen), contentOnly)
            val out = mutableListOf<String>()
            for (key in (a.keys + b.keys).distinct()) {
                val left = a[key]
                val right = b[key]
                when {
                    left == null -> out += "$key: only in actual"
                    right == null -> out += "$key: only in expected"
                    left != right -> {
                        for (line in left - right.toSet()) out += "$key: expected $line"
                        for (line in right - left.toSet()) out += "$key: actual $line"
                        if (left.toSet() == right.toSet()) out += "$key: same lines, different order"
                    }
                }
            }
            return out
        }

        private fun masked(report: Opened, unseen: Set<String>): Opened {
            if (unseen.isEmpty()) return report
            return Opened(report.lines.filterNot { it.startsWith("capabilities ") }.map { line ->
                when {
                    NO_GROUP_TAGS in unseen && line.startsWith("group ") -> line.replace(GROUP_TAGS, "")
                    NO_QUALITY_CHECK in unseen && line.startsWith("entry ") -> line.replace(QUALITY_CHECK, "")
                    else -> line
                }
            })
        }

        /** A [Opened.capabilities] token: group lines carry no tags token. */
        const val NO_GROUP_TAGS = "no-group-tags"

        /** A [Opened.capabilities] token: entry lines carry no qualityCheck token. */
        const val NO_QUALITY_CHECK = "no-quality-check"

        private val GROUP_TAGS = Regex(" tags=\\S*")
        private val QUALITY_CHECK = Regex(" qualityCheck=\\S+")

        // Splits the report into the header, the tree order and one section per entry keyed by its
        // group path and UUID, so a moved entry differs and a difference names the entry.
        private fun sections(report: Opened, contentOnly: Boolean): Map<String, List<String>> {
            val result = LinkedHashMap<String, MutableList<String>>()
            result["header"] = report.lines.takeWhile { !it.startsWith("group ") }
                .filterNot { line -> contentOnly && CONTAINER_LINES.any { line.startsWith(it) } }.toMutableList()
            val tree = report.walk()
            result["tree"] = tree.map { item ->
                when (item) {
                    is Item.Group -> "group " + item.path.joinToString("/") +
                        (if (" tags=" in item.line) " tags=" + item.line.substringAfter(" tags=") else "")
                    is Item.Entry -> "entry " + item.groups.joinToString("/") + " " + item.uuid
                }
            }.toMutableList()
            val entryKeys = tree.filterIsInstance<Item.Entry>().map { "entry " + it.groups.joinToString("/") + " " + it.uuid }.iterator()
            var key: String? = null
            for (line in report.lines.dropWhile { !it.startsWith("group ") }) {
                when {
                    line.startsWith("group ") -> key = null
                    line.startsWith("entry ") -> key = entryKeys.next()
                }
                key?.let { result.getOrPut(it) { mutableListOf() } += line }
            }
            return result
        }

        /**
         * Percent-encodes every UTF-8 byte outside 0x21-0x7E and '%', as KeePass 2's report mode
         * does.
         */
        fun escape(s: String): String {
            if (s.isEmpty()) return "%"
            val sb = StringBuilder()
            for (b in s.toByteArray(Charsets.UTF_8)) {
                val v = b.toInt() and 0xFF
                if (v in 0x21..0x7E && v != '%'.code) sb.append(v.toChar()) else sb.append('%').append("%02X".format(v))
            }
            return sb.toString()
        }

        /** Returns the HMAC-SHA-256 of [data] under [key] in lowercase hex. */
        fun mac(key: ByteArray, data: ByteArray): String =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data).toHex()

        /** Returns the lowercase hex of the bytes. */
        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    }
}
