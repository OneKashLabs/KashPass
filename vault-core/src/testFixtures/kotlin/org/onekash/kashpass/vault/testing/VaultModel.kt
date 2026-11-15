package org.onekash.kashpass.vault.testing

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * A vault's content for tests, written as KDBX XML with the Meta defaults a new database gets and
 * encoded by [KdbxToolkit.newVault]. A group lists its subgroups before its
 * entries.
 */
object VaultModel {

    /**
     * A String value: [Plain] text, or [Protected] (Protected="True", encrypted by the inner
     * stream).
     */
    sealed interface Value {
        val text: String

        data class Plain(override val text: String) : Value

        data class Protected(override val text: String) : Value
    }

    /**
     * An entry's times as a KDBX file stores them; a null time is written empty, which reads as
     * 0001-01-01.
     */
    data class Times(
        val created: Instant?,
        val lastAccess: Instant?,
        val modified: Instant?,
        val locationChanged: Instant?,
        val expiry: Instant?,
        val expires: Boolean = false,
    ) {
        companion object {
            /** Every time [now], not expiring. */
            fun at(now: Instant) = Times(now, now, now, now, now)
        }
    }

    /**
     * One entry: its String fields in order, [tags], [history] entries, attachments as names with
     * the index of the inner-header attachment they name, and [times] (null writes no Times
     * element).
     */
    data class Entry(
        val fields: List<Pair<String, Value>>,
        val tags: List<String> = emptyList(),
        val history: List<Entry> = emptyList(),
        val binaries: List<Pair<String, Int>> = emptyList(),
        val times: Times? = Times.at(Instant.now()),
        val uuid: UUID = UUID.randomUUID(),
    )

    /**
     * One group with its entries, subgroups and [tags] (a KDBX 4.1 element written after
     * LastTopVisibleEntry; a KashPass save of a group with tags is 4.1).
     */
    data class Group(
        val name: String,
        val entries: List<Entry> = emptyList(),
        val groups: List<Group> = emptyList(),
        val uuid: UUID = UUID.randomUUID(),
        val tags: List<String> = emptyList(),
    )

    /**
     * A vault: the root group, the recycle bin group's UUID, the inner-header attachments, and the
     * Meta settings for history and the recycle bin (defaults: a new database's values, and
     * the bin enabled when [recycleBin] is set).
     */
    data class Doc(
        val root: Group,
        val recycleBin: UUID? = null,
        val attachments: List<ByteArray> = emptyList(),
        val historyMaxItems: Int = 10,
        val historyMaxSize: Long = 6_291_456,
        val recycleBinEnabled: Boolean = recycleBin != null,
    )

    /**
     * Returns [doc] as a KDBX 4.0 vault: AES-256, gzip, AES-KDF at [aesRounds], the composite key
     * of [password] and [keyPart], and [innerStream] for protected values.
     */
    fun write(
        doc: Doc,
        aesRounds: ULong = 1_000UL,
        password: String? = TestVaults.PASSWORD,
        keyPart: ByteArray? = null,
        innerStream: Int = KdbxToolkit.CHACHA20,
    ): ByteArray {
        check(password != null || keyPart != null) { "a vault needs a password or a key" }
        val out = XmlOut(doc).write()
        return KdbxToolkit.newVault(
            out.text.toString().toByteArray(Charsets.UTF_8), out.protectedValues, KdbxToolkit.Key(password, keyPart),
            KdbxToolkit.Kdf.Aes(aesRounds, null), attachments = doc.attachments.map { false to it }, innerStream = innerStream,
        )
    }

    // Writes [doc] as KDBX XML, collecting each protected value's plaintext in document order.
    private class XmlOut(val doc: Doc) {
        val text = StringBuilder()
        val protectedValues = mutableListOf<ByteArray>()
        private val nowInstant = Instant.now()
        private val now = time(nowInstant)
        private val groupTimes = Times.at(nowInstant)
        private val zero = uuid(UUID(0, 0))

        fun write(): XmlOut {
            text.append("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><KeePassFile><Meta><Generator>VaultModel</Generator>")
            text.append("<SettingsChanged>$now</SettingsChanged><DatabaseName/><DatabaseNameChanged>$now</DatabaseNameChanged>")
            text.append("<DatabaseDescription/><DatabaseDescriptionChanged>$now</DatabaseDescriptionChanged><DefaultUserName/>")
            text.append("<DefaultUserNameChanged>$now</DefaultUserNameChanged><MaintenanceHistoryDays>365</MaintenanceHistoryDays><Color/>")
            text.append("<MasterKeyChanged>$now</MasterKeyChanged><MasterKeyChangeRec>-1</MasterKeyChangeRec><MasterKeyChangeForce>-1</MasterKeyChangeForce>")
            text.append("<MemoryProtection><ProtectTitle>False</ProtectTitle><ProtectUserName>False</ProtectUserName><ProtectPassword>True</ProtectPassword>")
            text.append("<ProtectURL>False</ProtectURL><ProtectNotes>False</ProtectNotes></MemoryProtection><CustomIcons/>")
            text.append("<RecycleBinEnabled>${if (doc.recycleBinEnabled) "True" else "False"}</RecycleBinEnabled>")
            text.append("<RecycleBinUUID>${uuid(doc.recycleBin ?: UUID(0, 0))}</RecycleBinUUID><RecycleBinChanged>$now</RecycleBinChanged>")
            text.append("<EntryTemplatesGroup>$zero</EntryTemplatesGroup><EntryTemplatesGroupChanged>$now</EntryTemplatesGroupChanged>")
            text.append("<HistoryMaxItems>${doc.historyMaxItems}</HistoryMaxItems><HistoryMaxSize>${doc.historyMaxSize}</HistoryMaxSize><CustomData/></Meta><Root>")
            group(doc.root, isRoot = true)
            text.append("<DeletedObjects/></Root></KeePassFile>")
            return this
        }

        private fun group(g: Group, isRoot: Boolean) {
            text.append("<Group><UUID>${uuid(g.uuid)}</UUID><Name>${escape(g.name)}</Name><Notes/><IconID>48</IconID>")
            times(groupTimes)
            val inherited = if (isRoot) "True" else "Null"
            text.append("<IsExpanded>True</IsExpanded><DefaultAutoTypeSequence/><EnableAutoType>$inherited</EnableAutoType>")
            text.append("<EnableSearching>$inherited</EnableSearching><LastTopVisibleEntry>$zero</LastTopVisibleEntry>")
            if (g.tags.isNotEmpty()) text.append("<Tags>${escape(g.tags.joinToString(";"))}</Tags>")
            for (sub in g.groups) group(sub, isRoot = false)
            for (e in g.entries) entry(e)
            text.append("</Group>")
        }

        private fun entry(e: Entry) {
            text.append("<Entry><UUID>${uuid(e.uuid)}</UUID><IconID>0</IconID><ForegroundColor/><BackgroundColor/><OverrideURL/>")
            text.append(if (e.tags.isEmpty()) "<Tags/>" else "<Tags>${escape(e.tags.joinToString(";"))}</Tags>")
            e.times?.let { times(it) }
            for ((key, value) in e.fields) {
                text.append("<String><Key>${escape(key)}</Key>")
                when (value) {
                    is Value.Protected -> {
                        text.append("<Value Protected=\"True\"></Value>")
                        protectedValues += value.text.toByteArray(Charsets.UTF_8)
                    }
                    is Value.Plain -> text.append(if (value.text.isEmpty()) "<Value/>" else "<Value>${escape(value.text)}</Value>")
                }
                text.append("</String>")
            }
            for ((name, ref) in e.binaries) text.append("<Binary><Key>${escape(name)}</Key><Value Ref=\"$ref\"/></Binary>")
            text.append("<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation></AutoType>")
            if (e.history.isNotEmpty()) {
                text.append("<History>")
                for (h in e.history) entry(h)
                text.append("</History>")
            }
            text.append("</Entry>")
        }

        private fun times(t: Times) {
            text.append("<Times><CreationTime>${time(t.created)}</CreationTime><LastModificationTime>${time(t.modified)}</LastModificationTime>")
            text.append("<LastAccessTime>${time(t.lastAccess)}</LastAccessTime><ExpiryTime>${time(t.expiry)}</ExpiryTime>")
            text.append("<Expires>${if (t.expires) "True" else "False"}</Expires><UsageCount>0</UsageCount>")
            text.append("<LocationChanged>${time(t.locationChanged)}</LocationChanged></Times>")
        }

        private fun escape(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

        private fun uuid(u: UUID): String =
            Base64.getEncoder().encodeToString(ByteBuffer.allocate(16).putLong(u.mostSignificantBits).putLong(u.leastSignificantBits).array())

        // KDBX 4 time: seconds since 0001-01-01 UTC as a little-endian Int64, in Base64.
        private fun time(t: Instant?): String = t?.let {
            Base64.getEncoder().encodeToString(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(it.epochSecond + SECONDS_TO_1970).array())
        }.orEmpty()

        private companion object {
            const val SECONDS_TO_1970 = 62_135_596_800L
        }
    }
}
