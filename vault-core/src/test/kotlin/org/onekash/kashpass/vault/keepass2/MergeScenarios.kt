package org.onekash.kashpass.vault.keepass2

import java.time.Instant
import org.onekash.kashpass.vault.doc.DocumentIds
import org.onekash.kashpass.vault.doc.EntryParts
import org.onekash.kashpass.vault.doc.Uuids
import org.onekash.kashpass.vault.fixtures.Fixtures
import org.onekash.kashpass.vault.fixtures.VaultFile
import org.onekash.kashpass.vault.xml.XmlElement

/**
 * The merge scenarios: a phone copy edited by KashPass at [Scenario.phoneAt] and a desktop copy
 * edited by KeePass 2 at [Scenario.desktopAt], from one base, merged by KeePass 2's synchronization
 * both ways. Each scenario carries a written expectation on every merged result, so a rule that
 * KashPass and the KeePass 2 reference share wrongly fails too. Entries and groups are found in
 * KeePass 2's export of the base by their hashed names.
 */
internal class MergeScenarios(private val hash: (String) -> String, private val earlier: Instant, private val later: Instant) {

    /**
     * One scenario on [base]. [premise] checks the base's export; [expect] lists what is wrong with
     * the result of one merge (a name from [KeePass2Run.MERGES]); [phoneSave] checks KashPass's own
     * reading of its phone copy, which KeePass 2 trims again when it loads it. Each returns an
     * empty list or null when it holds.
     */
    class Scenario(
        val name: String,
        val base: VaultFile,
        val phone: List<CompanionOp>,
        val desktop: List<CompanionOp>,
        val phoneAt: Instant,
        val desktopAt: Instant,
        val premise: (KeePassXml) -> String?,
        val expect: (merge: String, result: KeePassXml) -> List<String>,
        val phoneSave: ((VaultFile) -> String?)? = null,
    )

    private fun entry(x: KeePassXml, title: String): String = x.entryByTitle(hash(title)) ?: error("no entry $title")

    private fun group(x: KeePassXml, name: String): String =
        x.groups().entries.first { (_, g) -> g.child("Name")?.text()?.trim() == hash(name) }.key

    private fun title(e: XmlElement?) = KeePassXml.field(e, "Title")

    private fun check(ok: Boolean, what: String) = if (ok) emptyList() else listOf(what)

    private fun deleted(x: KeePassXml): Set<String> =
        x.root.child("Root")?.child("DeletedObjects")?.children("DeletedObject").orEmpty().map { it.child("UUID")!!.text().trim() }.toSet()

    private fun inHistory(x: KeePassXml, uuid: String, titleHash: String) = KeePassXml.history(x.entries().getValue(uuid)).any { title(it) == titleHash }

    // Whether the merge target is the desktop copy: the phone copy is then the source.
    private fun desktopIsTarget(merge: String) = merge.startsWith("D-")

    /**
     * Returns the scenarios on a sample-content [base]: "Example Mail" with history, "Example
     * Bank", group "Email".
     */
    fun sample(base: VaultFile, baseXml: KeePassXml, tag: String): List<Scenario> {
        val e1 = entry(baseXml, "Example Mail")
        val e2 = entry(baseXml, "Example Bank")
        val g = group(baseXml, "Email")
        val h = hash
        val present: (KeePassXml) -> String? = { x -> if (x.entries()[e1] == null || x.entries()[e2] == null) "an entry is missing" else null }
        fun s(
            n: String,
            phone: List<CompanionOp>,
            desktop: List<CompanionOp>,
            phoneAt: Instant,
            desktopAt: Instant,
            premise: (KeePassXml) -> String? = present,
            expect: (String, KeePassXml) -> List<String>,
        ) = Scenario("$n $tag", base, phone, desktop, phoneAt, desktopAt, premise, expect)
        return listOf(
            s("phone edits E1, desktop edits E2", listOf(CompanionOp.Edit(e1, "Title", "phone")), listOf(CompanionOp.Edit(e2, "Title", "desktop")), later, earlier) { _, x ->
                // KeePass 2 merges history by LastModificationTime, so items sharing one time
                // become one; each edited entry keeps its base version.
                check(title(x.entries()[e1]) == h("phone"), "E1 lost the phone edit") +
                    check(title(x.entries()[e2]) == h("desktop"), "E2 lost the desktop edit") +
                    check(inHistory(x, e1, h("Example Mail")), "E1's base version is not in its history") +
                    check(inHistory(x, e2, h("Example Bank")), "E2's base version is not in its history")
            },
            s("both edit E1, phone later", listOf(CompanionOp.Edit(e1, "Title", "phone")), listOf(CompanionOp.Edit(e1, "Title", "desktop")), later, earlier) { _, x ->
                check(title(x.entries()[e1]) == h("phone"), "E1 is not the phone version") +
                    check(inHistory(x, e1, h("desktop")), "the desktop version is not in E1's history")
            },
            s("both edit E1, desktop later", listOf(CompanionOp.Edit(e1, "Title", "phone")), listOf(CompanionOp.Edit(e1, "Title", "desktop")), earlier, later) { _, x ->
                check(title(x.entries()[e1]) == h("desktop"), "E1 is not the desktop version") +
                    check(inHistory(x, e1, h("phone")), "the phone version is not in E1's history")
            },
            s("phone moves E1 to the bin", listOf(CompanionOp.Delete(e1)), emptyList(), later, earlier) { _, x ->
                check(x.bin() != null && x.entries()[e1]?.parent === x.bin(), "E1 is not in the bin")
            },
            s("phone moves E1 to the bin, desktop edits E1 later", listOf(CompanionOp.Delete(e1)), listOf(CompanionOp.Edit(e1, "Title", "desktop")), earlier, later) { _, x ->
                check(x.bin() != null && x.entries()[e1]?.parent === x.bin(), "E1 is not in the bin") +
                    check(title(x.entries()[e1]) == h("desktop"), "E1 lost the desktop edit")
            },
            s("phone deletes E1 permanently", listOf(CompanionOp.Delete(e1), CompanionOp.Delete(e1)), emptyList(), later, earlier) { _, x ->
                check(x.entries()[e1] == null, "E1 is still there") + check(e1 in deleted(x), "no deletion record for E1")
            },
            s("phone deletes E1 permanently, desktop edits E1 later", listOf(CompanionOp.Delete(e1), CompanionOp.Delete(e1)), listOf(CompanionOp.Edit(e1, "Title", "desktop")), earlier, later) { _, x ->
                check(title(x.entries()[e1]) == h("desktop"), "E1 is gone or lost the desktop edit") + check(e1 !in deleted(x), "the deletion record for E1 is kept")
            },
            s(
                "both add an entry to G",
                listOf(CompanionOp.Add(g, PHONE_ADD, "phone added", "p", "", "")),
                listOf(CompanionOp.Add(g, DESKTOP_ADD, "desktop added", "d", "", "")),
                later, earlier,
            ) { _, x ->
                check(x.entries()[PHONE_ADD]?.parent === x.groups()[g] && x.entries()[DESKTOP_ADD]?.parent === x.groups()[g], "both added entries are not in G")
            },
            s(
                "both delete with no bin yet", listOf(CompanionOp.Delete(e1)), listOf(CompanionOp.Delete(e2)), later, earlier,
                premise = { x ->
                    present(x) ?: when {
                        x.meta().child("RecycleBinEnabled")?.text()?.trim() != "True" -> "the bin is off"
                        x.bin() != null -> "the base has a bin"
                        else -> null
                    }
                },
            ) { _, x ->
                // Each side creates its own bin; the merge keeps the target's as the bin and the
                // other becomes a plain group.
                val bins = x.groups().values.filter { it.child("Name")?.text()?.trim() == h("Recycle Bin") }
                check(bins.size == 2, "${bins.size} groups named Recycle Bin, not 2") +
                    check(x.entries()[e1]?.parent in bins && x.entries()[e2]?.parent in bins, "E1 and E2 are not both in a group named Recycle Bin") +
                    check(x.bin() in bins, "RecycleBinUUID names no Recycle Bin group")
            },
            s("both edit E1 at the same time", listOf(CompanionOp.Edit(e1, "Title", "phone")), listOf(CompanionOp.Edit(e1, "Title", "desktop")), earlier, earlier) { merge, x ->
                // On equal times the source's version replaces the target's and neither is kept in
                // history.
                val (won, lost) = if (desktopIsTarget(merge)) "phone" to "desktop" else "desktop" to "phone"
                check(title(x.entries()[e1]) == h(won), "E1 is not the $won version") + check(!inHistory(x, e1, h(lost)), "the $lost version is in E1's history")
            },
            s("phone clock behind, phone edit earlier", listOf(CompanionOp.Edit(e1, "Title", "phone")), listOf(CompanionOp.Edit(e1, "Title", "desktop")), earlier.minusSeconds(86_400), earlier) { _, x ->
                check(title(x.entries()[e1]) == h("desktop"), "E1 is not the desktop version") +
                    check(inHistory(x, e1, h("phone")), "the phone version is not in E1's history")
            },
        )
    }

    /** Returns a phone edit past the history limit [max] while the desktop edits the same entry. */
    fun historyLimit(base: VaultFile, baseXml: KeePassXml, entryTitle: String, max: Int, tag: String): Scenario {
        val e = entry(baseXml, entryTitle)
        return Scenario(
            "phone edit pushes history past the limit, desktop edits the same entry $tag", base,
            listOf(CompanionOp.Edit(e, "Password", "phone-pass")), listOf(CompanionOp.Edit(e, "UserName", "desktop-user")), later, earlier,
            premise = { x ->
                val items = x.entries()[e]?.let { KeePassXml.history(it).size }
                if (items != max) "history $items, not $max" else null
            },
            expect = { _, x -> check(KeePassXml.field(x.entries()[e], "Password") == hash("phone-pass"), "the phone edit is not current") },
            phoneSave = { phone ->
                val document = CompanionRig.open(phone).document
                val items = DocumentIds.entries(document)[Uuids.parse(e).toString()]?.let { EntryParts.history(it).size }
                if (items != max) "KashPass's phone save has $items history items, not $max" else null
            },
        )
    }

    /** Returns the plugin custom data and KDBX 4.1 content scenarios on the plugin-data fixture. */
    fun pluginData(base: VaultFile, baseXml: KeePassXml): List<Scenario> {
        val three = entry(baseXml, "Three backups")
        val mail = entry(baseXml, "Example Mail")
        val bank = entry(baseXml, "Example Bank")
        val plain = entry(baseXml, "No password entry")
        val h = hash
        fun items(e: XmlElement?) = e?.child("CustomData")?.children("Item").orEmpty().map { it.child("Key")!!.text() }.toSet()
        val premise: (KeePassXml) -> String? = { x -> if ("PluginA_Entry" !in items(x.entries()[three])) "the custom data item is missing" else null }
        val keeps41: (KeePassXml) -> List<String> = { x ->
            check(KeePassXml.isKdbx41(x), "the result is no longer 4.1 content") +
                check(x.meta().child("CustomData")!!.children("Item").any { it.child("LastModificationTime") != null }, "timed Meta custom data is gone") +
                check(x.groups().values.any { it.child("Tags")?.text()?.trim() == h("money") }, "the group tag is gone") +
                check(x.meta().child("CustomIcons")!!.children("Icon").size == 2, "custom icons are gone")
        }
        return listOf(
            Scenario(
                "phone edits a plugin-data entry, desktop deletes its custom data item later", base,
                listOf(CompanionOp.Edit(three, "Password", "phone-pass")), listOf(CompanionOp.DeleteCustomData(three, "PluginA_Entry")), earlier, later, premise,
                { _, x ->
                    check("PluginA_Entry" !in items(x.entries()[three]), "the desktop's delete is lost") + check("PluginB_Flag" in items(x.entries()[three]), "the other item is gone") +
                        check(KeePassXml.history(x.entries().getValue(three)).any { KeePassXml.field(it, "Password") == h("phone-pass") }, "the phone version is not in history")
                },
            ),
            Scenario(
                "phone edits a plugin-data entry later, desktop deletes its custom data item", base,
                listOf(CompanionOp.Edit(three, "Password", "phone-pass")), listOf(CompanionOp.DeleteCustomData(three, "PluginA_Entry")), later, earlier, premise,
                { _, x ->
                    check(KeePassXml.field(x.entries()[three], "Password") == h("phone-pass"), "the phone edit is not current") +
                        check(items(x.entries()[three]) == setOf("PluginA_Entry", "PluginB_Flag"), "custom data of the current version is ${items(x.entries()[three])}")
                },
            ),
            Scenario(
                "4.1 content with tags, timed custom data and icons", base,
                listOf(CompanionOp.Edit(mail, "Title", "phone"), CompanionOp.Delete(bank)), listOf(CompanionOp.Edit(plain, "Title", "desktop")), later, earlier,
                { x -> if (!KeePassXml.isKdbx41(x)) "the base is not 4.1 content" else null },
                { _, x ->
                    keeps41(x) + check(title(x.entries()[mail]) == h("phone") && title(x.entries()[plain]) == h("desktop"), "an edit is lost") +
                        check(x.bin() != null && x.entries()[bank]?.parent === x.bin(), "Example Bank is not in the bin")
                },
            ),
        )
    }

    companion object {
        /**
         * UUIDs of the entries both sides add: the 16 bytes "COMPANION-PHONE1" and
         * "COMPANION-DESKT1".
         */
        const val PHONE_ADD = "Q09NUEFOSU9OLVBIT05FMQ=="
        const val DESKTOP_ADD = "Q09NUEFOSU9OLURFU0tUMQ=="

        /** The KDBX 4.0 and 4.1 bases of the sample-content scenarios. */
        val BASES = listOf("keepass2-default-aeskdf.kdbx" to "4.0", "keepass2-kdbx41-tags.kdbx" to "4.1")

        fun base(name: String): VaultFile = Fixtures.file(Fixtures.named(name))
    }
}
