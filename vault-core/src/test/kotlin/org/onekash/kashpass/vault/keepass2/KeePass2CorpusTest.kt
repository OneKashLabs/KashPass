package org.onekash.kashpass.vault.keepass2

import kotlin.test.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import org.onekash.kashpass.vault.corpus.Corpus
import org.onekash.kashpass.vault.corpus.Seen
import org.onekash.kashpass.vault.corpus.Spec

/**
 * KeePass 2 gives every corpus case its recorded outcome, refuses with its key error exactly
 * the wrong-key cases it refuses, and reports for each case it opens the content of the case's
 * base. Runs with -Pkashpass.keepass2 only.
 */
@EnabledIfSystemProperty(named = KeePass2Run.PROPERTY, matches = "true")
class KeePass2CorpusTest {

    @Test
    fun `KeePass 2 gives every corpus case its recorded outcome`() {
        val cases = Corpus.all
        val files = cases.map { it.file() }
        val kp2 = KeePass2Run.keepass2(files, KeePass2Run.newKey())
        val problems = mutableListOf<String>()
        for ((case, file) in cases.zip(files)) {
            val k = kp2.getValue(file.name)
            val kSeen = if (k is KeePass2Report.Opened) Seen.OPEN else Seen.REFUSE
            if (kSeen != case.keepass2) problems += "${case.name}: recorded KeePass 2 ${case.keepass2}, it gives $kSeen ${(k as? KeePass2Report.Refused)?.reason.orEmpty()}"
            // A refusal for a wrong key must be KeePass 2's key error, and only there.
            val keyError = (k as? KeePass2Report.Refused)?.reason?.startsWith("InvalidCompositeKeyException") == true
            if (keyError != (case.spec == Spec.WRONG_KEY && kSeen == Seen.REFUSE)) problems += "${case.name}: KeePass 2 refusal ${(k as? KeePass2Report.Refused)?.reason} does not fit spec ${case.spec}"
            // KeePass 2 opening a file checks no protected value, so its content is compared with
            // the base case.
            val base = case.sameContentAs?.let { kp2.getValue("$it.kdbx") }
            if (k is KeePass2Report.Opened && base != null) {
                val drift = KeePass2Report.contentDiff(base, k)
                if (drift.isNotEmpty()) problems += "${case.name}: KeePass 2 content differs from ${case.sameContentAs}:\n  " + drift.joinToString("\n  ")
            }
        }
        if (problems.isNotEmpty()) fail("${problems.size} problems:\n" + problems.joinToString("\n"))
    }
}
