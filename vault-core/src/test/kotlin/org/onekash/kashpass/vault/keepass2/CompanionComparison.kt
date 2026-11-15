package org.onekash.kashpass.vault.keepass2

import java.time.Instant

/**
 * Compares KashPass's save of a set of actions with KeePass 2's replay of the same actions on the
 * same input, both as KeePass 2 exports them, with each side's action times normalised to its own
 * window.
 */
internal object CompanionComparison {

    /**
     * The differences beyond the listed new-object expiry ([diff]), the expiry lines themselves
     * ([expiry]), and a problem for each expiry line not in its listed form ([problems]).
     */
    class Result(val diff: List<String>, val expiry: List<String>, val problems: List<String>)

    /**
     * Compares [ours] (KashPass's save, its actions in [oursWindow]) with [theirs] over [input],
     * the export of the file both started from; [hashEmpty] is the run's hash of "".
     */
    fun compare(input: KeePassXml, ours: KeePassXml, oursWindow: KeePassXml.Window, theirs: KeePass2Run.Replayed, hashEmpty: String): Result {
        val all = KeePassXml.diff(ours.flat(KeePassXml.Normal(input, oursWindow, hashEmpty)), theirs.xml.flat(KeePassXml.Normal(input, theirs.window, hashEmpty)))
        val (expiry, diff) = all.partition(NEW_OBJECT_EXPIRY::containsMatchIn)
        // KashPass writes the action time; KeePass 2 a time before its run, when it started.
        val problems = expiry.mapNotNull { line ->
            val kp = LISTED_EXPIRY.find(line)?.groupValues?.get(1)?.let(Instant::parse)
            if (kp == null || kp >= theirs.window.start) "the expiry time difference is not in its listed form: $line" else null
        }
        return Result(diff, expiry, problems)
    }

    /**
     * A listed difference in every case: a new entry or a new recycle bin gets ExpiryTime = the
     * time of the action from KashPass, and the time KeePass 2 started from KeePass 2, and so does
     * each history copy an edit of the new entry makes. Expires is False on both, so neither app
     * reads the value.
     */
    val NEW_OBJECT_EXPIRY = Regex("""/(Entry|Group)\{NEW\d+}(/History/Entry#\d+)?/Times/ExpiryTime: """)

    // The listed form: KashPass's time in its run, KeePass 2's a literal time.
    private val LISTED_EXPIRY = Regex("""/Times/ExpiryTime: NOW \| (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)$""")
}
