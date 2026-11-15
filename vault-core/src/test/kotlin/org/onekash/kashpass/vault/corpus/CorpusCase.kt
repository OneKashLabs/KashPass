package org.onekash.kashpass.vault.corpus

import org.onekash.kashpass.vault.fixtures.CredentialMode
import org.onekash.kashpass.vault.fixtures.VaultFile

/** Whether an external reader opened a file. */
enum class Seen { OPEN, REFUSE }

/**
 * The outcome KashPass's decoder must give for a case. Every case KeePass 2 opens is
 * [OPENS] or [OPENS_READ_ONLY] unless it is [REFUSED_BY_POLICY] or [NOT_ENOUGH_MEMORY], and every
 * case KeePass 2 refuses is refused; [CorpusTest] checks this.
 */
enum class Spec {
    OPENS,
    OPENS_READ_ONLY,
    WRONG_KEY,
    DAMAGED,
    UNSUPPORTED,
    NOT_ENOUGH_MEMORY,

    /**
     * Refused by a rule of an approved exception (such as `KdfPolicy` for exception 1),
     * whether or not KeePass 2 refuses the file too; the case names the exception
     * ([CorpusCase.policyException]). A shape KeePass 2 refuses that no such rule checks is
     * [WRONG_KEY], [DAMAGED] or [UNSUPPORTED].
     */
    REFUSED_BY_POLICY,
}

/**
 * One corrupted or unusual file with what KeePass 2 does with it ([keepass2]) and what
 * KashPass's decoder must do ([spec]). [sameContentAs] names the case whose content KeePass 2 must
 * report for this one when it opens it (null when the case changes content on purpose).
 * [policyException] is the number of the approved exception a [Spec.REFUSED_BY_POLICY] case
 * falls under (1 KDF bounds, 2 downgrade, 3 KDBX 3, 4 device memory).
 */
class CorpusCase(
    val name: String,
    val keepass2: Seen,
    val spec: Spec,
    val sameContentAs: String? = null,
    val policyException: Int? = null,
    val mode: CredentialMode = CredentialMode.PASSWORD,
    val keyFileName: String? = null,
    val keyFile: ByteArray? = null,
    /**
     * KeePass 2's outcome on Windows where it differs from the [keepass2] column (KeePass 2 under
     * Mono), with [windowsReason]; the spec follows Windows.
     */
    val windows: Seen? = null,
    val windowsReason: String? = null,
    /** The damage layer (a KdbxDamage name) the decoder reports for a [Spec.DAMAGED] case. */
    val damage: String? = null,
    /**
     * The heap KashPass's decoder computes its memory limits for, for a case sized against a small
     * heap; null for the corpus default ([org.onekash.kashpass.vault.doc.ContainerRig.HEAP]).
     */
    val heapBytes: Long? = null,
    private val make: () -> ByteArray,
) {
    /** KeePass 2's outcome the spec follows: on Windows where known, else under Mono. */
    val reference: Seen get() = windows ?: keepass2

    /** The file's bytes, built once. */
    val bytes: ByteArray by lazy(make)

    /** The case as a file for KeePass 2. */
    fun file(): VaultFile = VaultFile("$name.kdbx", bytes, mode, keyFileName, keyFile)

    override fun toString() = name
}
