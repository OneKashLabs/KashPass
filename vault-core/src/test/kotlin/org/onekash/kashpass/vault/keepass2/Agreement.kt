package org.onekash.kashpass.vault.keepass2

import org.onekash.kashpass.vault.fixtures.VaultFile

/** Compares KeePass 2's reading with KashPass's over one run and lists every difference. */
object Agreement {

    /**
     * Lists the problems of KeePass 2's reading against KashPass's own ([DocumentReport]) over
     * [files]: a file KeePass 2 refuses, or a report that differs. Empty when they agree.
     */
    fun owned(files: List<VaultFile>, kp2: Map<String, KeePass2Report>, key: ByteArray): String = files.mapNotNull { f ->
        val report = kp2.getValue(f.name)
        if (report !is KeePass2Report.Opened) return@mapNotNull "${f.name}: KeePass 2 refused it: $report"
        KeePass2Report.diff(report, DocumentReport.of(f, key)).takeIf { it.isNotEmpty() }?.let { "${f.name}: KashPass differs:\n  " + it.joinToString("\n  ") }
    }.joinToString("\n")
}
