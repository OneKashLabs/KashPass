package org.onekash.kashpass.vault.index

import kotlinx.coroutines.runBlocking
import org.onekash.kashpass.vault.doc.VaultDocument
import org.onekash.kashpass.vault.testing.TestVaults
import org.onekash.kashpass.vault.testing.VaultModel

/**
 * Opens [bytes] (the test password) through the real opener into the document the index is built
 * from. The opener's limits come from a stated 8 GiB heap, so a large test vault of long notes
 * opens whatever heap the test JVM has.
 */
internal fun documentOf(bytes: ByteArray, password: String = TestVaults.PASSWORD): VaultDocument =
    runBlocking { TestVaults.unlock(bytes, password, maxHeapBytes = 8L shl 30) }.session.opened.document

/**
 * Builds the index of a vault the test describes with [VaultModel]: written with a one-round
 * AES-KDF, then opened through the real opener.
 */
internal fun VaultIndex.Companion.from(doc: VaultModel.Doc): VaultIndex = from(documentOf(VaultModel.write(doc, aesRounds = 1UL)))
