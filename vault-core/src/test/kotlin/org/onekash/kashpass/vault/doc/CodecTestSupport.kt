package org.onekash.kashpass.vault.doc

import org.onekash.kashpass.vault.kdbx.SaveSettings

/**
 * Opens [bytes] as the app does, reading its header first, with [derive] deriving the key:
 * the test form of the opener's two steps.
 */
internal fun VaultXmlCodec.decode(bytes: ByteArray, credentials: VaultKey, limits: VaultXmlCodec.Limits, derive: KeyDerivation = KdfEngine()): Decoded {
    val header = when (val read = header(bytes, org.onekash.kashpass.vault.kdbx.KdbxHeaderReader.NO_HEAP_LIMIT)) {
        is HeaderRead.Valid -> read.header
        is HeaderRead.Invalid -> return read.result
    }
    val budget = VaultXmlCodec.Budget(limits, Int.MAX_VALUE, Runtime.getRuntime().maxMemory())
    return decode(bytes, header, credentials, budget, derive = derive::derive)
}

/**
 * Returns the document [VaultXmlCodec.decode] opens from [bytes], failing the test with the
 * outcome when it does not open.
 */
internal fun VaultXmlCodec.open(bytes: ByteArray, credentials: VaultKey, limits: VaultXmlCodec.Limits, derive: KeyDerivation = KdfEngine()): VaultDocument =
    when (val d = decode(bytes, credentials, limits, derive)) {
        is Decoded.Opened -> d.document
        else -> throw AssertionError("did not open: $d")
    }

/** Returns the file [VaultXmlCodec.encode] writes for [document], failing the test otherwise. */
internal fun VaultXmlCodec.encodeBytes(document: VaultDocument, derive: KeyDerivation = KdfEngine()): ByteArray =
    when (val e = encode(document, derive = derive)) {
        is Encoded.Bytes -> e.bytes
        else -> throw AssertionError("did not encode: $e")
    }

/**
 * Returns [this] document with the KDF [kdf] in its save settings, as a header with no KDF
 * dictionary of its own gives it ([SaveSettings.from]); the public custom data is dropped.
 */
internal fun VaultDocument.withKdf(kdf: org.onekash.kashpass.vault.kdbx.KdfParameters): VaultDocument {
    val header = org.onekash.kashpass.vault.kdbx.EncoderRig.header(settings.cipher, settings.compression, kdf, settings.openedMinor)
    return VaultDocument(xml, SaveSettings.from(header), attachments, credentials, protectedValues, xmlBytes, saveability)
}
