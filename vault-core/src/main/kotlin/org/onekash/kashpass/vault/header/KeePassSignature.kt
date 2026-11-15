package org.onekash.kashpass.vault.header

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Tells a KeePass database from other files by its two signature words. */
object KeePassSignature {

    /** The bytes [matches] checks: two 32-bit signature words. */
    const val BYTES = 8

    private const val BASE = 0x9AA2D903.toInt()
    private const val KDBX = 0xB54BFB67.toInt()
    private const val KEEPASS_1 = 0xB54BFB65.toInt()
    private const val KDBX_PRE_RELEASE = 0xB54BFB66.toInt()

    /**
     * Returns true when [bytes] starts with the signature of a KeePass 1 database or a KDBX file,
     * pre-release included. Such a file is refused as a key file.
     */
    fun matches(bytes: ByteArray): Boolean {
        if (bytes.size < BYTES) return false
        val r = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        return r.getInt(0) == BASE && r.getInt(4) in setOf(KDBX, KEEPASS_1, KDBX_PRE_RELEASE)
    }
}
