package org.onekash.kashpass

import java.security.MessageDigest
import javax.crypto.Cipher
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.testing.PrimitiveVectors
import org.robolectric.RobolectricTestRunner

/**
 * Runs the container primitives' published vectors on Conscrypt, the engine behind Android's
 * default crypto provider. vault-core is a pure JVM module whose own tests run on the desktop
 * JDK's provider; Robolectric installs Conscrypt as the first provider, and its tests run in the
 * default suite and in preflight. An instrumented test would need the emulator, which preflight
 * does not run; device runs check the platform provider itself.
 */
@RunWith(RobolectricTestRunner::class)
class ConscryptPrimitivesTest {

    @Test
    fun `AES-CBC, SHA-256 and SHA-512 come from Conscrypt`() {
        val providers = listOf(
            Cipher.getInstance("AES/CBC/NoPadding").provider.name,
            MessageDigest.getInstance("SHA-256").provider.name,
            MessageDigest.getInstance("SHA-512").provider.name,
        )
        assertEquals(listOf("Conscrypt", "Conscrypt", "Conscrypt"), providers)
    }

    @Test
    fun `every published vector and edge case passes on Conscrypt`() {
        assertEquals(emptyList<String>(), PrimitiveVectors.failures())
    }
}
