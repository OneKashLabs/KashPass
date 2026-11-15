package org.onekash.kashpass.vault.doc

import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

/**
 * Edits, adds and deletes an entry in each KeePass 2 fixture, saving after each change as the app
 * does, and reopens the result ([InteropRoundTrip]). With -Pkashpass.interop.out=<dir> it also
 * writes the saved vaults there, for KeePass 2 itself to open.
 */
class KeePass2InteropTest {

    private val password = VaultXmlCodecTest.fixturePassword

    @ParameterizedTest
    @MethodSource("passwordFixtures")
    fun `KashPass edits, adds and deletes, and every change survives a reopen`(name: String) {
        InteropRoundTrip.run(name, password, keyFileName = null)
    }

    @ParameterizedTest
    @MethodSource("keyFileFixtures")
    fun `KashPass edits a key-file vault, and every change survives a reopen with the key file`(
        name: String,
        withPassword: Boolean,
        keyFileName: String,
    ) {
        InteropRoundTrip.run(name, if (withPassword) password else "", keyFileName)
    }

    companion object {
        @JvmStatic
        fun passwordFixtures(): List<String> = InteropRoundTrip.passwordFixtures

        @JvmStatic
        fun keyFileFixtures(): List<Arguments> = InteropRoundTrip.keyFileFixtures.map { Arguments.of(it.first, it.second, it.third) }
    }
}
