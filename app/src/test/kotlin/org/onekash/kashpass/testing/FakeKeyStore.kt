package org.onekash.kashpass.testing

/**
 * Returns a stand-in key store holding [keys] by alias, to reach the key-store checks Robolectric
 * can't (it has no AndroidKeyStore). When [failure] is set, every key load throws it.
 */
fun fakeKeyStore(keys: Map<String, java.security.Key>, failure: Exception? = null): java.security.KeyStore {
    val spi = object : java.security.KeyStoreSpi() {
        override fun engineGetKey(alias: String, password: CharArray?): java.security.Key? {
            if (failure != null) throw failure
            return keys[alias]
        }
        override fun engineGetCertificateChain(alias: String?) = null
        override fun engineGetCertificate(alias: String?) = null
        override fun engineGetCreationDate(alias: String?) = null
        override fun engineSetKeyEntry(alias: String?, key: java.security.Key?, password: CharArray?, chain: Array<out java.security.cert.Certificate>?) = Unit
        override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out java.security.cert.Certificate>?) = Unit
        override fun engineSetCertificateEntry(alias: String?, cert: java.security.cert.Certificate?) = Unit
        override fun engineDeleteEntry(alias: String?) = Unit
        override fun engineAliases() = java.util.Collections.enumeration(keys.keys)
        override fun engineContainsAlias(alias: String?) = alias in keys
        override fun engineSize() = keys.size
        override fun engineIsKeyEntry(alias: String?) = alias in keys
        override fun engineIsCertificateEntry(alias: String?) = false
        override fun engineGetCertificateAlias(cert: java.security.cert.Certificate?) = null
        override fun engineStore(stream: java.io.OutputStream?, password: CharArray?) = Unit
        override fun engineLoad(stream: java.io.InputStream?, password: CharArray?) = Unit
    }
    return object : java.security.KeyStore(spi, null, "fake") {}.apply { load(null) }
}
