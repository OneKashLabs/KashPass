package org.onekash.kashpass.platform

import android.hardware.biometrics.BiometricPrompt
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.storage.AesGcm
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.CryptoHandle
import org.onekash.kashpass.vault.storage.SealResult
import org.onekash.kashpass.vault.storage.SealedKey
import org.onekash.kashpass.vault.storage.StoredKeyState
import org.onekash.kashpass.vault.storage.UnlockAvailability
import org.onekash.kashpass.vault.storage.UnlockKeyStore
import org.onekash.kashpass.vault.storage.UnsealResult

/**
 * Seals one secret per vault location under its own AndroidKeyStore AES-256 key that a Class 3
 * biometric must authorize for every use: GCM, no padding, invalidated when a biometric is
 * enrolled, usable only while the phone is unlocked, in StrongBox when the phone has it (else the
 * TEE). The ciphertext lives in [dir] (app no_backup storage) as a [SealedKey]; nothing decrypted
 * touches disk.
 *
 * The Keystore is opened only when a call needs it, and a phone or test environment without the
 * provider reports [UnlockAvailability.UNAVAILABLE] instead of failing. A permanently
 * invalidated or missing key reads as [StoredKeyState.INVALIDATED], and a key the Keystore can't
 * load ([UnrecoverableKeyException]) as [StoredKeyState.UNRECOVERABLE]; any other failure (the
 * phone locked, the Keystore busy) leaves the stored key unchanged. Making a key (slow in
 * StrongBox) and reading or writing the file run on [io].
 */
class KeystoreUnlockKeyStore(
    private val dir: File,
    private val availability: () -> UnlockAvailability,
    private val strongBox: Boolean = false,
    private val keyStore: () -> KeyStore? = ::androidKeyStore,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) : UnlockKeyStore {

    private val store: KeyStore? by lazy { keyStore() }

    override fun availability(): UnlockAvailability = if (store == null) UnlockAvailability.UNAVAILABLE else availability.invoke()

    override fun state(location: String): StoredKeyState {
        val sealed = read(location) ?: return StoredKeyState.NONE
        val store = store ?: return StoredKeyState.NONE
        return try {
            val key = store.getKey(alias(location), null) as? SecretKey ?: return StoredKeyState.INVALIDATED
            decryptCipher(key, sealed)
            StoredKeyState.STORED
        } catch (e: KeyPermanentlyInvalidatedException) {
            StoredKeyState.INVALIDATED
        } catch (e: UnrecoverableKeyException) {
            // A subclass of GeneralSecurityException, so it is caught first.
            StoredKeyState.UNRECOVERABLE
        } catch (e: GeneralSecurityException) {
            StoredKeyState.STORED
        } catch (e: ProviderException) {
            StoredKeyState.STORED
        }
    }

    override suspend fun seal(location: String, secret: ByteArray, confirm: suspend (CryptoHandle) -> Confirmation): SealResult = try {
        val store = store ?: return SealResult.Failed
        val cipher = withContext(io) {
            // A fresh key on every seal replaces a key left by an interrupted turn-on.
            deleteKey(store, location)
            file(location).delete()
            try {
                Cipher.getInstance(AesGcm.TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, generateKey(location)) }
            } catch (e: GeneralSecurityException) {
                null
            } catch (e: ProviderException) {
                null
            }
        } ?: return SealResult.Failed
        when (val c = confirm(CryptoHandle(BiometricPrompt.CryptoObject(cipher)))) {
            Confirmation.Confirmed -> withContext(io) {
                try {
                    write(location, AesGcm.seal(cipher, secret, location).encode())
                    SealResult.Sealed
                } catch (e: GeneralSecurityException) {
                    deleteKey(store, location)
                    SealResult.Failed
                } catch (e: ProviderException) {
                    deleteKey(store, location)
                    SealResult.Failed
                } catch (e: IOException) {
                    deleteKey(store, location)
                    SealResult.Failed
                }
            }
            else -> {
                deleteKey(store, location)
                SealResult.NotConfirmed(c)
            }
        }
    } finally {
        secret.fill(0)
    }

    override suspend fun unseal(location: String, confirm: suspend (CryptoHandle) -> Confirmation): UnsealResult {
        val sealed = withContext(io) { read(location) } ?: return UnsealResult.Missing
        val store = store ?: return UnsealResult.Failed
        val cipher = try {
            val key = store.getKey(alias(location), null) as? SecretKey ?: return UnsealResult.Invalidated
            decryptCipher(key, sealed)
        } catch (e: KeyPermanentlyInvalidatedException) {
            return UnsealResult.Invalidated
        } catch (e: UnrecoverableKeyException) {
            return UnsealResult.Unrecoverable
        } catch (e: GeneralSecurityException) {
            return UnsealResult.Failed
        } catch (e: ProviderException) {
            return UnsealResult.Failed
        }
        return when (val c = confirm(CryptoHandle(BiometricPrompt.CryptoObject(cipher)))) {
            Confirmation.Confirmed -> try {
                AesGcm.open(cipher, sealed, location)?.let(UnsealResult::Unsealed) ?: UnsealResult.Damaged
            } catch (e: GeneralSecurityException) {
                UnsealResult.Failed
            } catch (e: ProviderException) {
                UnsealResult.Failed
            }
            else -> UnsealResult.NotConfirmed(c)
        }
    }

    override fun delete(location: String) {
        store?.let { deleteKey(it, location) }
        file(location).delete()
    }

    private fun generateKey(location: String): SecretKey {
        fun spec(strong: Boolean) = KeyGenParameterSpec.Builder(alias(location), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strong)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        if (strongBox) {
            try {
                generator.init(spec(true))
                return generator.generateKey()
            } catch (e: StrongBoxUnavailableException) {
                // Falls through to the TEE.
            } catch (e: ProviderException) {
                // Some StrongBox implementations refuse a spec at generation time.
            }
        }
        generator.init(spec(false))
        return generator.generateKey()
    }

    private fun decryptCipher(key: SecretKey, sealed: SealedKey): Cipher =
        Cipher.getInstance(AesGcm.TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(AesGcm.TAG_BITS, sealed.iv)) }

    private fun deleteKey(store: KeyStore, location: String) {
        try {
            store.deleteEntry(alias(location))
        } catch (e: GeneralSecurityException) {
            // A Keystore error leaves the key, unusable without the sealed file, which is deleted.
        }
    }

    private fun read(location: String): SealedKey? = try {
        file(location).takeIf { it.isFile }?.readBytes()?.let(SealedKey::decode)
    } catch (e: IOException) {
        null
    }

    // Written to a temporary file, synced and renamed, so a crash leaves the old file or none.
    private fun write(location: String, bytes: ByteArray) {
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("no folder")
        val target = file(location)
        val temp = File(dir, "${target.name}.tmp")
        FileOutputStream(temp).use {
            it.write(bytes)
            it.fd.sync()
        }
        if (!temp.renameTo(target)) {
            temp.delete()
            throw IOException("rename failed")
        }
    }

    private fun file(location: String) = File(dir, "${Sha256.ofLocation(location)}.bin")

    private fun alias(location: String) = "kashpass-unlock-${Sha256.ofLocation(location)}"

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"

        fun androidKeyStore(): KeyStore? = try {
            KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        } catch (e: GeneralSecurityException) {
            null
        } catch (e: IOException) {
            null
        }
    }
}
