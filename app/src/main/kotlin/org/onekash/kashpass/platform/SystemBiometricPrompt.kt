package org.onekash.kashpass.platform

import android.content.Context
import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.CryptoHandle

/** What the system prompt shows; [negative] is the button that leaves it. */
data class PromptTexts(val title: String, val subtitle: String, val negative: String)

/** Shows one system prompt and reports its outcome once; the seam tests replace. */
fun interface PromptShow {
    fun show(texts: PromptTexts, crypto: Any, signal: CancellationSignal, onResult: (Confirmation) -> Unit)
}

/**
 * Shows Android's own prompt for a strong biometric (android.hardware.biometrics, no library),
 * bound to the crypto object of a [CryptoHandle] so a match unlocks exactly that key operation.
 * Only BIOMETRIC_STRONG is allowed: the phone's PIN never stands in. Cancelling the caller cancels
 * the prompt. [SystemBiometricPromptTest] pins the outcome mapping.
 */
class SystemBiometricPrompt(private val prompt: PromptShow) {

    suspend fun confirm(texts: PromptTexts, handle: CryptoHandle): Confirmation = suspendCancellableCoroutine { cont ->
        val signal = CancellationSignal()
        cont.invokeOnCancellation { signal.cancel() }
        val done = AtomicBoolean(false)
        prompt.show(texts, handle.platform, signal) { result -> if (done.compareAndSet(false, true)) cont.resume(result) }
    }

    companion object {
        /** Returns the prompt for [context], which must be the activity in front. */
        fun forContext(context: Context) = SystemBiometricPrompt { texts, crypto, signal, onResult ->
            val executor = context.mainExecutor
            val prompt = BiometricPrompt.Builder(context)
                .setTitle(texts.title)
                .setSubtitle(texts.subtitle)
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(false)
                .setNegativeButton(texts.negative, executor) { _, _ -> onResult(Confirmation.UsePassword) }
                .build()
            prompt.authenticate(
                crypto as BiometricPrompt.CryptoObject,
                signal,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onResult(Confirmation.Confirmed)

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onResult(confirmationFor(errorCode))
                },
            )
        }

        /**
         * Maps a prompt error code; a single wrong finger isn't an error and keeps the prompt up.
         * The negative button reports through its own listener ([Confirmation.UsePassword]).
         */
        fun confirmationFor(errorCode: Int): Confirmation = when (errorCode) {
            BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED -> Confirmation.Cancelled
            // The system ended it: screen off, another app took the sensor, the activity left.
            BiometricPrompt.BIOMETRIC_ERROR_CANCELED -> Confirmation.Interrupted
            BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT, BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT -> Confirmation.LockedOut
            else -> Confirmation.Failed
        }
    }
}
