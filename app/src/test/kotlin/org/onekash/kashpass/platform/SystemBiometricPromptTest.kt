package org.onekash.kashpass.platform

import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.CryptoHandle
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SystemBiometricPromptTest {

    private val texts = PromptTexts(title = "Unlock KashPass", subtitle = "Passwords.kdbx", negative = "Use password")

    @Test
    fun `error codes map to cancel, interruption, lockout and failure`() {
        assertEquals(Confirmation.Cancelled, SystemBiometricPrompt.confirmationFor(BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED))
        assertEquals(Confirmation.Interrupted, SystemBiometricPrompt.confirmationFor(BiometricPrompt.BIOMETRIC_ERROR_CANCELED))
        assertEquals(Confirmation.LockedOut, SystemBiometricPrompt.confirmationFor(BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT))
        assertEquals(Confirmation.LockedOut, SystemBiometricPrompt.confirmationFor(BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT))
        assertEquals(Confirmation.Failed, SystemBiometricPrompt.confirmationFor(BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT))
        assertEquals(Confirmation.Failed, SystemBiometricPrompt.confirmationFor(BiometricPrompt.BIOMETRIC_ERROR_HW_UNAVAILABLE))
    }

    @Test
    fun `the prompt shows the given texts and reports a success once`() = runBlocking<Unit> {
        var shown: PromptTexts? = null
        val prompt = SystemBiometricPrompt { t, _, _, onResult ->
            shown = t
            onResult(Confirmation.Confirmed)
            onResult(Confirmation.Failed)
        }
        assertEquals(Confirmation.Confirmed, prompt.confirm(texts, CryptoHandle(Unit)))
        assertEquals(texts, shown)
    }

    @Test
    fun `cancelling the caller cancels the system prompt`() = runBlocking<Unit> {
        var signal: CancellationSignal? = null
        val prompt = SystemBiometricPrompt { _, _, s, _ -> signal = s }
        val job = async(start = CoroutineStart.UNDISPATCHED) { prompt.confirm(texts, CryptoHandle(Unit)) }
        yield()
        job.cancel()
        assertTrue(signal!!.isCanceled)
    }
}
