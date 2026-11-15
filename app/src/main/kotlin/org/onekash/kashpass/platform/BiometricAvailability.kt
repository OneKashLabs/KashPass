package org.onekash.kashpass.platform

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
import android.provider.Settings
import org.onekash.kashpass.vault.storage.UnlockAvailability

/** Which strong biometric the phone has, for sentences that need its name. */
enum class SensorKind { FINGERPRINT, FACE, FINGERPRINT_OR_FACE, OTHER }

/** Holds Android's own button label for the phone's strong biometric; null where it gives none. */
data class BiometricLabels(val button: String?)

/**
 * Reports whether a strong (Class 3) biometric can protect a key now, and how to name it. A phone
 * without a secure screen lock can't hold such a key at all.
 * [BiometricAvailabilityTest] pins the mapping.
 */
class BiometricAvailability(private val context: Context) {

    private val biometrics: BiometricManager? get() = context.getSystemService(BiometricManager::class.java)

    fun availability(): UnlockAvailability {
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        if (keyguard == null || !keyguard.isDeviceSecure) return UnlockAvailability.NO_SCREEN_LOCK
        return when (biometrics?.canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> UnlockAvailability.READY
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> UnlockAvailability.NONE_ENROLLED
            else -> UnlockAvailability.UNAVAILABLE
        }
    }

    /**
     * Returns Android's button label for the strong biometric, shown as given. Its setting name
     * reads as a command on some phones ("Use fingerprint"), so the switch keeps KashPass's own
     * names.
     */
    fun labels(): BiometricLabels = try {
        BiometricLabels(biometrics?.getStrings(BIOMETRIC_STRONG)?.buttonLabel?.toString())
    } catch (e: RuntimeException) {
        // A missing or throwing system service leaves KashPass's own wording.
        BiometricLabels(null)
    }

    fun sensor(): SensorKind {
        val pm = context.packageManager
        val fingerprint = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        val face = pm.hasSystemFeature(PackageManager.FEATURE_FACE)
        return when {
            fingerprint && face -> SensorKind.FINGERPRINT_OR_FACE
            fingerprint -> SensorKind.FINGERPRINT
            face -> SensorKind.FACE
            else -> SensorKind.OTHER
        }
    }

    /** Returns the intent for the system screen that enrolls a strong biometric. */
    fun enrollIntent(): Intent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, BIOMETRIC_STRONG)
}
