package org.onekash.kashpass.platform

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.provider.Settings
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.storage.UnlockAvailability
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows

@RunWith(RobolectricTestRunner::class)
class BiometricAvailabilityTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val biometrics = org.robolectric.shadow.api.Shadow.extract<org.robolectric.shadows.ShadowBiometricManager>(context.getSystemService(BiometricManager::class.java))
        .apply { setAuthenticatorType(BiometricManager.Authenticators.BIOMETRIC_STRONG) }
    private val keyguard = Shadows.shadowOf(context.getSystemService(KeyguardManager::class.java))
    private val packages = Shadows.shadowOf(context.packageManager)
    private val availability = BiometricAvailability(context)

    @Test
    fun `a secure phone with a strong biometric is ready`() {
        keyguard.setIsDeviceSecure(true)
        biometrics.setCanAuthenticate(true)
        assertEquals(UnlockAvailability.READY, availability.availability())
    }

    @Test
    fun `no screen lock wins over everything else`() {
        keyguard.setIsDeviceSecure(false)
        biometrics.setCanAuthenticate(true)
        assertEquals(UnlockAvailability.NO_SCREEN_LOCK, availability.availability())
    }

    @Test
    fun `no strong biometric is not ready`() {
        keyguard.setIsDeviceSecure(true)
        biometrics.setCanAuthenticate(false)
        assertEquals(false, availability.availability() == UnlockAvailability.READY)
    }

    @Test
    fun `the sensor kind follows the phone's features`() {
        packages.setSystemFeature(PackageManager.FEATURE_FINGERPRINT, true)
        packages.setSystemFeature(PackageManager.FEATURE_FACE, false)
        assertEquals(SensorKind.FINGERPRINT, availability.sensor())
        packages.setSystemFeature(PackageManager.FEATURE_FACE, true)
        assertEquals(SensorKind.FINGERPRINT_OR_FACE, availability.sensor())
        packages.setSystemFeature(PackageManager.FEATURE_FINGERPRINT, false)
        assertEquals(SensorKind.FACE, availability.sensor())
    }

    @Test
    fun `the enroll hint asks for a strong biometric, and labels never throw`() {
        val intent = availability.enrollIntent()
        assertEquals(Settings.ACTION_BIOMETRIC_ENROLL, intent.action)
        assertEquals(BiometricManager.Authenticators.BIOMETRIC_STRONG, intent.getIntExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, 0))
        availability.labels()
    }
}
