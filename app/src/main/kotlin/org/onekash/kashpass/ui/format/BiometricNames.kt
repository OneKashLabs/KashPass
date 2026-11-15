package org.onekash.kashpass.ui.format

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.res.stringResource
import org.onekash.kashpass.R
import org.onekash.kashpass.platform.BiometricAvailability
import org.onekash.kashpass.platform.BiometricLabels
import org.onekash.kashpass.platform.SensorKind

/** How this phone's biometric is named: Android's own button label where it gives one. */
class BiometricNames(val button: String, val name: String, val noun: String)

@Composable
fun biometricNames(availability: BiometricAvailability?): BiometricNames {
    val kind = remember(availability) { availability?.sensor() ?: SensorKind.OTHER }
    val labels = remember(availability) { availability?.labels() ?: BiometricLabels(null) }
    val noun = stringResource(
        when (kind) {
            SensorKind.FINGERPRINT -> R.string.biometric_noun_fingerprint
            SensorKind.FACE -> R.string.biometric_noun_face
            SensorKind.FINGERPRINT_OR_FACE -> R.string.biometric_noun_either
            SensorKind.OTHER -> R.string.biometric_noun_other
        },
    )
    val name = stringResource(
        when (kind) {
            SensorKind.FINGERPRINT -> R.string.biometric_name_fingerprint
            SensorKind.FACE -> R.string.biometric_name_face
            SensorKind.FINGERPRINT_OR_FACE -> R.string.biometric_name_either
            SensorKind.OTHER -> R.string.biometric_name_other
        },
    )
    val button = labels.button ?: stringResource(R.string.biometric_button, noun)
    return BiometricNames(button, name, noun)
}
