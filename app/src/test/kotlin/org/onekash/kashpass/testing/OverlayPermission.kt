package org.onekash.kashpass.testing

import android.Manifest
import android.app.Application
import androidx.test.core.app.ApplicationProvider
import org.junit.rules.ExternalResource
import org.robolectric.Shadows

/**
 * Grants HIDE_OVERLAY_WINDOWS before the activity starts, as Android does at install time.
 * Robolectric grants only what a test requests, not what the manifest declares.
 */
class OverlayPermissionRule : ExternalResource() {
    override fun before() = grantOverlayPermission()
}

/** Grants HIDE_OVERLAY_WINDOWS to the app under test. */
fun grantOverlayPermission() {
    Shadows.shadowOf(ApplicationProvider.getApplicationContext<Application>()).grantPermissions(Manifest.permission.HIDE_OVERLAY_WINDOWS)
}
