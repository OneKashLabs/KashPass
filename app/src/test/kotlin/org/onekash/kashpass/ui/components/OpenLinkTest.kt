package org.onekash.kashpass.ui.components

import android.app.Activity
import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf

@RunWith(RobolectricTestRunner::class)
class OpenLinkTest {

    private val activity = Robolectric.buildActivity(Activity::class.java).setup().get()

    @Test
    fun `an https link starts a browsable ACTION_VIEW`() {
        assertTrue(openWebLink(activity, "https://example.com/a"))
        val started = shadowOf(activity).nextStartedActivity
        assertEquals(Intent.ACTION_VIEW, started.action)
        assertTrue(started.hasCategory(Intent.CATEGORY_BROWSABLE))
        assertEquals("https://example.com/a", started.dataString)
    }

    @Test
    fun `other schemes start nothing`() {
        for (link in listOf("javascript:alert(1)", "file:///sdcard/x", "intent://x#Intent;end", "cmd://calc", "example.com")) {
            assertFalse(link, openWebLink(activity, link))
        }
        assertNull(shadowOf(activity).nextStartedActivity)
    }

    @Test
    fun `no app for the link returns false`() {
        shadowOf(activity.application).checkActivities(true)
        assertFalse(openWebLink(activity, "https://example.com"))
    }
}
