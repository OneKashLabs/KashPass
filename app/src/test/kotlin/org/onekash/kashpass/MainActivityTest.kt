package org.onekash.kashpass

import android.content.ComponentName
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.net.Uri
import androidx.lifecycle.ViewModelProvider
import android.view.View
import android.view.WindowManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.testing.grantOverlayPermission
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MainActivityTest {

    @Test
    fun `window blocks screenshots and recents thumbnail from onCreate on`() {
        // Checked after onCreate and before start and resume, so the first frame (drawn after
        // resume) is secure. Moving the flag to onStart or later fails here.
        grantOverlayPermission()
        val activity = Robolectric.buildActivity(MainActivity::class.java).create().get()

        val flags = activity.window.attributes.flags
        assertTrue(flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
    }

    @Test
    fun `other apps' overlays are hidden while KashPass shows`() {
        grantOverlayPermission()
        val activity = Robolectric.buildActivity(MainActivity::class.java).create().get()
        assertTrue(privateFlags(activity.window.attributes) and HIDE_NON_SYSTEM_OVERLAY_WINDOWS != 0)
    }

    @Test
    fun `the app opens without the permission`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).create().get()
        assertNotNull(activity.window)
        assertEquals(0, privateFlags(activity.window.attributes) and HIDE_NON_SYSTEM_OVERLAY_WINDOWS)
    }

    @Test
    fun `the window excludes every view from autofill`() {
        grantOverlayPermission()
        val activity = Robolectric.buildActivity(MainActivity::class.java).create().start().resume().get()
        val decor = activity.window.decorView
        assertEquals(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS, decor.importantForAutofill)
        val content = activity.findViewById<android.view.ViewGroup>(android.R.id.content).getChildAt(0)
        assertEquals(false, content.isImportantForAutofill)
    }

    @Test
    fun `the app requests the large heap that Argon2 vaults with more memory need`() {
        val activity = Robolectric.buildActivity(MainActivity::class.java).create().get()
        assertTrue(activity.applicationInfo.flags and ApplicationInfo.FLAG_LARGE_HEAP != 0)
    }

    private val context get() = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()

    private fun view(uri: String, type: String = "application/octet-stream") =
        Intent(Intent.ACTION_VIEW).setDataAndType(Uri.parse(uri), type)

    private fun resolves(intent: Intent): Boolean =
        context.packageManager.queryIntentActivities(intent, 0).any { it.activityInfo.name == MainActivity::class.java.name }

    @Test
    fun `the manifest offers KashPass to open KeePass files from content URIs only`() {
        assertTrue(resolves(view("content://com.google.android.apps.docs.storage/document/1")))
        assertTrue(resolves(view("content://provider/doc", "application/x-kdbx")))
        assertTrue(resolves(view("content://provider/doc", "application/x-keepass")))
        assertFalse("file: is never accepted", resolves(view("file:///sdcard/Passwords.kdbx")))
        assertFalse(resolves(view("content://provider/doc", "image/png")))
        assertFalse(resolves(view("https://example.com/Passwords.kdbx")))
    }

    @Test
    fun `an Open with lands in the existing KashPass task`() {
        val info = context.packageManager.getActivityInfo(ComponentName(context, MainActivity::class.java), 0)
        assertEquals(ActivityInfo.LAUNCH_SINGLE_TASK, info.launchMode)
    }

    @Test
    fun `only the data URI of a content VIEW intent is read`() {
        val content = "content://provider/doc"
        assertEquals(Uri.parse(content), openWithUri(view(content)))
        // An extra naming another file is never read.
        assertEquals(Uri.parse(content), openWithUri(view(content).putExtra(Intent.EXTRA_STREAM, Uri.parse("content://other/doc"))))
        assertNull(openWithUri(view("file:///sdcard/Passwords.kdbx")))
        assertNull(openWithUri(Intent(Intent.ACTION_SEND).setData(Uri.parse(content))))
        assertNull(openWithUri(Intent(Intent.ACTION_VIEW)))
        assertNull(openWithUri(Intent(Intent.ACTION_MAIN)))
        assertNull(openWithUri(null))
        assertNull("a launch from Recents replays the old intent", openWithUri(view(content).addFlags(Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY)))
    }

    @Test
    fun `only a persistable write grant is tried as a writable vault`() {
        val content = "content://provider/doc"
        assertFalse(offersWritableGrant(view(content).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)))
        assertFalse(offersWritableGrant(view(content).addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)))
        assertFalse(offersWritableGrant(view(content).addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION)))
        assertTrue(offersWritableGrant(view(content).addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)))
    }

    private fun lockState(activity: MainActivity) = ViewModelProvider(activity)[org.onekash.kashpass.ui.lock.LockViewModel::class.java].uiState.value

    // The name lookup runs on the IO dispatcher; the main looper applies its result.
    private fun idleUntil(condition: () -> Boolean): Boolean {
        repeat(300) {
            org.robolectric.shadows.ShadowLooper.idleMainLooper()
            if (condition()) return true
            Thread.sleep(10)
        }
        return false
    }

    @Test
    fun `the launch intent is handled once, not again after recreation`() {
        val controller = Robolectric.buildActivity(MainActivity::class.java, view("content://provider/document/shared.kdbx")).setup()
        assertTrue(idleUntil { lockState(controller.get()).openedFromApp })
        ViewModelProvider(controller.get())[org.onekash.kashpass.ui.lock.LockViewModel::class.java].cancelIncoming()
        org.robolectric.shadows.ShadowLooper.idleMainLooper()
        assertFalse(lockState(controller.get()).openedFromApp)
        controller.recreate()
        assertFalse(idleUntil { lockState(controller.get()).openedFromApp })
    }

    @Test
    fun `a launch from Recents ignores the old VIEW data`() {
        val intent = view("content://provider/document/shared.kdbx").addFlags(Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY)
        val activity = Robolectric.buildActivity(MainActivity::class.java, intent).setup().get()
        org.robolectric.shadows.ShadowLooper.idleMainLooper()
        assertFalse(lockState(activity).openedFromApp)
        assertNull(lockState(activity).vaultName)
    }

    // WindowManager.LayoutParams.privateFlags and SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS are
    // hidden from the SDK; Window.setHideOverlayWindows sets that flag (Android 12+).
    private fun privateFlags(attributes: WindowManager.LayoutParams): Int =
        WindowManager.LayoutParams::class.java.getField("privateFlags").getInt(attributes)

    private companion object {
        const val HIDE_NON_SYSTEM_OVERLAY_WINDOWS = 0x00080000
    }

    @Test
    fun `Save as new file names the remembered vault it replaces only for a session-only file`() = kotlinx.coroutines.runBlocking<Unit> {
        val files = org.onekash.kashpass.testing.FakeVaultFiles()
        val bytes = org.onekash.kashpass.vault.testing.TestVaults.bytes(aesRounds = 1_000UL)
        val shared = org.onekash.kashpass.vault.testing.TestVaults.unlock(bytes, access = org.onekash.kashpass.vault.doc.FileAccess.SESSION_ONLY)
        val opened = org.onekash.kashpass.vault.testing.TestVaults.unlock(bytes)
        val sessionOnly = org.onekash.kashpass.session.Unlocked("content://other.app/files/shared.kdbx", shared.session, shared.kdf, false, sessionName = "Shared.kdbx")
        val remembered = org.onekash.kashpass.session.Unlocked("content://drive/document/doc1", opened.session, opened.kdf, false)
        assertNull("no vault is remembered", savedCopyReplaces(sessionOnly, files))
        files.vault = org.onekash.kashpass.platform.RememberedVault("content://drive/document/doc1", "Passwords.kdbx")
        assertEquals("Passwords.kdbx", savedCopyReplaces(sessionOnly, files))
        assertNull(savedCopyReplaces(remembered, files))
        assertNull(savedCopyReplaces(null, files))
        assertEquals("Shared.kdbx", shownFileName(sessionOnly, files))
        assertEquals("Passwords.kdbx", shownFileName(remembered, files))
    }
}
