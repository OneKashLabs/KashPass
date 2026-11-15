package org.onekash.kashpass.platform

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import androidx.core.content.IntentCompat
import androidx.core.net.toUri
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class OpenDocumentFromTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun `the picker starts in the folder of the file given at launch`() {
        var initial: Uri? = "content://other.app/files/shared.kdbx".toUri()
        val contract = OpenDocumentFrom { initial }
        val intent = contract.createIntent(context, arrayOf("*/*"))
        assertEquals(Intent.ACTION_OPEN_DOCUMENT, intent.action)
        assertEquals(initial, IntentCompat.getParcelableExtra(intent, DocumentsContract.EXTRA_INITIAL_URI, Uri::class.java))
        initial = null
        assertFalse(contract.createIntent(context, arrayOf("*/*")).hasExtra(DocumentsContract.EXTRA_INITIAL_URI))
    }
}
