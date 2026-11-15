package org.onekash.kashpass.ui.input

import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.ui.platform.PlatformTextInputMethodRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class NoLearningInputTest {

    @Test
    fun `the wrapped request adds no-personalized-learning after the field's own options`() {
        val connection = object : android.view.inputmethod.BaseInputConnection(android.view.View(androidx.test.core.app.ApplicationProvider.getApplicationContext()), false) {}
        // A field assigns imeOptions outright, so the flag must be added after it runs.
        val field = object : PlatformTextInputMethodRequest {
            override fun createInputConnection(outAttributes: EditorInfo): InputConnection {
                outAttributes.imeOptions = EditorInfo.IME_ACTION_DONE
                outAttributes.inputType = EditorInfo.TYPE_CLASS_TEXT
                return connection
            }
        }
        val info = EditorInfo()
        assertSame(connection, noLearning(field).createInputConnection(info))
        assertNotEquals(0, info.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING)
        assertEquals(EditorInfo.IME_ACTION_DONE, info.imeOptions and EditorInfo.IME_MASK_ACTION)
        assertEquals(EditorInfo.TYPE_CLASS_TEXT, info.inputType)
    }
}
