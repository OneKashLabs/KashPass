package org.onekash.kashpass.platform

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.onekash.kashpass.vault.backup.SaveMarker
import org.onekash.kashpass.vault.backup.Sha256
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PrefsSaveMarkerStoreTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val loc = "content://drive/document/42"
    private val old = "a".repeat(64)
    private val new = "b".repeat(64)

    @Test
    fun `a marker survives a new store instance and clears`() {
        PrefsSaveMarkerStore(context).set(loc, old, new)
        assertEquals(SaveMarker(old, new), PrefsSaveMarkerStore(context).get(loc))
        assertNull(PrefsSaveMarkerStore(context).get("content://drive/document/43"))
        PrefsSaveMarkerStore(context).clear(loc)
        assertNull(PrefsSaveMarkerStore(context).get(loc))
    }

    @Test
    fun `only the location hash and the two file hashes are stored`() {
        PrefsSaveMarkerStore(context).set(loc, old, new)
        val stored = context.getSharedPreferences("save_markers", Context.MODE_PRIVATE).all
        assertEquals(mapOf(Sha256.ofLocation(loc) to "$old:$new"), stored)
    }
}
