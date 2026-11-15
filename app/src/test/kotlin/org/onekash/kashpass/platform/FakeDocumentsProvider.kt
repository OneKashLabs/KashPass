package org.onekash.kashpass.platform

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import java.io.File

/**
 * A provider that answers [OpenableColumns] and document column queries the way a documents
 * provider does, opens [file] in the requested mode (recording the mode), deletes on the
 * documents call, or throws [failure] for every query, as a buggy or restarting provider can.
 */
class FakeDocumentsProvider : ContentProvider() {

    override fun onCreate() = true

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, args: Array<out String>?, sort: String?): Cursor {
        failure?.let { throw it }
        val columns = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return MatrixCursor(columns).apply {
            addRow(
                columns.map<String, Any?> {
                    when (it) {
                        OpenableColumns.SIZE -> size
                        DocumentsContract.Document.COLUMN_FLAGS -> flags
                        DocumentsContract.Document.COLUMN_LAST_MODIFIED -> lastModified
                        else -> name
                    }
                }.toTypedArray(),
            )
        }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        modes += mode
        val target = file ?: throw java.io.FileNotFoundException("no document")
        return ParcelFileDescriptor.open(target, ParcelFileDescriptor.parseMode(mode))
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method == "android:deleteDocument") {
            deleted = true
            file?.delete()
        }
        return Bundle()
    }

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, args: Array<out String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, args: Array<out String>?) = 0

    companion object {
        const val AUTHORITY = "org.onekash.kashpass.test.documents"
        val URI: Uri = Uri.parse("content://$AUTHORITY/document/1")
        var name: String? = "Passwords.kdbx"
        var size: Long? = 1_975
        var failure: RuntimeException? = null
        var flags: Int? = DocumentsContract.Document.FLAG_SUPPORTS_WRITE
        var lastModified: Long? = 1_700_000_000_000
        var file: File? = null
        val modes = mutableListOf<String>()
        var deleted = false

        fun reset() {
            name = "Passwords.kdbx"
            size = 1_975
            failure = null
            flags = DocumentsContract.Document.FLAG_SUPPORTS_WRITE
            lastModified = 1_700_000_000_000
            file = null
            modes.clear()
            deleted = false
        }
    }
}
