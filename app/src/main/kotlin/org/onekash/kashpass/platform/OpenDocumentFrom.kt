package org.onekash.kashpass.platform

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.result.contract.ActivityResultContracts

/**
 * Opens the system file picker ([ActivityResultContracts.OpenDocument]) in the folder of the file
 * [initial] returns at launch, through [DocumentsContract.EXTRA_INITIAL_URI]; with null the picker
 * opens at its default location. The picker ignores a location its provider doesn't serve.
 */
class OpenDocumentFrom(private val initial: () -> Uri?) : ActivityResultContracts.OpenDocument() {

    override fun createIntent(context: Context, input: Array<String>): Intent =
        super.createIntent(context, input).apply { initial()?.let { putExtra(DocumentsContract.EXTRA_INITIAL_URI, it) } }
}
