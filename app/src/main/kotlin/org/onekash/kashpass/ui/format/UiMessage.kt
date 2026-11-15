package org.onekash.kashpass.ui.format

/** A message to show once in a snackbar, with an optional action such as Try again. */
class UiMessage(val text: String, val actionLabel: String? = null, val onAction: () -> Unit = {})
