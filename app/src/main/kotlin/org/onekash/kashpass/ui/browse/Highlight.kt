package org.onekash.kashpass.ui.browse

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle

/** Returns the style of a matched search term in a row: bold on a soft [background]. */
fun matchStyle(background: Color) = SpanStyle(fontWeight = FontWeight.Bold, background = background)

/**
 * Returns [prefix] + [text] with [range] (in [text]'s positions) in [style]. A null or empty range,
 * or one outside [text], gives the plain text: highlighting never changes what is shown.
 */
fun highlighted(text: String, range: IntRange?, style: SpanStyle, prefix: String = ""): AnnotatedString = buildAnnotatedString {
    append(prefix)
    if (range == null || range.isEmpty() || range.first < 0 || range.last >= text.length) {
        append(text)
        return@buildAnnotatedString
    }
    append(text.substring(0, range.first))
    withStyle(style) { append(text.substring(range)) }
    append(text.substring(range.last + 1))
}
