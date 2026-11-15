package org.onekash.kashpass.vault.doc

import java.util.Locale

/**
 * Whether a Meta/Color or an entry's ForegroundColor or BackgroundColor is readable: whether .NET
 * Framework 4.8's ColorTranslator.FromHtml accepts it. Follows the reference source
 * (github.com/microsoft/referencesource, System.Drawing/commonui/System/Drawing/ColorTranslator.cs
 * and ColorConverter.cs, and mscorlib's ParseNumbers and Int32 parsing):
 * - `#` with 6 or 3 more characters: each pair (or doubled character) is hex, else refused;
 * - `LightGrey` in any case, and the HTML system color names in lower case;
 * - else ColorConverter on the trimmed text: a color name of System.Drawing.Color or
 *   SystemColors in any case; a quoted name; one integer (decimal, or hex after `#`, `0x` or
 *   `&h`); or 3 or 4 integers from 0 to 255 split by the list separator.
 * ColorConverter uses the current culture's list separator; this follows `,`, the separator of
 * en-US and of the invariant culture. [HtmlColorTest] pins each form.
 */
internal object HtmlColor {

    /** Returns true when FromHtml accepts [text], or [text] is empty, which means no color. */
    fun accepts(text: String): Boolean {
        if (text.isEmpty()) return true
        if (text[0] == '#' && (text.length == 7 || text.length == 4)) {
            val pairs = if (text.length == 7) listOf(text.substring(1, 3), text.substring(3, 5), text.substring(5, 7))
            else (1..3).map { "${text[it]}${text[it]}" }
            return pairs.all { hex(it) != null }
        }
        if (text.equals("LightGrey", ignoreCase = true)) return true
        if (text.lowercase(Locale.ROOT) in HTML_SYSTEM_COLORS) return true
        return converter(text.trim())
    }

    // ColorConverter.ConvertFrom with the list separator ','.
    private fun converter(text: String): Boolean {
        if (text.isEmpty()) return true
        if (text.uppercase(Locale.ROOT) in NAMED) return true
        if (',' !in text && text.length >= 2 && (text[0] == '\'' || text[0] == '"') && text[0] == text[text.length - 1]) return true
        val values = text.split(',').map { int32(it) ?: return false }
        return when (values.size) {
            1 -> true
            3, 4 -> values.all { it in 0..255 }
            else -> false
        }
    }

    // Int32Converter.ConvertFromString: trimmed; hex after '#', "0x", "0X", "&h" or "&H"; else
    // Int32.Parse with NumberStyles.Integer.
    private fun int32(token: String): Int? {
        val t = token.trim()
        return when {
            t.startsWith("#") -> hex(t.substring(1))
            t.startsWith("0x") || t.startsWith("0X") || t.startsWith("&h") || t.startsWith("&H") -> hex(t.substring(2))
            else -> parseInt32Invariant(t)
        }
    }

    // Convert.ToInt32(s, 16), ParseNumbers.StringToInt with IsTight: an optional '+' ('-' is
    // refused for base 16), an optional "0x", then hex digits and nothing else, at most 0xFFFFFFFF;
    // the value wraps into Int32 as an unsigned 32-bit number does.
    private fun hex(s: String): Int? {
        var t = s.removePrefix("+")
        if (t.startsWith("0x") || t.startsWith("0X")) t = t.substring(2)
        if (t.isEmpty() || !t.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        val value = t.trimStart('0').ifEmpty { "0" }
        if (value.length > 8) return null
        return value.toLong(16).toInt()
    }

    // ColorTranslator's htmlSysColorTable keys.
    private val HTML_SYSTEM_COLORS = setOf(
        "activeborder", "activecaption", "appworkspace", "background", "buttonface", "buttonhighlight", "buttonshadow",
        "buttontext", "captiontext", "graytext", "highlight", "highlighttext", "inactiveborder", "inactivecaption",
        "inactivecaptiontext", "infobackground", "infotext", "menu", "menutext", "scrollbar", "threeddarkshadow",
        "threedface", "threedhighlight", "threedlightshadow", "window", "windowframe", "windowtext",
    )

    // The public static Color properties of System.Drawing.Color and SystemColors in .NET Framework
    // 4.8, which ColorConverter's name table holds; compared without case (all ASCII).
    private val NAMED = setOf(
        "Transparent", "AliceBlue", "AntiqueWhite", "Aqua", "Aquamarine", "Azure", "Beige", "Bisque", "Black", "BlanchedAlmond",
        "Blue", "BlueViolet", "Brown", "BurlyWood", "CadetBlue", "Chartreuse", "Chocolate", "Coral", "CornflowerBlue", "Cornsilk",
        "Crimson", "Cyan", "DarkBlue", "DarkCyan", "DarkGoldenrod", "DarkGray", "DarkGreen", "DarkKhaki", "DarkMagenta",
        "DarkOliveGreen", "DarkOrange", "DarkOrchid", "DarkRed", "DarkSalmon", "DarkSeaGreen", "DarkSlateBlue", "DarkSlateGray",
        "DarkTurquoise", "DarkViolet", "DeepPink", "DeepSkyBlue", "DimGray", "DodgerBlue", "Firebrick", "FloralWhite",
        "ForestGreen", "Fuchsia", "Gainsboro", "GhostWhite", "Gold", "Goldenrod", "Gray", "Green", "GreenYellow", "Honeydew",
        "HotPink", "IndianRed", "Indigo", "Ivory", "Khaki", "Lavender", "LavenderBlush", "LawnGreen", "LemonChiffon", "LightBlue",
        "LightCoral", "LightCyan", "LightGoldenrodYellow", "LightGreen", "LightGray", "LightPink", "LightSalmon", "LightSeaGreen",
        "LightSkyBlue", "LightSlateGray", "LightSteelBlue", "LightYellow", "Lime", "LimeGreen", "Linen", "Magenta", "Maroon",
        "MediumAquamarine", "MediumBlue", "MediumOrchid", "MediumPurple", "MediumSeaGreen", "MediumSlateBlue",
        "MediumSpringGreen", "MediumTurquoise", "MediumVioletRed", "MidnightBlue", "MintCream", "MistyRose", "Moccasin",
        "NavajoWhite", "Navy", "OldLace", "Olive", "OliveDrab", "Orange", "OrangeRed", "Orchid", "PaleGoldenrod", "PaleGreen",
        "PaleTurquoise", "PaleVioletRed", "PapayaWhip", "PeachPuff", "Peru", "Pink", "Plum", "PowderBlue", "Purple", "Red",
        "RosyBrown", "RoyalBlue", "SaddleBrown", "Salmon", "SandyBrown", "SeaGreen", "SeaShell", "Sienna", "Silver", "SkyBlue",
        "SlateBlue", "SlateGray", "Snow", "SpringGreen", "SteelBlue", "Tan", "Teal", "Thistle", "Tomato", "Turquoise", "Violet",
        "Wheat", "White", "WhiteSmoke", "Yellow", "YellowGreen",
        "ActiveBorder", "ActiveCaption", "ActiveCaptionText", "AppWorkspace", "ButtonFace", "ButtonHighlight", "ButtonShadow",
        "Control", "ControlDark", "ControlDarkDark", "ControlLight", "ControlLightLight", "ControlText", "Desktop",
        "GradientActiveCaption", "GradientInactiveCaption", "GrayText", "Highlight", "HighlightText", "HotTrack",
        "InactiveBorder", "InactiveCaption", "InactiveCaptionText", "Info", "InfoText", "Menu", "MenuBar", "MenuHighlight",
        "MenuText", "ScrollBar", "Window", "WindowFrame", "WindowText",
    ).mapTo(HashSet()) { it.uppercase(Locale.ROOT) }
}
