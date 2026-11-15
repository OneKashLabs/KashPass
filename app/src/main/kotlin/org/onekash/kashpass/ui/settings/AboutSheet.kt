package org.onekash.kashpass.ui.settings

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.ModalBottomSheetProperties
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.SecureFlagPolicy
import org.onekash.kashpass.R
import org.onekash.kashpass.ui.components.CenteredSheetLayout
import org.onekash.kashpass.ui.components.KASH_TAG
import org.onekash.kashpass.ui.components.KashArt
import org.onekash.kashpass.ui.components.KashPose
import org.onekash.kashpass.ui.components.RisingRows
import org.onekash.kashpass.ui.components.SheetRowSpec
import org.onekash.kashpass.ui.components.rememberHeroMotionEnabled

/** Holds the installed build's version name. */
data class AppVersion(val name: String) {
    companion object {
        /** Reads the version name from the package manager. */
        fun read(context: Context): AppVersion =
            AppVersion(context.packageManager.getPackageInfo(context.packageName, 0).versionName.orEmpty())
    }
}

/**
 * Shows About KashPass as a full-height sheet over Settings: Kash, the app name and what it is,
 * rows that open the source code, the issue tracker and the sponsor page, and a footer with the
 * version. The rows rise in unless [rowsPlayed]; [onRowsPlayed] runs as they start. [onOpenLink]
 * returns false when no app opens the link; a line then says so.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AboutSheet(
    version: AppVersion,
    onDismiss: () -> Unit,
    onOpenLink: (String) -> Boolean,
    rowsPlayed: Boolean,
    onRowsPlayed: () -> Unit,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        modifier = Modifier.fillMaxHeight(),
        // The sheet is its own window; SecureOn sets FLAG_SECURE on it whatever the activity sets.
        properties = ModalBottomSheetProperties(securePolicy = SecureFlagPolicy.SecureOn),
    ) {
        AboutContent(version, onOpenLink, rowsPlayed, onRowsPlayed)
    }
}

@Composable
private fun AboutContent(version: AppVersion, onOpenLink: (String) -> Boolean, rowsPlayed: Boolean, onRowsPlayed: () -> Unit) {
    var linkFailed by remember { mutableStateOf(false) }
    val open: (String) -> Unit = { link -> linkFailed = !onOpenLink(link) }
    val source = stringResource(R.string.about_url_source)
    val issues = stringResource(R.string.about_url_issues)
    val support = stringResource(R.string.about_url_support)
    CenteredSheetLayout(
        footer = {
            Column(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    stringResource(R.string.about_version, version.name),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    ) {
        KashArt(KashPose.HAPPY, Modifier.size(160.dp).testTag(KASH_TAG))
        Spacer(Modifier.height(8.dp))
        Text(
            stringResource(R.string.app_name),
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { heading() },
        )
        Spacer(Modifier.height(4.dp))
        Text(
            stringResource(R.string.about_tagline),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        RisingRows(
            rows = listOf(
                SheetRowSpec(R.drawable.ic_code, R.string.about_source, R.string.about_source_detail, { open(source) }, opensBrowser = true),
                SheetRowSpec(R.drawable.ic_bug_report, R.string.about_report, R.string.about_report_warning, { open(issues) }, opensBrowser = true),
                SheetRowSpec(R.drawable.ic_favorite, R.string.about_support, R.string.about_support_detail, { open(support) }, opensBrowser = true),
            ),
            motionEnabled = rememberHeroMotionEnabled(),
            played = rowsPlayed,
            onPlayed = onRowsPlayed,
        )
        // Always in the tree, empty until a link fails: TalkBack announces a live region when its
        // text changes, not when the node first appears.
        Text(
            if (linkFailed) stringResource(R.string.entry_no_browser) else "",
            color = MaterialTheme.colorScheme.error,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 12.dp).semantics { liveRegion = LiveRegionMode.Polite },
        )
    }
}
