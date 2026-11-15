package org.onekash.kashpass.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.onekash.kashpass.session.BiometricStatus
import org.onekash.kashpass.session.BiometricUnlock
import org.onekash.kashpass.session.EnableResult
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.session.VaultTarget
import org.onekash.kashpass.vault.backup.BackupInfo
import org.onekash.kashpass.vault.storage.Confirmation
import org.onekash.kashpass.vault.storage.CryptoHandle

/** What Settings shows; null while it is closed. */
data class SettingsUiState(
    val fileName: String,
    val biometric: BiometricStatus,
    /** False for a backup opened read-only; the biometric switch belongs to the file itself. */
    val isFile: Boolean = true,
    /** The prompt passed but the phone couldn't store the key; shown under the switch. */
    val biometricFailed: Boolean = false,
    /** True while a biometric change runs; progress shows and the switch is disabled. */
    val applying: Boolean = false,
    /** True while the About sheet shows over Settings; closing Settings or a lock closes it. */
    val about: Boolean = false,
    /**
     * False for a vault opened with a key file alone (it has no password to seal) and for a
     * session-only file (nothing is stored for it).
     */
    val biometricShown: Boolean = true,
    /** False for a session-only file, which has no backups. */
    val backupsShown: Boolean = true,
)

/**
 * Drives Settings, the page behind the browser's gear. Activity-scoped, so whether it is open
 * survives a rotation without saved state; a lock closes it. [SettingsViewModelTest] pins it.
 */
class SettingsViewModel(
    private val sessions: SessionHolder,
    private val biometric: BiometricUnlock,
    private val fileName: () -> String,
) : ViewModel() {

    private val mutable = MutableStateFlow<SettingsUiState?>(null)
    val state: StateFlow<SettingsUiState?> = mutable.asStateFlow()

    // Running changes, kept here so reopening Settings shows them; main thread only.
    private var inFlight = 0

    // The backup the open Settings page belongs to; null for the file itself.
    private var openedFor: BackupInfo? = null

    init {
        // A lock closes Settings, and so does a switch to or from a backup (one opened from
        // Vault backups, or Close backup), so that session shows. A save's session swap keeps it.
        viewModelScope.launch {
            sessions.current.collect { u ->
                if (u == null || u.backup != openedFor) mutable.value = null
            }
        }
    }

    fun open() {
        val unlocked = sessions.current.value ?: return
        openedFor = unlocked.backup
        mutable.value = SettingsUiState(
            unlocked.sessionName ?: fileName(), biometric.status(unlocked.location), isFile = unlocked.backup == null, applying = inFlight > 0,
            biometricShown = biometric.canSeal(unlocked),
            backupsShown = !unlocked.sessionOnly,
        )
    }

    fun close() {
        mutable.value = null
    }

    /**
     * True once About's rows have risen in since About last opened; a rotation finds them played
     * and shows them at rest. Kept apart from [state], with no saved state.
     */
    var aboutRowsPlayed = false
        private set

    /** Records that About's rows have started rising in. */
    fun markAboutRowsPlayed() {
        aboutRowsPlayed = true
    }

    /** Shows the About sheet while Settings is open; its rows rise in again. */
    fun openAbout() {
        aboutRowsPlayed = false
        mutable.update { it?.copy(about = true) }
    }

    fun closeAbout() {
        mutable.update { it?.copy(about = false) }
    }

    // Runs [block] in the view model's scope, counted in SettingsUiState.applying until it ends.
    private fun applying(block: suspend () -> Unit) {
        inFlight++
        mutable.update { it?.copy(applying = true) }
        viewModelScope.launch {
            try {
                block()
            } finally {
                inFlight--
                mutable.update { it?.copy(applying = inFlight > 0) }
            }
        }
    }

    /** Turns biometric unlock on (after [confirm]) or off for the open remembered file. */
    fun setBiometric(on: Boolean, confirm: suspend (CryptoHandle) -> Confirmation) {
        val unlocked = sessions.current.value?.takeIf { it.target == VaultTarget.REMEMBERED } ?: return
        applying {
            val failed = if (on) {
                biometric.enable(unlocked, confirm) == EnableResult.Failed
            } else {
                biometric.disable(unlocked.location)
                false
            }
            mutable.update { it?.copy(biometric = biometric.status(unlocked.location), biometricFailed = failed) }
        }
    }
}
