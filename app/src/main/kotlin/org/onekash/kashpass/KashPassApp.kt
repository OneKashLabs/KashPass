package org.onekash.kashpass

import android.app.Application
import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.StrictMode
import android.content.ClipboardManager
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.onekash.kashpass.lock.LockController
import org.onekash.kashpass.lock.LockOnCrash
import android.content.pm.PackageManager
import org.onekash.kashpass.platform.AlarmClearAlarm
import org.onekash.kashpass.platform.BiometricAvailability
import org.onekash.kashpass.platform.KeystoreUnlockKeyStore
import org.onekash.kashpass.vault.backup.BackupRetention
import org.onekash.kashpass.vault.backup.Sha256
import org.onekash.kashpass.vault.storage.UnlockKeyStore
import org.onekash.kashpass.platform.ClipboardDeadlineStore
import org.onekash.kashpass.platform.FileBackupStore
import org.onekash.kashpass.platform.KeyFileAccess
import org.onekash.kashpass.platform.PrefsSaveMarkerStore
import org.onekash.kashpass.platform.PrefsVaultStateStore
import org.onekash.kashpass.platform.ResolverUriGrants
import org.onekash.kashpass.platform.SafVaultStorage
import org.onekash.kashpass.platform.SensitiveClipboard
import org.onekash.kashpass.platform.VaultFileAccess
import org.onekash.kashpass.session.BackupSettings
import org.onekash.kashpass.session.BiometricUnlock
import org.onekash.kashpass.session.SaveCoordinator
import org.onekash.kashpass.session.SessionHolder
import org.onekash.kashpass.vault.save.SafeSaver
import org.onekash.kashpass.vault.storage.DeadlineStorage
import org.onekash.kashpass.vault.storage.VaultStorage
import org.onekash.kashpass.vault.save.VaultSaving
import org.onekash.kashpass.vault.open.VaultOpener
import org.onekash.kashpass.vault.open.VaultOpening

/** Holds the app's single object graph, wired by hand (no DI framework). */
class KashPassApp : Application() {

    lateinit var graph: AppGraph
        private set

    override fun onCreate() {
        super.onCreate()
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) strictMode()
        graph = AppGraph(this)
        // Before the process dies of an uncaught exception, drop the document and the key.
        LockOnCrash.install {
            graph.sessions.lock()
            graph.saves.cancelRunning()
        }
        graph.clipboard.clearIfDue()
        graph.files.releaseUnusedGrants()
        graph.locker.registerScreenOff(this)
        graph.appScope.launch { graph.backups.pruneAll() }
    }
}

/**
 * Logs main-thread disk and network access and leaked resources in debug builds. Only checks whose
 * reports are stack traces: the URI and intent checks would log content URIs (vault locations).
 */
private fun strictMode() {
    StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().detectDiskReads().detectDiskWrites().detectNetwork().penaltyLog().build())
    StrictMode.setVmPolicy(
        StrictMode.VmPolicy.Builder()
            .detectLeakedClosableObjects()
            .detectLeakedRegistrationObjects()
            .detectActivityLeaks()
            .penaltyLog()
            .build(),
    )
}

/** Holds every long-lived object, created once per process. */
class AppGraph(context: Context) {

    /** Outlives screens and locks; the clipboard timer runs here. */
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /**
     * True from the activity's start or focus regain until it stops or loses window focus; the
     * clipboard reads it to choose its clearing rule.
     */
    @Volatile
    var inForeground = false

    val sessions = SessionHolder()
    val state = PrefsVaultStateStore(context)
    val biometrics = BiometricAvailability(context)

    /** Biometric unlock's sealed keys, in storage Android never backs up or transfers. */
    val unlockKeys: UnlockKeyStore = KeystoreUnlockKeyStore(
        File(context.noBackupFilesDir, "biometric"),
        availability = biometrics::availability,
        strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE),
    )
    val files = VaultFileAccess(ResolverUriGrants(context.contentResolver), state, Dispatchers.IO, unlockKeys, VaultFileAccess.displayNameFrom(context.contentResolver))

    val markers = PrefsSaveMarkerStore(context)

    /**
     * Encrypted copies of the vault, in storage Android never backs up or transfers. A backup
     * folder and a save marker share the location's hash, so no copy in a folder is deleted while
     * that location's save is unverified.
     */
    val backups = FileBackupStore(
        backupRoot(context), Dispatchers.IO,
        keep = { BackupRetention.keepOf(state.backupKeep()) },
        pinned = markers::isPending,
    )
    // Provider calls that ran past their deadline finish in this scope.
    private val providerCalls = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Every provider call but a write stops after 30 s; opener, saver and coordinator share it. */
    val storage: VaultStorage = DeadlineStorage(SafVaultStorage.forResolver(context, Dispatchers.IO), providerCalls)
    val opener: VaultOpening = VaultOpener.create(storage, state, Dispatchers.IO, backups, markers)

    /** The remembered vault's key file, read through [storage] for each unlock. */
    val keyFiles = KeyFileAccess(
        ResolverUriGrants(context.contentResolver), state, storage, Dispatchers.IO, VaultFileAccess.displayNameFrom(context.contentResolver),
    )

    /** Provider writes run here, so a write that outlasts the save's deadline runs to the end. */
    private val writers = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val saver: VaultSaving = SafeSaver.create(storage, backups, markers, state, Dispatchers.IO, writers)
    val saves = SaveCoordinator(sessions, saver, opener, appScope, storage, backups)

    /** The backup count and single-copy deletes for the Vault backups sheet. */
    val backupSettings = BackupSettings(state, backups, sessions) { markers.isPending(Sha256.ofLocation(it)) }

    /** Biometric unlock for the remembered vault. */
    val biometricUnlock = BiometricUnlock(unlockKeys, opener, state, sessions)
    val locker = LockController(sessions, appScope, saves = saves)
    val clipboard = SensitiveClipboard(
        clipboard = context.getSystemService(ClipboardManager::class.java),
        deadlines = ClipboardDeadlineStore(context),
        alarm = AlarmClearAlarm(context, ClipboardClearReceiver::class.java),
        scope = appScope,
        isForeground = { inForeground },
    )

    init {
        // Every lock, from any path, clears a pending clip.
        sessions.onLock = { clipboard.clearForLock() }
    }

    companion object {
        /**
         * Where backups live: noBackupFilesDir is excluded from Auto Backup and device transfer.
         */
        fun backupRoot(context: Context) = File(context.noBackupFilesDir, "backups")
    }
}

/** Returns the app's graph from any context. */
val Context.graph: AppGraph get() = (applicationContext as KashPassApp).graph
