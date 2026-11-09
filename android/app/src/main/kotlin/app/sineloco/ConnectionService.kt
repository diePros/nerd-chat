package app.sineloco

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.IBinder

/**
 * Keeps the app (and the tor process it started) alive and at foreground priority while the user wants to be reachable. Without it Android freezes or kills a background
 * app within minutes and no message could arrive. It contains NO logic: the core runs in the app process as before; this service only holds the process priority and shows ONE
 * generic notification (Android requires it): no contact, no message, hidden on the lock screen.
 *
 * Lifecycle (see [SineLocoApp.watchConnection]): started when the user is online with an unlocked vault, stopped when they go offline, panic or purge. Swiping the app out of
 * the recent-apps list ends everything: RAM wiped, tor stopped (the safe default for this threat model; a setting may relax it later).
 *
 * Foreground service type `remoteMessaging` (Android 14+): the type Android defines for "transfer text messages between devices". NOT VERIFIED on a stock Android 14+ phone.
 */
class ConnectionService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val app = application as SineLocoApp
        if (intent?.action == ACTION_OFFLINE) {
            // only ASK: the core refuses while tor is still starting (it cannot be cancelled yet) and asks for confirmation when texts are unconfirmed. The service ends when the
            // state really says offline ([SineLocoApp.watchConnection]), never before. If the core did not go offline, the reason (and the confirmation) is in the app: open it.
            app.backend.setOnline(false)
            Handler(Looper.getMainLooper()).postDelayed({
                if (app.backend.state.value.online) {
                    try { startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)) } catch (_: Exception) { }
                }
            }, 1200)
            return START_NOT_STICKY
        }
        try {
            val n = notification()
            if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
            else startForeground(NOTIFICATION_ID, n)
        } catch (_: Exception) {
            // Android refused (started from the background, or the permission is missing): the app simply behaves as before, reachable while it is in front
            stopSelf()
        }
        return START_NOT_STICKY // never restart by itself: a restarted process has a locked vault and nothing to keep alive
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // swiped away from the recent apps: the same end of the session as everywhere else (wipe, then die)
        stopForegroundCompat()
        (application as SineLocoApp).wipeAndExit()
    }

    private fun stopForegroundCompat() = stopForeground(STOP_FOREGROUND_REMOVE)

    private fun notification(): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(CHANNEL_ID, getString(R.string.channel_name), NotificationManager.IMPORTANCE_LOW).apply {
            description = getString(R.string.channel_description)
            lockscreenVisibility = Notification.VISIBILITY_SECRET
            setShowBadge(false)
            setSound(null, null)
            enableVibration(false)
        }
        nm.createNotificationChannel(channel)
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), PendingIntent.FLAG_IMMUTABLE)
        val offline = PendingIntent.getService(this, 1, Intent(this, ConnectionService::class.java).setAction(ACTION_OFFLINE), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_connected)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setVisibility(Notification.VISIBILITY_SECRET)
            .setOngoing(true).setOnlyAlertOnce(true).setShowWhen(false)
            .setLocalOnly(true) // never bridged to a paired watch or a companion app
            .setCategory(Notification.CATEGORY_SERVICE)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(null, getString(R.string.notification_go_offline), offline).build())
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "connection"
        private const val NOTIFICATION_ID = 1
        const val ACTION_OFFLINE = "app.sineloco.OFFLINE"

        fun start(c: Context) {
            try { c.startForegroundService(Intent(c, ConnectionService::class.java)) } catch (_: Exception) { /* not allowed from the background */ }
        }
        fun stop(c: Context) { try { c.stopService(Intent(c, ConnectionService::class.java)) } catch (_: Exception) { } }
    }
}
