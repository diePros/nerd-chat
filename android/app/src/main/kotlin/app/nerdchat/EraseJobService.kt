package app.nerdchat

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context

/**
 * Destroys expired history keys even when the app is not running and the phone is locked (without it, "deleted after a day" would only happen when the user opens the app).
 * It needs neither the vault password nor the Rust core: [AndroidKeystoreKeys.eraseOlderThan] works from the key names alone. Runs about every 6 hours and after a reboot.
 * NOT VERIFIED ON A DEVICE: Doze and vendor battery managers may delay it by hours; the app also runs the same erase at every start.
 */
class EraseJobService : JobService() {
    override fun onStartJob(params: JobParameters?): Boolean {
        AndroidKeystoreKeys().eraseOlderThan(System.currentTimeMillis() / 1000)
        return false // done, nothing in the background
    }
    override fun onStopJob(params: JobParameters?): Boolean = true // run again at the next period

    companion object {
        private const val JOB_ID = 4711
        fun schedule(c: Context) {
            try {
                val js = c.getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler
                if (js.getPendingJob(JOB_ID) != null) return
                js.schedule(JobInfo.Builder(JOB_ID, ComponentName(c, EraseJobService::class.java)).setPeriodic(6 * 3600_000L).setPersisted(true).build())
            } catch (_: Exception) { } // no permission or no scheduler: the erase at every app start remains
        }
    }
}
