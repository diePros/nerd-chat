package app.sineloco

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.graphics.Bitmap
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import app.sineloco.clean.CleanerService
import app.sineloco.model.MediaCleaner
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * The client of [CleanerService]: hands one job to a FRESH isolated process, waits (bounded) and returns its answer, or null on any failure. One job at a time. Never call from the
 * main thread. There is no fallback: when the isolated process cannot be started or does not answer, the caller refuses the file; nothing is ever parsed in this process.
 */
class MediaProcess(private val context: Context) : MediaCleaner {
    private val lock = Any()
    private val pool = Executors.newCachedThreadPool { Thread(it, "sineloco-media-io").apply { isDaemon = true } }

    /** The core's request frame for a file that arrived (called from the core's threads through JNI). */
    override fun clean(request: ByteArray): ByteArray? = run(CleanerService.OP_STRIP, request, CleanerService.MAX_IN, STRIP_TIMEOUT_MS)

    /** A picked photo -> a small JPEG without metadata (null: unreadable, too large or too many pixels). */
    fun reencode(photo: ByteArray): ByteArray? = run(CleanerService.OP_REENCODE, photo, CleanerService.PHOTO_MAX, REENCODE_TIMEOUT_MS)

    /** A received (already cleaned) photo -> a bitmap for the screen. The pixels come back raw: this process has no image decoder in the path. */
    fun decode(image: ByteArray): Bitmap? {
        val raw = run(CleanerService.OP_DECODE, image, 8 + 1440 * 1440 * 4, REENCODE_TIMEOUT_MS) ?: return null
        try {
            val bb = ByteBuffer.wrap(raw)
            if (raw.size < 8) return null
            val w = bb.int; val h = bb.int
            if (w <= 0 || h <= 0 || w > 4096 || h > 4096 || raw.size.toLong() != 8L + w.toLong() * h * 4) return null // a lying answer is dropped
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            bmp.copyPixelsFromBuffer(bb)
            return bmp
        } finally { raw.fill(0) }
    }

    private fun run(op: Int, input: ByteArray, maxOut: Int, timeoutMs: Long): ByteArray? {
        check(Looper.myLooper() != Looper.getMainLooper()) { "media work never runs on the main thread" }
        synchronized(lock) {
            val bound = CountDownLatch(1)
            var binder: IBinder? = null
            val conn = object : ServiceConnection {
                override fun onServiceConnected(n: ComponentName?, b: IBinder?) { binder = b; bound.countDown() }
                override fun onServiceDisconnected(n: ComponentName?) {}
                override fun onNullBinding(n: ComponentName?) { bound.countDown() }
            }
            val ok = try { context.bindService(Intent(context, CleanerService::class.java), conn, Context.BIND_AUTO_CREATE) } catch (_: Exception) { false }
            if (!ok) return null
            try {
                if (!bound.await(START_TIMEOUT_MS, TimeUnit.MILLISECONDS)) return null
                val b = binder ?: return null
                val inPipe = ParcelFileDescriptor.createPipe(); val outPipe = ParcelFileDescriptor.createPipe()
                val msg = Message.obtain(null, op).apply { data = android.os.Bundle().apply { putParcelable("in", inPipe[0]); putParcelable("out", outPipe[1]) } }
                try { Messenger(b).send(msg) } catch (_: Exception) { inPipe.forEach { it.close() }; outPipe.forEach { it.close() }; return null }
                inPipe[0].close(); outPipe[1].close() // the service holds its own copies now
                val writer = pool.submit { try { ParcelFileDescriptor.AutoCloseOutputStream(inPipe[1]).use { it.write(input) } } catch (_: Exception) { } }
                val reader = pool.submit<ByteArray?> {
                    try {
                        ParcelFileDescriptor.AutoCloseInputStream(outPipe[0]).use { s ->
                            val out = java.io.ByteArrayOutputStream(1 shl 16); val buf = ByteArray(1 shl 16); var total = 0
                            while (true) { val n = s.read(buf); if (n < 0) break; total += n; if (total > maxOut + 8192) return@submit null; out.write(buf, 0, n) }
                            out.toByteArray().takeIf { it.isNotEmpty() }
                        }
                    } catch (_: Exception) { null }
                }
                return try { reader.get(timeoutMs, TimeUnit.MILLISECONDS) } catch (_: Exception) { reader.cancel(true); writer.cancel(true); null }
            } finally {
                try { context.unbindService(conn) } catch (_: Exception) { } // the service ends its process in onDestroy
            }
        }
    }

    companion object {
        const val START_TIMEOUT_MS = 10_000L
        const val STRIP_TIMEOUT_MS = 30_000L
        const val REENCODE_TIMEOUT_MS = 30_000L
    }
}
