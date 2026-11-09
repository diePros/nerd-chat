package app.sineloco.clean

import android.app.Service
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * Everything that parses an image from outside runs HERE, in an `isolatedProcess` service (declared in the manifest): no permissions, no network, no access to the app's files, its own
 * UID and the system's seccomp policy. The process holds no key and no message. The caller ([MediaProcess]) hands the data over through a pipe (a Binder transaction is limited to 1 MB),
 * reads the answer from another pipe and then lets the process die: every job gets a fresh process.
 *
 * Jobs: [OP_STRIP] (the core's metadata stripper for a file that ARRIVED), [OP_REENCODE] (the sender's photo: decode, apply the rotation, scale down, re-encode as JPEG: nothing of the
 * camera's metadata or quantisation tables survives), [OP_DECODE] (a received photo to raw pixels for the screen, so that the main process needs no image decoder at all).
 * A failure of any kind = an EMPTY answer. The caller treats it as "refused".
 */
class CleanerService : Service() {
    private val messenger = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(m: Message) {
            val b = m.data.apply { classLoader = ParcelFileDescriptor::class.java.classLoader }
            @Suppress("DEPRECATION") val input = b.getParcelable<ParcelFileDescriptor>("in")
            @Suppress("DEPRECATION") val output = b.getParcelable<ParcelFileDescriptor>("out")
            if (input == null || output == null) { input?.close(); output?.close(); return }
            val op = m.what
            Thread { job(op, input, output) }.start()
        }
    })

    override fun onBind(intent: Intent?): IBinder = messenger.binder

    /** A fresh process for every job: when the caller unbinds, this process ends (nothing of the last image stays in memory). */
    override fun onDestroy() { super.onDestroy(); android.os.Process.killProcess(android.os.Process.myPid()) }

    private fun job(op: Int, input: ParcelFileDescriptor, output: ParcelFileDescriptor) {
        var result: ByteArray? = null
        try {
            val data = ParcelFileDescriptor.AutoCloseInputStream(input).use { s -> readCapped(s, MAX_IN) }
            result = if (data == null) null else when (op) {
                OP_STRIP -> { CleanerNative.load(); CleanerNative.nClean(data) }
                OP_REENCODE -> reencode(data)
                OP_DECODE -> decode(data)
                else -> null
            }
            data?.fill(0)
        } catch (_: Throwable) { result = null }
        try { ParcelFileDescriptor.AutoCloseOutputStream(output).use { o -> if (result != null) o.write(result) } } catch (_: Throwable) { }
        result?.fill(0)
    }

    private fun readCapped(s: java.io.InputStream, cap: Int): ByteArray? {
        val out = ByteArrayOutputStream(1 shl 16); val buf = ByteArray(1 shl 16); var total = 0
        while (true) { val n = s.read(buf); if (n < 0) break; total += n; if (total > cap) return null; out.write(buf, 0, n) }
        return out.toByteArray()
    }

    /** Decode with the system's decoder (which also applies the EXIF rotation), never bigger than [edge] on the long side, software memory only. */
    private fun decodeScaled(data: ByteArray, edge: Int): Bitmap? = try {
        ImageDecoder.decodeBitmap(ImageDecoder.createSource(ByteBuffer.wrap(data))) { d, info, _ ->
            val w = info.size.width; val h = info.size.height
            if (w <= 0 || h <= 0 || w.toLong() * h > MAX_PIXELS) throw IllegalArgumentException("too many pixels")
            val k = minOf(1.0, edge.toDouble() / maxOf(w, h))
            d.setTargetSize(maxOf(1, (w * k).toInt()), maxOf(1, (h * k).toInt()))
            d.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            d.isMutableRequired = false
        }
    } catch (_: Throwable) { null }

    private fun reencode(data: ByteArray): ByteArray? {
        val bmp = decodeScaled(data, PHOTO_EDGE) ?: return null
        try {
            for (q in intArrayOf(80, 65, 50)) {
                val out = ByteArrayOutputStream(1 shl 18)
                if (!bmp.compress(Bitmap.CompressFormat.JPEG, q, out)) return null
                if (out.size() <= PHOTO_MAX) return out.toByteArray()
            }
            return null
        } finally { bmp.recycle() }
    }

    /** `width(4) height(4)` big-endian, then width*height ARGB_8888 pixels in the bitmap's own byte order. */
    private fun decode(data: ByteArray): ByteArray? {
        val bmp = decodeScaled(data, VIEW_EDGE) ?: return null
        try {
            val w = bmp.width; val h = bmp.height
            val buf = ByteBuffer.allocate(8 + w * h * 4)
            buf.putInt(w).putInt(h)
            val bmp32 = if (bmp.config == Bitmap.Config.ARGB_8888) bmp else bmp.copy(Bitmap.Config.ARGB_8888, false) ?: return null
            bmp32.copyPixelsToBuffer(buf)
            if (bmp32 !== bmp) bmp32.recycle()
            return buf.array()
        } finally { bmp.recycle() }
    }

    companion object {
        const val OP_STRIP = 1
        const val OP_REENCODE = 2
        const val OP_DECODE = 3
        /** the most the process reads (an 8 MiB file plus the frame, or a camera original) */
        const val MAX_IN = 32 * 1024 * 1024
        /** refuse images with more pixels than this before allocating them (about 100 megapixels) */
        const val MAX_PIXELS = 100_000_000L
        /** a sent photo: long edge and size cap (the core accepts 4 MiB from the phone, Tor is slow: a few hundred KiB is the aim) */
        const val PHOTO_EDGE = 1600
        const val PHOTO_MAX = 1_500_000
        /** a received photo on screen */
        const val VIEW_EDGE = 1440
    }
}
