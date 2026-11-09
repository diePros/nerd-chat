package app.sineloco

import android.app.Activity
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.os.Bundle
import android.util.Log
import java.io.ByteArrayOutputStream

/** Debug-only: runs the isolated media process on real input and logs PASS/FAIL lines under the tag MEDIASELFTEST. */
class MediaSelfTest : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Thread { run(); runOnUiThread { finish() } }.start()
    }

    private fun check(name: String, ok: Boolean, extra: String = "") = Log.i("MEDIASELFTEST", (if (ok) "PASS " else "FAIL ") + name + " " + extra)

    private fun wireRequest(mode: Int, data: ByteArray): ByteArray {
        val bb = java.nio.ByteBuffer.allocate(5 + data.size); bb.put(mode.toByte()); bb.putInt(data.size); bb.put(data); return bb.array()
    }

    private fun run() {
        val media = (application as SineLocoApp).media
        if (media == null) { check("media present", false); return }
        // a 2400 x 1600 picture with some structure
        val bmp = Bitmap.createBitmap(2400, 1600, Bitmap.Config.ARGB_8888)
        val c = Canvas(bmp); val p = Paint()
        for (i in 0 until 40) { p.color = Color.rgb(i * 6, 255 - i * 6, (i * 37) % 255); c.drawRect(i * 60f, 0f, i * 60f + 60f, 1600f, p) }
        val orig = ByteArrayOutputStream().also { bmp.compress(Bitmap.CompressFormat.JPEG, 95, it) }.toByteArray()
        Log.i("MEDIASELFTEST", "original ${orig.size} bytes")

        val t0 = System.nanoTime()
        val small = media.reencode(orig)
        check("reencode answers", small != null, "in ${(System.nanoTime() - t0) / 1_000_000} ms")
        if (small == null) return
        val o = BitmapFactory.Options().apply { inJustDecodeBounds = true }; BitmapFactory.decodeByteArray(small, 0, small.size, o)
        check("reencode is a JPEG, long edge <= 1600, <= 1.5 MB", small[0] == 0xFF.toByte() && small[1] == 0xD8.toByte() && maxOf(o.outWidth, o.outHeight) <= 1600 && small.size <= 1_500_000, "${o.outWidth}x${o.outHeight} ${small.size} bytes")

        // metadata: plant an EXIF segment and let the core's stripper (in the isolated process) remove it
        val exif = "Exif\u0000\u0000GPS-SECRET-LOCATION".toByteArray(Charsets.ISO_8859_1)
        val seg = byteArrayOf(0xFF.toByte(), 0xE1.toByte(), ((exif.size + 2) shr 8).toByte(), ((exif.size + 2) and 0xFF).toByte()) + exif
        val dirty = small.copyOfRange(0, 2) + seg + small.copyOfRange(2, small.size)
        val ans = media.clean(wireRequest(0, dirty))
        check("strip answers ok", ans != null && ans.isNotEmpty() && ans[0] == 0.toByte(), "first byte=${ans?.firstOrNull()}")
        check("planted EXIF is gone", ans != null && String(ans, Charsets.ISO_8859_1).indexOf("GPS-SECRET") < 0)
        val junk = media.clean(wireRequest(0, "%PDF-1.7 hostile".toByteArray()))
        check("a PDF is refused", junk != null && junk.isNotEmpty() && junk[0] == 1.toByte(), "first byte=${junk?.firstOrNull()}")
        val garbage = media.reencode(ByteArray(5000) { it.toByte() })
        check("garbage is not re-encoded", garbage == null)

        val view = media.decode(small)
        check("decode gives a bitmap scaled to at most 1440 px, same aspect", view != null && maxOf(view.width, view.height) <= 1440 && Math.abs(view.width.toDouble() / view.height - o.outWidth.toDouble() / o.outHeight) < 0.01, "${view?.width}x${view?.height}")
        Log.i("MEDIASELFTEST", "DONE")
    }
}
