package app.sineloco.ui

import app.sineloco.model.PairLink
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.EncodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlin.test.Test
import kotlin.test.assertEquals

/** The QR code must decode to EXACTLY the pairing text and that text must parse back: an encoder that drew a pretty but unreadable picture would pass every screenshot test. */
class QrRoundTripTest {
    private fun roundTrip(text: String): String {
        // the same encoder settings as QrCode()
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 2))
        val scale = 4
        val w = m.width * scale; val h = m.height * scale
        val px = IntArray(w * h) { i -> if (m.get((i % w) / scale, (i / w) / scale)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
        return QRCodeReader().decode(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(w, h, px)))).text
    }

    @Test fun aTorPairingQrDecodesToTheLinkAndCodeAndParsesBack() {
        val id = "mxqfz3k7ayv2wbn5cdr4eh6jg2tup7lis3o5kqwn4yz6ahbvc3dfe6xi"
        val text = PairLink.torQr("sineloco:pair/$id", "4821-7390-52")
        assertEquals(text, roundTrip(text))
        assertEquals(PairLink.Tor("sineloco:pair/$id", "4821739052"), PairLink.parse(roundTrip(text)))
    }

    @Test fun aLanPairingQrDecodesToTheAddressAndCode() {
        val text = PairLink.lanQr("192.168.1.5:40123", "4821739052")
        assertEquals(PairLink.Lan("192.168.1.5:40123", "4821739052"), PairLink.parse(roundTrip(text)))
    }
}
