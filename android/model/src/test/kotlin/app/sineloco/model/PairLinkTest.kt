package app.sineloco.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PairLinkTest {
    private val id = "a".repeat(56)

    @Test fun aTorQrCarriesLinkAndCodeAndParsesBack() {
        val qr = PairLink.torQr("sineloco:pair/$id", "123 456 7890")
        assertEquals("sineloco:pair/$id#1234567890", qr)
        assertEquals(PairLink.Tor("sineloco:pair/$id", "1234567890"), PairLink.parse(qr))
    }

    @Test fun aLinkWithoutCodeStillParsesAndCaseAndOnionSuffixAreForgiven() {
        assertEquals(PairLink.Tor("sineloco:pair/$id", null), PairLink.parse("SINELOCO:PAIR/${id.uppercase()}.ONION"))
    }

    @Test fun aLanQrParsesAndOnlyDottedQuadsWithAPortPass() {
        assertEquals(PairLink.Lan("192.168.1.5:4000", "1234567890"), PairLink.parse(PairLink.lanQr("192.168.1.5:4000", "1234567890")))
        for (bad in listOf("sineloco:lan/example.com:80", "sineloco:lan/192.168.1.5", "sineloco:lan/192.168.1.5:99999", "sineloco:lan/300.1.1.1:5", "sineloco:lan/1.2.3.4:5:6")) assertNull(PairLink.parse(bad), bad)
    }

    @Test fun anythingElseIsNotAPairLink() {
        for (bad in listOf(null, "", "https://example.org", "sineloco:pair/short", "sineloco:pair/${"1".repeat(56)}", "x".repeat(400))) assertNull(PairLink.parse(bad), bad.toString())
    }

    @Test fun aWrongLengthCodeIsDroppedNotGuessed() {
        assertEquals(PairLink.Tor("sineloco:pair/$id", null), PairLink.parse("sineloco:pair/$id#12345"))
        assertTrue(PairLink.parse("sineloco:pair/$id#12345678901")?.code == null)
    }
}
