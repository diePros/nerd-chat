package app.sineloco.model

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The deletable key store behind the message history (Rust: `sine_loco_store::history::PlatformKeys`; called from the core through JNI BY NAME:
 * the method names and signatures are fixed, the R8 rules keep them). The history encrypts every 6-hour bucket of messages under its own random key and asks
 * this object to protect that key under a key of its 24-hour EPOCH. Destroying the epoch key (`erase`) is what makes old messages unreadable even if the file is copied.
 *
 *  * `wrap` returns a blob that only this key store can open again, or null if it could not (the history then writes nothing and retries);
 *  * `unwrap` returns the 32 bytes; null if the epoch key is gone (erased) or the blob is not ours (the bucket is then lost for good); an EMPTY array if the key store
 *    could not answer right now (error, busy): the core then refuses to open the history and leaves the file untouched, instead of concluding anything;
 *  * `erase` destroys the epoch key for good.
 */
interface PlatformKeys {
    fun wrap(epoch: Int, key: ByteArray): ByteArray?
    fun unwrap(epoch: Int, blob: ByteArray): ByteArray?
    fun erase(epoch: Int)
}

/** Optional: a key store that wants to know the history setting the user chose (called whenever the unlocked app reports it). Separate from [PlatformKeys], whose method set is the fixed JNI contract. */
interface HistoryModeListener {
    fun modeChanged(persist: Persist)
}

/**
 * Epoch keys in memory (tests and the demo): same format as the phone's key store (version byte, 12-byte IV, AES-256-GCM, the epoch as associated data),
 * but nothing survives the process, so a vault written with it cannot be read after a restart of the JVM. NOT for production.
 */
class SoftwareKeys : PlatformKeys {
    private val keys = HashMap<Int, ByteArray>()
    val erased = ArrayList<Int>()
    var wraps = 0; private set
    var unwraps = 0; private set
    private val rnd = SecureRandom()

    private fun aad(epoch: Int) = "sineloco.hist.epoch".toByteArray() + byteArrayOf((epoch ushr 24).toByte(), (epoch ushr 16).toByte(), (epoch ushr 8).toByte(), epoch.toByte())

    @Synchronized override fun wrap(epoch: Int, key: ByteArray): ByteArray? {
        wraps++
        val k = keys.getOrPut(epoch) { ByteArray(32).also(rnd::nextBytes) }
        val iv = ByteArray(12).also(rnd::nextBytes)
        val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, iv)); c.updateAAD(aad(epoch))
        return byteArrayOf(1) + iv + c.doFinal(key)
    }

    @Synchronized override fun unwrap(epoch: Int, blob: ByteArray): ByteArray? {
        unwraps++
        val k = keys[epoch] ?: return null
        if (blob.size < 13 + 16 || blob[0] != 1.toByte()) return null
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, blob.copyOfRange(1, 13))); c.updateAAD(aad(epoch))
            c.doFinal(blob, 13, blob.size - 13)
        } catch (_: Exception) { null }
    }

    @Synchronized override fun erase(epoch: Int) { keys.remove(epoch)?.fill(0); erased += epoch }
    @Synchronized fun has(epoch: Int) = keys.containsKey(epoch)
}
