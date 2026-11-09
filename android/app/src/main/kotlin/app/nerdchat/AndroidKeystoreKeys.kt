package app.nerdchat

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import app.nerdchat.model.PlatformKeys
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The history's epoch keys in the Android Keystore: one AES-256-GCM key per 24-hour epoch, never exportable, created in the StrongBox chip when the phone has one
 * (then deleting the key is a real erase inside secure hardware), otherwise in the TEE (best effort: the key blob is deleted, but the TEE's own root key still exists).
 * No user authentication is required: the app must be able to open its history without a prompt, and the vault password already guards everything else.
 *
 * NOT VERIFIED ON A DEVICE (written without a phone). What to check: that `wrap`/`unwrap` round-trip, that `erase` makes `unwrap` return null, and which [level] a given phone gives.
 */
class AndroidKeystoreKeys : PlatformKeys {
    /** Where the last key was created: "StrongBox", "TEE" (or "software" on an emulator). Informational. */
    @Volatile var level: String = "unknown"; private set

    private val ks: KeyStore by lazy { KeyStore.getInstance(PROVIDER).apply { load(null) } }

    private fun alias(epoch: Int) = "$PREFIX$epoch"
    private fun aad(epoch: Int) = "nerdchat.hist.epoch".toByteArray() + byteArrayOf((epoch ushr 24).toByte(), (epoch ushr 16).toByte(), (epoch ushr 8).toByte(), epoch.toByte())

    private fun create(epoch: Int): SecretKey {
        fun gen(strongBox: Boolean): SecretKey {
            val b = KeyGenParameterSpec.Builder(alias(epoch), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setRandomizedEncryptionRequired(true)
            if (strongBox) b.setIsStrongBoxBacked(true)
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).apply { init(b.build()) }.generateKey()
        }
        return try { gen(true).also { level = "StrongBox" } }
        catch (_: StrongBoxUnavailableException) { gen(false).also { level = "TEE" } }
        catch (_: Exception) { gen(false).also { level = "TEE" } } // some ROMs throw a different exception when there is no StrongBox
    }

    @Synchronized override fun wrap(epoch: Int, key: ByteArray): ByteArray? = try {
        val k = (ks.getKey(alias(epoch), null) as? SecretKey) ?: create(epoch)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, k); c.updateAAD(aad(epoch))
        byteArrayOf(1) + c.iv + c.doFinal(key)
    } catch (_: Exception) { null }

    @Synchronized override fun unwrap(epoch: Int, blob: ByteArray): ByteArray? = try {
        if (blob.size < 13 + 16 || blob[0] != 1.toByte()) null
        else {
            val k = ks.getKey(alias(epoch), null) as? SecretKey // null once erased
            if (k == null) null else {
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(128, blob.copyOfRange(1, 13))); c.updateAAD(aad(epoch))
                c.doFinal(blob, 13, blob.size - 13)
            }
        }
    } catch (_: Exception) { null }

    @Synchronized override fun erase(epoch: Int) { try { ks.deleteEntry(alias(epoch)) } catch (_: Exception) { } }

    /**
     * What the erase job does, knowing nothing about the history: destroy every epoch key more than [KEEP_EPOCHS] epochs old. A message lives at most the rest of its epoch plus
     * seven days (Rust: `ERASE_AFTER_EPOCHS`, pinned by a test), so a key this old protects nothing that may still be shown. Returns how many keys were destroyed.
     * A device clock moved far into the future destroys younger keys too: that loses history, it never exposes any.
     */
    @Synchronized fun eraseOlderThan(nowEpochSeconds: Long): Int {
        val nowEpoch = nowEpochSeconds / EPOCH_SECS
        var n = 0
        try {
            for (a in ks.aliases().toList()) {
                if (!a.startsWith(PREFIX)) continue
                val e = a.removePrefix(PREFIX).toLongOrNull()
                if (e == null || e + KEEP_EPOCHS < nowEpoch) { ks.deleteEntry(a); n++ }
            }
        } catch (_: Exception) { }
        return n
    }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val PREFIX = "nerdchat.hist."
        const val EPOCH_SECS = 86_400L
        /** mirrors `ERASE_AFTER_EPOCHS` in `crates/store/src/history.rs` */
        const val KEEP_EPOCHS = 9L
    }
}
