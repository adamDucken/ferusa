package com.plugin.keystore

import android.app.Activity
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.webkit.WebView
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class SecretKeyPayload {
    lateinit var key: String
}

@InvokeArg
class SetSecretPayload {
    lateinit var key: String
    lateinit var value: String
}

@InvokeArg
class ApprovalKeyPayload {
    lateinit var alias: String
}

@InvokeArg
class SignApprovalPayload {
    lateinit var alias: String
    lateinit var payloadHex: String
}

@TauriPlugin
class KeystorePlugin(private val activity: Activity) : Plugin(activity) {
    private val approvalKeyAuthValiditySeconds = 120
    private var webView: WebView? = null

    override fun load(webView: WebView) {
        this.webView = webView
    }

    override fun onStop() {
        webView?.post {
            webView?.evaluateJavascript(
                "document.dispatchEvent(new Event('visibilitychange'))",
                null
            )
        }
    }

    private val sharedPrefs by lazy {
        val masterKey = MasterKey.Builder(activity)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            activity,
            "ferusa_secure_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "hex length must be even" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun unsignedFixed32(value: java.math.BigInteger): ByteArray {
        val raw = value.toByteArray()
        val unsigned = if (raw.isNotEmpty() && raw[0].toInt() == 0) raw.copyOfRange(1, raw.size) else raw
        require(unsigned.size <= 32) { "EC coordinate too large" }
        return ByteArray(32 - unsigned.size) + unsigned
    }

    private fun ecPublicPoint(publicKey: ECPublicKey): ByteArray =
        byteArrayOf(0x04.toByte()) +
            unsignedFixed32(publicKey.w.affineX) +
            unsignedFixed32(publicKey.w.affineY)

    @Command
    fun clockSnapshot(invoke: Invoke) {
        try {
            val ret = JSObject()
            ret.put("elapsedRealtimeMs", SystemClock.elapsedRealtime())
            ret.put(
                "bootCount",
                Settings.Global.getInt(activity.contentResolver, Settings.Global.BOOT_COUNT)
            )
            invoke.resolve(ret)
        } catch (e: Exception) {
            invoke.reject("Android clock snapshot error: ${e.message}")
        }
    }

    @Command
    fun getSecret(invoke: Invoke) {
        try {
            val payload = invoke.parseArgs(SecretKeyPayload::class.java)
            val ret = JSObject()
            ret.put("value", sharedPrefs.getString(payload.key, null))
            invoke.resolve(ret)
        } catch (e: Exception) {
            invoke.reject("Android Keystore getSecret error: ${e.message}")
        }
    }

    @Command
    fun setSecret(invoke: Invoke) {
        try {
            val payload = invoke.parseArgs(SetSecretPayload::class.java)
            if (!sharedPrefs.edit().putString(payload.key, payload.value).commit()) {
                invoke.reject("Android Keystore setSecret error: commit failed")
                return
            }
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject("Android Keystore setSecret error: ${e.message}")
        }
    }

    @Command
    fun deleteSecret(invoke: Invoke) {
        try {
            val payload = invoke.parseArgs(SecretKeyPayload::class.java)
            if (!sharedPrefs.edit().remove(payload.key).commit()) {
                invoke.reject("Android Keystore deleteSecret error: commit failed")
                return
            }
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject("Android Keystore deleteSecret error: ${e.message}")
        }
    }

    @Command
    fun clearSecrets(invoke: Invoke) {
        try {
            if (!sharedPrefs.edit().clear().commit()) {
                invoke.reject("Android Keystore clearSecrets error: commit failed")
                return
            }
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject("Android Keystore clearSecrets error: ${e.message}")
        }
    }

    @Command
    fun generateApprovalKey(invoke: Invoke) {
        try {
            val payload = invoke.parseArgs(ApprovalKeyPayload::class.java)
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (keyStore.containsAlias(payload.alias)) {
                keyStore.deleteEntry(payload.alias)
            }

            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            val spec = KeyGenParameterSpec.Builder(
                payload.alias,
                KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                spec.setUserAuthenticationParameters(
                    approvalKeyAuthValiditySeconds,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            } else {
                @Suppress("DEPRECATION")
                spec.setUserAuthenticationValidityDurationSeconds(approvalKeyAuthValiditySeconds)
            }

            generator.initialize(spec.build())
            val pair = generator.generateKeyPair()
            val ret = JSObject()
            ret.put("value", bytesToHex(ecPublicPoint(pair.public as ECPublicKey)))
            invoke.resolve(ret)
        } catch (e: Exception) {
            invoke.reject("Android Keystore generateApprovalKey error: ${e.message}")
        }
    }

    @Command
    fun signApproval(invoke: Invoke) {
        try {
            val payload = invoke.parseArgs(SignApprovalPayload::class.java)
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val privateKey = keyStore.getKey(payload.alias, null)
                ?: throw IllegalStateException("approval key not found")
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(privateKey as java.security.PrivateKey)
            sig.update(hexToBytes(payload.payloadHex))
            val ret = JSObject()
            ret.put("value", bytesToHex(sig.sign()))
            invoke.resolve(ret)
        } catch (e: UserNotAuthenticatedException) {
            invoke.reject("Android Keystore signApproval error: approval key authentication required or expired")
        } catch (e: Exception) {
            invoke.reject("Android Keystore signApproval error: ${e.message}")
        }
    }

    @Command
    fun deleteApprovalKey(invoke: Invoke) {
        try {
            val payload = invoke.parseArgs(ApprovalKeyPayload::class.java)
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (keyStore.containsAlias(payload.alias)) {
                keyStore.deleteEntry(payload.alias)
            }
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject("Android Keystore deleteApprovalKey error: ${e.message}")
        }
    }
}
