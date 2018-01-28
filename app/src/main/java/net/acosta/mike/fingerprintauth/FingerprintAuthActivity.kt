package net.acosta.mike.fingerprintauth

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.app.KeyguardManager
import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.widget.Toast
import android.Manifest
import android.content.pm.PackageManager
import android.support.v4.app.ActivityCompat
import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import net.acosta.mike.fingerprintdemo.FingerprintHandler

import java.security.KeyStore
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import javax.crypto.KeyGenerator
import java.security.cert.CertificateException
import java.security.InvalidAlgorithmParameterException
import java.io.IOException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.UnrecoverableKeyException

import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey
import javax.crypto.Cipher

class FingerprintAuthActivity : AppCompatActivity() {

    private var fingerprintManager: FingerprintManager? = null
    private var keyguardManager: KeyguardManager? = null
    private var keyStore: KeyStore? = null
    private var keyGenerator: KeyGenerator? = null
    private val KEY_NAME = "encryption_key"
    private var cipher: Cipher? = null
    private var cryptoObject: FingerprintManager.CryptoObject? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_fingerprint_auth)

        setManagers()
        if (isDeviceSecurityEnabled()) {
            setKeyStore()
            if (initializeCipher()) {
                cipher?.let { cryptoObject = FingerprintManager.CryptoObject(it) }
            }

            val helper = FingerprintHandler(this)
            if (fingerprintManager != null && cryptoObject != null) {
                helper.startAuth(fingerprintManager!!, cryptoObject!!)
            }
        }
    }

    private fun setManagers() {
        keyguardManager = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        fingerprintManager = getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
    }

    private fun isDeviceSecurityEnabled(): Boolean {
        if (keyguardManager?.isKeyguardSecure == false) {
            Toast.makeText(this, getString(R.string.msg_no_lock_screen_security),
                    Toast.LENGTH_LONG).show()
            return false
        }
        if (ActivityCompat.checkSelfPermission(this,
                        Manifest.permission.USE_FINGERPRINT) != PackageManager.
                        PERMISSION_GRANTED) {
            Toast.makeText(this, getString(R.string.msg_fps_auth_not_enabled),
                    Toast.LENGTH_LONG).show()
            return false
        }
        if (fingerprintManager?.hasEnrolledFingerprints() == false) {
            Toast.makeText(this, getString(R.string.msg_register),
                    Toast.LENGTH_LONG).show()
            return false
        }
        return true
    }

    private fun setKeyStore() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
        } catch (e: Exception) {
            e.printStackTrace()
        }

        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,
                    "AndroidKeyStore")
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get KeyGenerator instance", e)
        } catch (e: NoSuchProviderException) {
            throw RuntimeException("Failed to get KeyGenerator instance", e)
        }

        try {
            keyStore?.load(null)
            keyGenerator?.init(KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build())
            keyGenerator?.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        } catch (e: CertificateException) {
            throw RuntimeException(e)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }
    }

    private fun initializeCipher(): Boolean {

        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to get Cipher", e)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException("Failed to get Cipher", e)
        }

        try {
            keyStore?.load(null)
            val key = keyStore?.getKey(KEY_NAME, null) as SecretKey
            cipher?.init(Cipher.ENCRYPT_MODE, key)
            return true
        } catch (e: KeyPermanentlyInvalidatedException) {
            return false
        } catch (e: KeyStoreException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: CertificateException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: IOException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Failed to init Cipher", e)
        } catch (e: InvalidKeyException) {
            throw RuntimeException("Failed to init Cipher", e)
        }
    }
}
