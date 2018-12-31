package net.acosta.mike.fingerprintauth

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.hardware.fingerprint.FingerprintManagerCompat
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.os.CancellationSignal

class FingerprintHandler(private val appContext: Context) : FingerprintManagerCompat.AuthenticationCallback() {

    private var cancellationSignal: CancellationSignal? = null

    fun startAuth(manager: FingerprintManagerCompat, cryptoObject: FingerprintManagerCompat.CryptoObject) {
        cancellationSignal = CancellationSignal()
        if (ActivityCompat.checkSelfPermission(appContext,
                        Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return
        }
        manager.authenticate(cryptoObject, 0, cancellationSignal, this, null)
    }

    override fun onAuthenticationError(errMsgId: Int, errString: CharSequence) {
        Toast.makeText(appContext, "Authentication error\n" + errString, Toast.LENGTH_LONG).show()
    }
    override fun onAuthenticationHelp(helpMsgId: Int, helpString: CharSequence) {
        Toast.makeText(appContext, "Authentication help\n" + helpString, Toast.LENGTH_LONG).show()
    }
    override fun onAuthenticationFailed() {
        Toast.makeText(appContext, "Authentication failed.", Toast.LENGTH_LONG).show()
    }
    override fun onAuthenticationSucceeded(
            result: FingerprintManagerCompat.AuthenticationResult) {
        Toast.makeText(appContext, "Authentication succeeded.", Toast.LENGTH_LONG).show()
    }
}