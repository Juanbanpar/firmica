package dev.dioxus.main

import android.content.Intent
import android.os.Bundle
import android.util.Log

typealias BuildConfig = org.firmica.client.BuildConfig

class MainActivity : WryActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Do not replay a launch intent when Android recreates the activity.
        if (savedInstanceState == null) deliver(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        deliver(intent)
    }

    private fun deliver(intent: Intent?) {
        if (intent?.action != Intent.ACTION_VIEW) return
        val uri = intent.data ?: return
        if (uri.scheme != "afirma") return
        val encoded = uri.toString()
        if (encoded.length > 65536 || !receiveInvocation(encoded)) {
            Log.w("Firmica", "External invocation rejected")
        }
    }

    private external fun receiveInvocation(uri: String): Boolean
}
