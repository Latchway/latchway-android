package dev.latchway.sample.basic

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import dev.latchway.core.AttestationProvider
import dev.latchway.core.IdentityTokenProvider
import dev.latchway.okhttp.LatchwayClient
import dev.latchway.okhttp.LatchwayConfiguration
import okhttp3.HttpUrl

public class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            textSize = 18f
            setPadding(48, 48, 48, 48)
            text = "Latchway basic sample\n\nUse BasicLatchwayFactory with your app's existing " +
                "identity-token provider and the attestation adapter required by your server policy. " +
                "No credentials or synthetic attestation are bundled in this sample."
        })
    }
}

public object BasicLatchwayFactory {
    public fun create(
        activity: Activity,
        gateway: HttpUrl,
        applicationId: String,
        environment: String,
        identityTokenProvider: IdentityTokenProvider,
        attestationProvider: AttestationProvider,
    ): LatchwayClient = LatchwayClient(
        configuration = LatchwayConfiguration(gateway, applicationId, environment),
        identityTokenProvider = identityTokenProvider,
        attestationProvider = attestationProvider,
        context = activity,
    )
}
