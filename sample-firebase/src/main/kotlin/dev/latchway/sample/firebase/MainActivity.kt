package dev.latchway.sample.firebase

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import com.google.firebase.FirebaseApp
import com.google.firebase.auth.FirebaseAuth
import dev.latchway.firebaseauth.FirebaseIdentityTokenProvider

public class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val state = when {
            FirebaseApp.getApps(this).isEmpty() ->
                "Firebase is not configured. Add this sample to your Firebase Android app before running it."
            FirebaseAuth.getInstance().currentUser == null ->
                "Firebase is configured. Sign in through your application's normal authentication flow first."
            else -> {
                FirebaseIdentityTokenProvider()
                "Firebase user is ready. Pass FirebaseIdentityTokenProvider to LatchwayClient with your gateway configuration."
            }
        }
        setContentView(TextView(this).apply {
            textSize = 18f
            setPadding(48, 48, 48, 48)
            text = "Latchway Firebase sample\n\n$state"
        })
    }
}
