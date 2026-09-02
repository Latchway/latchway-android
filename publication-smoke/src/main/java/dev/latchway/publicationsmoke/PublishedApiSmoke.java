package dev.latchway.publicationsmoke;

import com.google.firebase.auth.FirebaseAuth;
import dev.latchway.core.CoreConfiguration;
import dev.latchway.firebaseauth.FirebaseIdentityTokenProvider;
import dev.latchway.okhttp.LatchwayClient;
import dev.latchway.playintegrity.PlayIntegrityAttestationProvider;
import okhttp3.OkHttpClient;

/** Compile-time proof that all four public Android libraries are visible to an external consumer. */
public final class PublishedApiSmoke {
    private PublishedApiSmoke() {}

    public static Class<?>[] publicTypes() {
        return new Class<?>[] {
            CoreConfiguration.class,
            LatchwayClient.class,
            PlayIntegrityAttestationProvider.class,
            FirebaseIdentityTokenProvider.class,
            OkHttpClient.class,
            FirebaseAuth.class,
        };
    }

    /** Compile-time proof that the atomic OkHttp helper is available to Java consumers. */
    public static OkHttpClient buildProtectedClient(LatchwayClient client) {
        return client.buildOkHttpClient(new OkHttpClient.Builder());
    }
}
