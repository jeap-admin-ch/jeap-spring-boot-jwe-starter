package ch.admin.bit.jeap.jwe.crypto;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Security;

/**
 * Installs the Amazon Corretto Crypto Provider (ACCP) so the JWE crypto operations are accelerated by
 * it, with a transparent fallback to the JDK provider when it is unavailable — the same approach as
 * {@code jeap-crypto-core}'s {@code CryptoAdapter}.
 *
 * <p>ACCP is installed at the highest JCA priority via {@link AmazonCorrettoCryptoProvider#install()}
 * and its native self-test is checked with {@link AmazonCorrettoCryptoProvider#assertHealthy()}.
 * Because the JWE crypto runs through Nimbus (which resolves ciphers via the default JCA provider
 * order rather than a pinned provider), installing ACCP at top priority is enough for it to be used
 * for the RSA-OAEP and AES-GCM operations it supports, while operations it does not provide (e.g. the
 * {@code OAEP} {@code AlgorithmParameters}) fall back to the JDK provider automatically.
 *
 * <p>If the native library is missing or the self-test fails, the provider is <strong>removed</strong>
 * again so an unhealthy ACCP can never be preferred, the failure is logged, and
 * {@link #isCorrettoEnabled()} stays {@code false}: the JDK provider then handles everything.
 */
public final class JweCryptoProvider {

    private static final Logger log = LoggerFactory.getLogger(JweCryptoProvider.class);

    private static final boolean CORRETTO_ENABLED;

    static {
        AmazonCorrettoCryptoProvider.install();
        boolean enabled;
        try {
            AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
            enabled = true;
            log.info("Amazon Corretto Crypto Provider installed at top priority and healthy; "
                    + "using it for JWE crypto where supported.");
        } catch (Exception e) {
            // Remove the unhealthy provider so JCA resolution falls back cleanly to the JDK provider.
            Security.removeProvider(AmazonCorrettoCryptoProvider.PROVIDER_NAME);
            // Logged at WARN without the stack trace: the JDK fallback is a fully supported path (e.g. on
            // platforms without a shipped native library), so this is an optimisation notice, not an error.
            log.warn("Native Amazon Corretto Crypto Provider is not available on this platform ({}); "
                            + "removed it and falling back to the JDK provider. Crypto performance will not be optimized.",
                    e.getMessage());
            enabled = false;
        }
        CORRETTO_ENABLED = enabled;
    }

    private JweCryptoProvider() {
    }

    /**
     * @return {@code true} if ACCP is installed and passed its self-test, so it is used for crypto;
     * {@code false} if the JWE crypto runs on the JDK provider instead.
     */
    public static boolean isCorrettoEnabled() {
        return CORRETTO_ENABLED;
    }

    /**
     * Ensures the crypto provider has been installed. Idempotent and cheap: referencing this method
     * triggers the one-time static installation. The starter calls it during application startup so
     * the native-library load and self-test do not delay the first JWE crypto operation, which also
     * calls it defensively for non-starter usages of this module.
     */
    public static void ensureInstalled() {
        // no-op: the work happens in the static initializer the first time this class is loaded.
    }
}
