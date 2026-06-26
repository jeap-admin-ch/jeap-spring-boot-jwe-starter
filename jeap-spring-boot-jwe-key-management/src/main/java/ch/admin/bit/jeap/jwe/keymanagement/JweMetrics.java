package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweProtocolException;

import java.time.Duration;

/**
 * Observability hook for the JWE subsystem. Implementations record the metrics the starter exposes
 * (decryption outcome and latency, response-encryption outcome, Vault refresh status). The default
 * {@link #NOOP} implementation does nothing, so the filter, refresher and key store work unchanged
 * when no metrics backend (Micrometer {@code MeterRegistry}) is present.
 *
 * <p>The interface intentionally references only JDK and {@code jwe-crypto} types so the no-op path
 * never touches Micrometer; the only Micrometer-aware implementation is {@link MicrometerJweMetrics},
 * contributed by the starter's metrics auto-configuration.
 *
 * <p>Gauges (active key versions, current key version and the governance "encryption active" signal)
 * are not recorded through this interface: {@link MicrometerJweMetrics} binds them directly to the
 * live {@link JweKeyStore} snapshot so they always reflect current state without push updates.
 */
public interface JweMetrics {

    /**
     * No-op metrics used when no {@code MeterRegistry} is available.
     */
    JweMetrics NOOP = new JweMetrics() {
    };

    /**
     * Categories of inbound request rejected <em>before</em> (or independently of) a JWE decryption
     * attempt - they never reach the crypto layer and so are not reflected in {@link #recordDecryption}.
     * Counted through {@link #recordRequestRejected(RejectionReason)}.
     */
    enum RejectionReason {
        /** The request body, or the {@code JWE-Response-Key} envelope, exceeded the maximum payload size. */
        PAYLOAD_TOO_LARGE,
        /** A body method arrived without the required {@code application/jose} encryption. */
        ENCRYPTION_REQUIRED,
        /** An encrypted response was required but the client did not accept {@code application/jose}. */
        RESPONSE_ENCRYPTION_REQUIRED,
        /** An encrypted response was required but the {@code JWE-Response-Key} header was absent. */
        RESPONSE_KEY_REQUIRED
    }

    /**
     * Records the outcome and latency of an inbound JWE decryption. Covers both the request-body
     * decryption and the {@code JWE-Response-Key} envelope unwrap (itself an RSA decryption); a failed
     * envelope unwrap is recorded here as a failure rather than going uncounted.
     *
     * @param success {@code true} if the JWE was decrypted and accepted, {@code false} on a protocol
     *                failure
     * @param reason  the failure category when {@code success} is {@code false}; {@code null} on success
     * @param elapsed the wall-clock time spent attempting the decryption
     */
    default void recordDecryption(boolean success, JweProtocolException.Reason reason, Duration elapsed) {
        // no-op
    }

    /**
     * Records an inbound request rejected before reaching (or independently of) the crypto layer - an
     * oversized payload or a missing-encryption policy violation. These are not decryption attempts, so
     * they are counted separately from {@link #recordDecryption} rather than skewing its latency series.
     */
    default void recordRequestRejected(RejectionReason reason) {
        // no-op
    }

    /**
     * Records the outcome of an outbound response encryption (only counted when encryption is actually
     * attempted, i.e. for a successful response that carries a body).
     */
    default void recordResponseEncryption(boolean success) {
        // no-op
    }

    /**
     * Records the outcome of a periodic Vault key-refresh cycle: {@code true} once a refresh has
     * successfully swapped the key snapshot, {@code false} when a cycle exhausted its retries and kept
     * the cached keys.
     */
    default void recordRefresh(boolean success) {
        // no-op
    }
}
