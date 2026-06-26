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
     * Records the outcome and latency of an inbound request decryption.
     *
     * @param success {@code true} if the request was decrypted and accepted, {@code false} on a
     *                protocol failure
     * @param reason  the failure category when {@code success} is {@code false}; {@code null} on success
     * @param elapsed the wall-clock time spent attempting the decryption
     */
    default void recordDecryption(boolean success, JweProtocolException.Reason reason, Duration elapsed) {
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
