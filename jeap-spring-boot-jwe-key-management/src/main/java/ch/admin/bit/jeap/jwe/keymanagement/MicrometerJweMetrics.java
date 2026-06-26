package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweProtocolException;
import com.nimbusds.jose.jwk.RSAKey;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Micrometer-backed {@link JweMetrics}. Registers the JWE meters under the {@code jeap.jwe.*} prefix
 * against the application's {@link MeterRegistry}, so they are exported through whatever registry the
 * service configures (Prometheus, OpenTelemetry, ...).
 *
 * <p>Meters (Prometheus names in parentheses):
 * <ul>
 *   <li>{@code jeap.jwe.decryption} - {@link Timer} with a percentile histogram, tagged
 *   {@code result}=success|failure and {@code reason}; carries both the success/failure counts and the
 *   decryption latency distribution ({@code jeap_jwe_decryption_seconds_*}). Covers the request body and
 *   the {@code JWE-Response-Key} envelope unwrap.</li>
 *   <li>{@code jeap.jwe.request.rejected} - {@link Counter} tagged {@code reason}, inbound requests
 *   rejected before the crypto layer (size or policy guard) ({@code jeap_jwe_request_rejected_total}).</li>
 *   <li>{@code jeap.jwe.response.encryption} - {@link Counter} tagged {@code result}
 *   ({@code jeap_jwe_response_encryption_total}).</li>
 *   <li>{@code jeap.jwe.key.refresh} - {@link Counter} tagged {@code result}
 *   ({@code jeap_jwe_key_refresh_total}).</li>
 *   <li>{@code jeap.jwe.key.refresh.timestamp} - {@link Gauge}, epoch seconds of the last successful
 *   refresh; seeded at startup from the initial key load and then updated on each successful periodic
 *   refresh ({@code jeap_jwe_key_refresh_timestamp_seconds}).</li>
 *   <li>{@code jeap.jwe.keys.active} - {@link Gauge}, number of active key versions
 *   ({@code jeap_jwe_keys_active}).</li>
 *   <li>{@code jeap.jwe.keys.current.version} - {@link Gauge}, version of the current encryption key,
 *   {@code 0} when none ({@code jeap_jwe_keys_current_version}).</li>
 *   <li>{@code jeap.jwe.encryption.active} - {@link Gauge}, governance signal: {@code 1} iff JWE is
 *   enabled, both request and response encryption are enforced, and at least one key is loaded; else
 *   {@code 0} ({@code jeap_jwe_encryption_active}).</li>
 * </ul>
 *
 * <p>All tags are enum- or boolean-bounded; no per-request or per-path tags are emitted, keeping the
 * cardinality low.
 */
public class MicrometerJweMetrics implements JweMetrics {

    private static final String METRIC_DECRYPTION = "jeap.jwe.decryption";
    private static final String METRIC_REQUEST_REJECTED = "jeap.jwe.request.rejected";
    private static final String METRIC_RESPONSE_ENCRYPTION = "jeap.jwe.response.encryption";
    private static final String METRIC_KEY_REFRESH = "jeap.jwe.key.refresh";

    private static final String RESULT = "result";
    private static final String SUCCESS = "success";
    private static final String FAILURE = "failure";
    private static final String REASON = "reason";
    private static final String NONE = "none";

    private final MeterRegistry registry;
    private final AtomicLong lastRefreshSuccessEpochSeconds = new AtomicLong(0);
    // Meters are cached and registered once, not rebuilt on every record() call. The decryption timers
    // are keyed by their result/reason tag combination (bounded by the JweProtocolException reasons).
    private final ConcurrentMap<String, Timer> decryptionTimers = new ConcurrentHashMap<>();
    // Request-rejection counters, keyed by reason (bounded by the RejectionReason enum).
    private final ConcurrentMap<RejectionReason, Counter> rejectionCounters = new ConcurrentHashMap<>();
    private final Counter responseEncryptionSuccess;
    private final Counter responseEncryptionFailure;
    private final Counter refreshSuccess;
    private final Counter refreshFailure;

    public MicrometerJweMetrics(MeterRegistry registry, JweKeyStore keyStore,
                                boolean requireEncryptedRequest, boolean requireEncryptedResponse) {
        this.registry = registry;

        // The startup key load runs (and fails fast) before this bean is created, so a present key means
        // the keys are fresh as of startup. Seed the last-success timestamp accordingly; otherwise the
        // gauge would read 0 until the first periodic refresh and a staleness alert would fire falsely for
        // up to one refresh interval after every restart/deploy.
        if (keyStore.currentEncryptionKey().isPresent()) {
            lastRefreshSuccessEpochSeconds.set(System.currentTimeMillis() / 1000L);
        }

        this.responseEncryptionSuccess = responseEncryptionCounter(SUCCESS);
        this.responseEncryptionFailure = responseEncryptionCounter(FAILURE);
        this.refreshSuccess = refreshCounter(SUCCESS);
        this.refreshFailure = refreshCounter(FAILURE);

        Gauge.builder("jeap.jwe.keys.active", keyStore, store -> store.activeKeys().size())
                .description("Number of active JWE key versions accepted for decryption")
                .register(registry);

        Gauge.builder("jeap.jwe.keys.current.version", keyStore, MicrometerJweMetrics::currentKeyVersion)
                .description("Version of the current JWE encryption key (newest active version), 0 if none")
                .register(registry);

        Gauge.builder("jeap.jwe.key.refresh.timestamp", lastRefreshSuccessEpochSeconds, AtomicLong::get)
                .description("Epoch seconds of the last successful Vault key refresh; seeded from the startup key load")
                .baseUnit("seconds")
                .register(registry);

        // Governance signal: end-to-end encryption is only "active" when enforcement is on for both
        // directions and at least one key is loaded. Captures the enforcement flags once (they are
        // fixed for the lifetime of the context) and reads key availability live.
        boolean enforced = requireEncryptedRequest && requireEncryptedResponse;
        Gauge.builder("jeap.jwe.encryption.active", keyStore,
                        store -> enforced && store.currentEncryptionKey().isPresent() ? 1.0 : 0.0)
                .description("1 if JWE end-to-end encryption is enforced (request+response) and keyed, else 0")
                .register(registry);
    }

    @Override
    public void recordDecryption(boolean success, JweProtocolException.Reason reason, Duration elapsed) {
        String resultTag = success ? SUCCESS : FAILURE;
        String reasonTag = success || reason == null ? NONE : reason.name().toLowerCase(Locale.ROOT);
        decryptionTimers.computeIfAbsent(resultTag + '/' + reasonTag,
                        key -> Timer.builder(METRIC_DECRYPTION)
                                .description("JWE request decryption outcome and latency")
                                .tag(RESULT, resultTag)
                                .tag(REASON, reasonTag)
                                .publishPercentileHistogram()
                                .register(registry))
                .record(elapsed);
    }

    @Override
    public void recordRequestRejected(RejectionReason reason) {
        rejectionCounters.computeIfAbsent(reason,
                        r -> Counter.builder(METRIC_REQUEST_REJECTED)
                                .description("Inbound JWE request rejected before the crypto layer (size or policy guard)")
                                .tag(REASON, r.name().toLowerCase(Locale.ROOT))
                                .register(registry))
                .increment();
    }

    @Override
    public void recordResponseEncryption(boolean success) {
        (success ? responseEncryptionSuccess : responseEncryptionFailure).increment();
    }

    @Override
    public void recordRefresh(boolean success) {
        if (success) {
            lastRefreshSuccessEpochSeconds.set(System.currentTimeMillis() / 1000L);
            refreshSuccess.increment();
        } else {
            refreshFailure.increment();
        }
    }

    private Counter responseEncryptionCounter(String result) {
        return Counter.builder(METRIC_RESPONSE_ENCRYPTION)
                .description("JWE response encryption outcome")
                .tag(RESULT, result)
                .register(registry);
    }

    private Counter refreshCounter(String result) {
        return Counter.builder(METRIC_KEY_REFRESH)
                .description("Vault JWE key refresh outcome")
                .tag(RESULT, result)
                .register(registry);
    }

    /**
     * The numeric version of the current encryption key, parsed from its {@code <name>:<version>}
     * {@code kid}; {@code 0} when no key is loaded or the version cannot be parsed.
     */
    private static double currentKeyVersion(JweKeyStore keyStore) {
        return keyStore.currentEncryptionKey()
                .map(MicrometerJweMetrics::versionOf)
                .orElse(0);
    }

    private static int versionOf(RSAKey key) {
        String kid = key.getKeyID();
        if (kid == null) {
            return 0;
        }
        int separator = kid.lastIndexOf(':');
        if (separator < 0 || separator == kid.length() - 1) {
            return 0;
        }
        try {
            return Integer.parseInt(kid.substring(separator + 1));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
