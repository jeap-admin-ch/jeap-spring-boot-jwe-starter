package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweProtocolException;
import com.nimbusds.jose.jwk.RSAKey;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.MeterBinder;

import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Micrometer-backed {@link JweMetrics}. Registers the JWE meters under the {@code jeap.jwe.*} prefix
 * against the application's {@link MeterRegistry}, so they are exported through whatever registry the
 * service configures (Prometheus, OpenTelemetry, ...).
 *
 * <p>Registration happens in {@link #bindTo(MeterRegistry)}, not at construction: Spring Boot applies
 * {@link MeterBinder} beans only after all {@code MeterFilter}s have been configured, whereas this bean
 * is created during servlet web-server initialization (pulled in by the JWE servlet filter), long before
 * that. Record calls before binding are safe no-ops - only the refresh timestamp is tracked, so a
 * pre-bind refresh still shows in the timestamp gauge once bound.
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
public class MicrometerJweMetrics implements JweMetrics, MeterBinder {

    private static final String METRIC_DECRYPTION = "jeap.jwe.decryption";
    private static final String METRIC_REQUEST_REJECTED = "jeap.jwe.request.rejected";
    private static final String METRIC_RESPONSE_ENCRYPTION = "jeap.jwe.response.encryption";
    private static final String METRIC_KEY_REFRESH = "jeap.jwe.key.refresh";

    private static final String RESULT = "result";
    private static final String SUCCESS = "success";
    private static final String FAILURE = "failure";
    private static final String REASON = "reason";
    private static final String NONE = "none";

    // Set once by the first bindTo call and published last: a non-null registry implies the counters
    // below are initialized. All meters - eager and lazily created per-request ones - live in this
    // single registry; further bindTo calls are ignored.
    private final AtomicReference<MeterRegistry> registry = new AtomicReference<>();
    private final JweKeyStore keyStore;
    private final boolean enforced;
    private final AtomicLong lastRefreshSuccessEpochSeconds = new AtomicLong(0);
    // Meters are cached and registered once, not rebuilt on every record() call. The decryption timers
    // are keyed by their result/reason tag combination (bounded by the JweProtocolException reasons).
    private final ConcurrentMap<String, Timer> decryptionTimers = new ConcurrentHashMap<>();
    // Request-rejection counters, keyed by reason (bounded by the RejectionReason enum).
    private final ConcurrentMap<RejectionReason, Counter> rejectionCounters = new ConcurrentHashMap<>();
    private Counter responseEncryptionSuccess;
    private Counter responseEncryptionFailure;
    private Counter refreshSuccess;
    private Counter refreshFailure;

    public MicrometerJweMetrics(JweKeyStore keyStore,
                                boolean requireEncryptedRequest, boolean requireEncryptedResponse) {
        this.keyStore = keyStore;
        // Governance signal: end-to-end encryption is only "active" when enforcement is on for both
        // directions and at least one key is loaded. Captures the enforcement flags once (they are
        // fixed for the lifetime of the context); key availability is read live by the gauge.
        this.enforced = requireEncryptedRequest && requireEncryptedResponse;

        // The startup key load runs (and fails fast) before this bean is created, so a present key means
        // the keys are fresh as of startup. Seed the last-success timestamp accordingly; otherwise the
        // gauge would read 0 until the first periodic refresh and a staleness alert would fire falsely for
        // up to one refresh interval after every restart/deploy.
        if (keyStore.currentEncryptionKey().isPresent()) {
            lastRefreshSuccessEpochSeconds.set(System.currentTimeMillis() / 1000L);
        }
    }

    /**
     * Binds all meters at most once: the instance holds stateful counters, so binding to a second
     * registry would split the meters across registries. In a Spring Boot application the binder is
     * applied to the (single) auto-configured composite registry anyway.
     */
    @Override
    public synchronized void bindTo(MeterRegistry meterRegistry) {
        if (registry.get() != null) {
            return;
        }

        this.responseEncryptionSuccess = responseEncryptionCounter(meterRegistry, SUCCESS);
        this.responseEncryptionFailure = responseEncryptionCounter(meterRegistry, FAILURE);
        this.refreshSuccess = refreshCounter(meterRegistry, SUCCESS);
        this.refreshFailure = refreshCounter(meterRegistry, FAILURE);

        Gauge.builder("jeap.jwe.keys.active", keyStore, store -> store.activeKeys().size())
                .description("Number of active JWE key versions accepted for decryption")
                .register(meterRegistry);

        Gauge.builder("jeap.jwe.keys.current.version", keyStore, MicrometerJweMetrics::currentKeyVersion)
                .description("Version of the current JWE encryption key (newest active version), 0 if none")
                .register(meterRegistry);

        Gauge.builder("jeap.jwe.key.refresh.timestamp", lastRefreshSuccessEpochSeconds, AtomicLong::get)
                .description("Epoch seconds of the last successful Vault key refresh; seeded from the startup key load")
                .baseUnit("seconds")
                .register(meterRegistry);

        Gauge.builder("jeap.jwe.encryption.active", keyStore,
                        store -> enforced && store.currentEncryptionKey().isPresent() ? 1.0 : 0.0)
                .description("1 if JWE end-to-end encryption is enforced (request+response) and keyed, else 0")
                .register(meterRegistry);

        this.registry.set(meterRegistry);
    }

    @Override
    public void recordDecryption(boolean success, JweProtocolException.Reason reason, Duration elapsed) {
        MeterRegistry meterRegistry = registry.get();
        if (meterRegistry == null) {
            return;
        }
        String resultTag = success ? SUCCESS : FAILURE;
        String reasonTag = success || reason == null ? NONE : reason.name().toLowerCase(Locale.ROOT);
        decryptionTimers.computeIfAbsent(resultTag + '/' + reasonTag,
                        key -> Timer.builder(METRIC_DECRYPTION)
                                .description("JWE request decryption outcome and latency")
                                .tag(RESULT, resultTag)
                                .tag(REASON, reasonTag)
                                .publishPercentileHistogram()
                                .register(meterRegistry))
                .record(elapsed);
    }

    @Override
    public void recordRequestRejected(RejectionReason reason) {
        MeterRegistry meterRegistry = registry.get();
        if (meterRegistry == null) {
            return;
        }
        rejectionCounters.computeIfAbsent(reason,
                        r -> Counter.builder(METRIC_REQUEST_REJECTED)
                                .description("Inbound JWE request rejected before the crypto layer (size or policy guard)")
                                .tag(REASON, r.name().toLowerCase(Locale.ROOT))
                                .register(meterRegistry))
                .increment();
    }

    @Override
    public void recordResponseEncryption(boolean success) {
        if (registry.get() == null) {
            return;
        }
        (success ? responseEncryptionSuccess : responseEncryptionFailure).increment();
    }

    @Override
    public void recordRefresh(boolean success) {
        // The timestamp is tracked even before binding so the gauge reflects a pre-bind refresh.
        if (success) {
            lastRefreshSuccessEpochSeconds.set(System.currentTimeMillis() / 1000L);
        }
        if (registry.get() == null) {
            return;
        }
        (success ? refreshSuccess : refreshFailure).increment();
    }

    private Counter responseEncryptionCounter(MeterRegistry meterRegistry, String result) {
        return Counter.builder(METRIC_RESPONSE_ENCRYPTION)
                .description("JWE response encryption outcome")
                .tag(RESULT, result)
                .register(meterRegistry);
    }

    private Counter refreshCounter(MeterRegistry meterRegistry, String result) {
        return Counter.builder(METRIC_KEY_REFRESH)
                .description("Vault JWE key refresh outcome")
                .tag(RESULT, result)
                .register(meterRegistry);
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
