package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweProtocolException;
import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.RSAKey;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the Micrometer meters registered by {@link MicrometerJweMetrics}: decryption
 * counts/latency, response-encryption and refresh counters, the key-version gauges and the
 * governance "encryption active" gauge.
 */
class MicrometerJweMetricsTest {

    private final RSAKey keyV1 = JweRsaKeys.from(JweTestKeys.rsa4096(0), JweRsaKeys.keyId("k", 1));
    private final RSAKey keyV2 = JweRsaKeys.from(JweTestKeys.rsa4096(1), JweRsaKeys.keyId("k", 2));

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();

    @Test
    void keyGaugesReflectTheLiveStoreSnapshot() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(keyV1, keyV2));
        new MicrometerJweMetrics(registry, store, true, true);

        assertThat(registry.get("jeap.jwe.keys.active").gauge().value()).isEqualTo(2.0);
        assertThat(registry.get("jeap.jwe.keys.current.version").gauge().value()).isEqualTo(2.0);

        // Gauges are live: dropping the older version is reflected without re-registering.
        store.replaceKeys(List.of(keyV2));
        assertThat(registry.get("jeap.jwe.keys.active").gauge().value()).isEqualTo(1.0);
        assertThat(registry.get("jeap.jwe.keys.current.version").gauge().value()).isEqualTo(2.0);
    }

    @Test
    void encryptionActiveIsOneOnlyWhenEnforcedAndKeyed() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(keyV1));
        new MicrometerJweMetrics(registry, store, true, true);

        assertThat(registry.get("jeap.jwe.encryption.active").gauge().value()).isEqualTo(1.0);

        // Keys vanish -> not active anymore.
        store.replaceKeys(List.of());
        assertThat(registry.get("jeap.jwe.encryption.active").gauge().value()).isEqualTo(0.0);
    }

    @Test
    void encryptionActiveIsZeroWhenEnforcementIsRelaxed() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(keyV1));
        new MicrometerJweMetrics(registry, store, true, false);

        assertThat(registry.get("jeap.jwe.encryption.active").gauge().value()).isEqualTo(0.0);
    }

    @Test
    void seedsRefreshTimestampFromStartupKeyLoad() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(keyV1));

        // Keys are already loaded (startup load) when the metrics are wired -> timestamp seeded at once,
        // without waiting for the first periodic refresh.
        new MicrometerJweMetrics(registry, store, true, true);

        assertThat(registry.get("jeap.jwe.key.refresh.timestamp").gauge().value()).isGreaterThan(0.0);
    }

    @Test
    void refreshTimestampStaysZeroWhenNoKeysLoadedAtStartup() {
        new MicrometerJweMetrics(registry, new InMemoryJweKeyStore(), true, true);

        assertThat(registry.get("jeap.jwe.key.refresh.timestamp").gauge().value()).isEqualTo(0.0);
    }

    @Test
    void recordsDecryptionSuccessWithLatency() {
        MicrometerJweMetrics metrics = metrics();

        metrics.recordDecryption(true, null, Duration.ofMillis(7));

        Timer timer = registry.get("jeap.jwe.decryption").tag("result", "success").tag("reason", "none").timer();
        assertThat(timer.count()).isEqualTo(1);
        assertThat(timer.totalTime(java.util.concurrent.TimeUnit.MILLISECONDS)).isGreaterThanOrEqualTo(7.0);
    }

    @Test
    void recordsDecryptionFailureTaggedWithReason() {
        MicrometerJweMetrics metrics = metrics();

        metrics.recordDecryption(false, JweProtocolException.Reason.UNKNOWN_KEY_ID, Duration.ofMillis(2));

        assertThat(registry.get("jeap.jwe.decryption")
                .tag("result", "failure").tag("reason", "unknown_key_id").timer().count()).isEqualTo(1);
    }

    @Test
    void recordsRequestRejectionTaggedWithReason() {
        MicrometerJweMetrics metrics = metrics();

        metrics.recordRequestRejected(JweMetrics.RejectionReason.PAYLOAD_TOO_LARGE);
        metrics.recordRequestRejected(JweMetrics.RejectionReason.ENCRYPTION_REQUIRED);
        metrics.recordRequestRejected(JweMetrics.RejectionReason.ENCRYPTION_REQUIRED);

        assertThat(registry.get("jeap.jwe.request.rejected").tag("reason", "payload_too_large").counter().count())
                .isEqualTo(1.0);
        assertThat(registry.get("jeap.jwe.request.rejected").tag("reason", "encryption_required").counter().count())
                .isEqualTo(2.0);
    }

    @Test
    void recordsResponseEncryptionAndRefreshOutcomes() {
        MicrometerJweMetrics metrics = metrics();

        metrics.recordResponseEncryption(true);
        metrics.recordRefresh(true);
        metrics.recordRefresh(false);

        assertThat(registry.get("jeap.jwe.response.encryption").tag("result", "success").counter().count())
                .isEqualTo(1.0);
        assertThat(registry.get("jeap.jwe.key.refresh").tag("result", "success").counter().count()).isEqualTo(1.0);
        assertThat(registry.get("jeap.jwe.key.refresh").tag("result", "failure").counter().count()).isEqualTo(1.0);
        // A successful refresh stamps the last-success timestamp gauge.
        assertThat(registry.get("jeap.jwe.key.refresh.timestamp").gauge().value()).isGreaterThan(0.0);
    }

    private MicrometerJweMetrics metrics() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(keyV1));
        return new MicrometerJweMetrics(registry, store, true, true);
    }
}
