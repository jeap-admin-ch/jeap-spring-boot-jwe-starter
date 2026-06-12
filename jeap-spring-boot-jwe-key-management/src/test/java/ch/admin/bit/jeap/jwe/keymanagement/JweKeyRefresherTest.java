package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Verifies the outage resilience of the refresh: retries with exponential backoff, never
 * clearing or partially overwriting a good snapshot, never throwing, and recovering automatically.
 */
class JweKeyRefresherTest {

    private final RSAKey cachedKey = JweRsaKeys.from(JweTestKeys.rsa4096(0), JweRsaKeys.keyId("k", 1));
    private final RSAKey newKey = JweRsaKeys.from(JweTestKeys.rsa4096(1), JweRsaKeys.keyId("k", 2));

    private final List<Long> sleeps = new ArrayList<>();
    private final JweKeyRefresher.Sleeper recordingSleeper = sleeps::add;

    private final JweRefreshRetrySettings settings =
            new JweRefreshRetrySettings(Duration.ofMillis(10), 2.0, Duration.ofMillis(25), 4);

    @Test
    void refresh_succeedsOnFirstAttempt_swapsCacheWithoutBackoff() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(cachedKey));
        CountingKeySource source = new CountingKeySource(0, List.of(cachedKey, newKey));

        refresher(store, source).refresh();

        assertThat(source.calls).isEqualTo(1);
        assertThat(sleeps).isEmpty();
        assertThat(store.currentEncryptionKey()).contains(newKey);
    }

    @Test
    void refresh_retriesWithExponentialBackoff_thenSucceeds() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(cachedKey));
        CountingKeySource source = new CountingKeySource(2, List.of(cachedKey, newKey));

        refresher(store, source).refresh();

        assertThat(source.calls).isEqualTo(3);
        assertThat(sleeps).containsExactly(10L, 20L); // initial, initial * multiplier
        assertThat(store.currentEncryptionKey()).contains(newKey);
    }

    @Test
    void refresh_exhaustsAttempts_keepsCachedKeysAndNeverThrows() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(cachedKey));
        CountingKeySource source = new CountingKeySource(Integer.MAX_VALUE, List.of(newKey));

        assertThatCode(() -> refresher(store, source).refresh()).doesNotThrowAnyException();

        assertThat(source.calls).isEqualTo(4); // maxAttempts
        // Backoff grows 10 -> 20 -> capped at maxBackoff 25; no sleep after the final attempt.
        assertThat(sleeps).containsExactly(10L, 20L, 25L);
        // The good snapshot is never cleared or partially overwritten during the outage.
        assertThat(store.activeKeys()).containsExactly(cachedKey);
    }

    @Test
    void refresh_recoversOnNextSuccessfulRefreshAfterAnOutage() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(cachedKey));
        // Fails for all attempts of the first refresh, then succeeds on the next refresh.
        CountingKeySource source = new CountingKeySource(4, List.of(cachedKey, newKey));
        JweKeyRefresher refresher = refresher(store, source);

        refresher.refresh(); // outage: keeps cached key
        assertThat(store.activeKeys()).containsExactly(cachedKey);

        refresher.refresh(); // recovery: swaps
        assertThat(store.currentEncryptionKey()).contains(newKey);
    }

    private JweKeyRefresher refresher(InMemoryJweKeyStore store, JweKeySource source) {
        return new JweKeyRefresher(new JweKeyLoader(store, source), settings, recordingSleeper);
    }

    /**
     * Key source that fails its first {@code failUntilCall} invocations, then returns the given keys.
     */
    private static final class CountingKeySource implements JweKeySource {
        private final int failUntilCall;
        private final List<RSAKey> keys;
        private int calls;

        CountingKeySource(int failUntilCall, List<RSAKey> keys) {
            this.failUntilCall = failUntilCall;
            this.keys = keys;
        }

        @Override
        public List<RSAKey> loadActiveKeys() {
            calls++;
            if (calls <= failUntilCall) {
                throw new RuntimeException("Vault unavailable (call " + calls + ")");
            }
            return keys;
        }
    }
}
