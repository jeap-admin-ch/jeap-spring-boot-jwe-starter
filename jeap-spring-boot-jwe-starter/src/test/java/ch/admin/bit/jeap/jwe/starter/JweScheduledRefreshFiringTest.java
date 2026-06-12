package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeySource;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * End-to-end check that the scheduled refresh actually fires and swaps the cache without a
 * restart. A short interval drives a key source whose active versions change at runtime; the test waits
 * for the store to reflect the new current key. Uses a custom {@link JweKeySource} so no Vault/clock
 * mocking is needed - the scheduler, refresher, loader and store are exercised for real.
 */
class JweScheduledRefreshFiringTest {

    private final RSAKey v1 = JweRsaKeys.from(JweTestKeys.rsa4096(0), JweRsaKeys.keyId("k", 1));
    private final RSAKey v2 = JweRsaKeys.from(JweTestKeys.rsa4096(1), JweRsaKeys.keyId("k", 2));

    @Test
    void scheduledRefresh_picksUpNewVersionWithoutRestart() {
        AtomicReference<List<RSAKey>> activeKeys = new AtomicReference<>(List.of(v1));
        JweKeySource changingSource = activeKeys::get;

        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        JweAutoConfiguration.class, JweVaultAutoConfiguration.class, JweRefreshAutoConfiguration.class))
                .withBean(JweKeySource.class, () -> changingSource)
                .withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.vault.transit-key-name=k",
                        "jeap.jwe.vault.secret-engine-path=transit",
                        "jeap.jwe.refresh.interval=100ms")
                .run(context -> {
                    JweKeyStore store = context.getBean(JweKeyStore.class);
                    assertThat(store.currentEncryptionKey()).contains(v1);

                    // Simulate a rotation becoming visible to the source.
                    activeKeys.set(List.of(v2, v1));

                    await().atMost(Duration.ofSeconds(5))
                            .untilAsserted(() -> assertThat(store.currentEncryptionKey()).contains(v2));
                });
    }
}
