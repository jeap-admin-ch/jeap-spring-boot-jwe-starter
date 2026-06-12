package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeyRefreshScheduler;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyRefresher;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.vault.core.VaultOperations;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the periodic-refresh wiring: the scheduler is registered in Vault mode and is
 * absent in the static test mode (no Vault, no rotation).
 */
class JweRefreshAutoConfigurationTest {

    private static final String ENGINE = "transit";
    private static final String KEY_NAME = "my-jwe-key";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    JweAutoConfiguration.class, JweVaultAutoConfiguration.class, JweRefreshAutoConfiguration.class));

    @Test
    void vaultMode_registersRefreshScheduler() {
        runner.withBean(VaultOperations.class, () -> StubVaultTransit.withSingleVersion(ENGINE, KEY_NAME))
                .withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.vault.transit-key-name=" + KEY_NAME,
                        "jeap.jwe.vault.secret-engine-path=" + ENGINE)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JweKeyRefresher.class);
                    assertThat(context).hasSingleBean(JweKeyRefreshScheduler.class);
                });
    }

    @Test
    void staticTestMode_doesNotRegisterRefresh() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.test.keys[0]=" + JweTestKeys.rsa4096Pem(0))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(JweKeyRefresher.class);
                    assertThat(context).doesNotHaveBean(JweKeyRefreshScheduler.class);
                });
    }
}
