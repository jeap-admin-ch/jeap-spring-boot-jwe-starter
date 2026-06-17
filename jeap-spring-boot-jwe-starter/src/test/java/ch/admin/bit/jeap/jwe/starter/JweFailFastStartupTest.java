package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.vault.core.VaultOperations;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fail-fast startup key loading: the initial load runs during startup and must succeed before
 * the application is ready. A Vault that is unreachable at startup fails the context with a clear,
 * actionable error; static mode loads its keys and never contacts Vault.
 */
class JweFailFastStartupTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class, JweVaultAutoConfiguration.class));

    @Test
    void vaultUnreachableAtStartupFailsFastWithActionableError() {
        runner.withBean(VaultOperations.class, () -> StubVaultTransit.unreachable("Connection refused"))
                .withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.vault.transit-key-name=my-jwe-key",
                        "jeap.jwe.vault.secret-engine-path=transit")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context).getFailure()
                            .hasStackTraceContaining("Failed to load JWE encryption keys")
                            .hasStackTraceContaining("Connection refused");
                });
    }

    @Test
    void staticModeWithoutVaultStartsCleanlyAndPopulatesCache() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.test.keys[0]=" + JweTestKeys.rsa4096Pem(0))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(VaultOperations.class);
                    assertThat(context.getBean(JweKeyStore.class).currentEncryptionKey()).isPresent();
                });
    }
}
