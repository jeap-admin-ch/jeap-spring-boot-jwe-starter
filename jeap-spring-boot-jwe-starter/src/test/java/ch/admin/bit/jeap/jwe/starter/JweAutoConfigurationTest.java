package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class JweAutoConfigurationTest {

    private static final String TEST_KEY_PEM = JweTestKeys.rsa4096Pem(0);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class));

    @Test
    void enabledByDefault_activatesWhenOnClasspath() {
        // Without any jeap.jwe.enabled property, the starter activates (and requires config).
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context).getFailure()
                    .hasStackTraceContaining("jeap.jwe.vault.transit-key-name");
        });
    }

    @Test
    void explicitlyDisabled_noJweBeans() {
        runner.withPropertyValues("jeap.jwe.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(JweProperties.class);
                });
    }

    @Test
    void enabledInTestMode_bindsDefaults() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.test.keys[0]=" + TEST_KEY_PEM)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JweProperties.class);
                    JweProperties props = context.getBean(JweProperties.class);
                    assertThat(props.isEnabled()).isTrue();
                    assertThat(props.getVault().getMinKeyVersion()).isEqualTo(1);
                    assertThat(props.getJwks().getPath()).isEqualTo("/.well-known/jwks.json");
                    assertThat(props.getRefresh().getInterval()).isEqualTo(Duration.ofMinutes(5));
                });
    }

    @Test
    void customJwksPath_isBound() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.test.keys[0]=" + TEST_KEY_PEM,
                        "jeap.jwe.jwks.path=/custom/jwks.json")
                .run(context -> assertThat(context.getBean(JweProperties.class).getJwks().getPath())
                        .isEqualTo("/custom/jwks.json"));
    }

    @Test
    void vaultMode_withoutKeySource_failsFastAtStartup() {
        // Vault mode but no VaultOperations / key source available (Spring Cloud Vault not wired):
        // the starter must fail fast rather than start with no usable keys.
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.vault.transit-key-name=my-jwe-key",
                        "jeap.vault.system-name=my-system")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context).getFailure()
                            .hasStackTraceContaining("no key source is available");
                });
    }

    @Test
    void vaultMode_failsWithoutTransitKeyName() {
        runner.withPropertyValues("jeap.jwe.enabled=true")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context).getFailure()
                            .hasStackTraceContaining("jeap.jwe.vault.transit-key-name");
                });
    }

    @Test
    void vaultDisabled_treatedAsRequiringStaticKeys() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "spring.cloud.vault.enabled=false")
                .run(context -> {
                    // Not Vault mode (vault disabled) and test keys missing -> fails fast.
                    assertThat(context).hasFailed();
                    assertThat(context).getFailure()
                            .hasStackTraceContaining("jeap.jwe.test.keys");
                });
    }

    @Test
    void nonPositiveRefreshInterval_failsFast() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.test.keys[0]=" + TEST_KEY_PEM,
                        "jeap.jwe.refresh.interval=0s")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context).getFailure()
                            .hasStackTraceContaining("jeap.jwe.refresh.interval");
                });
    }

    @Test
    void invalidRefreshMaxAttempts_failsFast() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.test.keys[0]=" + TEST_KEY_PEM,
                        "jeap.jwe.refresh.max-attempts=0")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context).getFailure()
                            .hasStackTraceContaining("jeap.jwe.refresh.max-attempts");
                });
    }
}
