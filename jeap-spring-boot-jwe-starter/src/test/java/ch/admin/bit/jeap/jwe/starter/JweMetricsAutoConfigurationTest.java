package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweMetrics;
import ch.admin.bit.jeap.jwe.keymanagement.MicrometerJweMetrics;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.micrometer.metrics.autoconfigure.MetricsAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the conditional wiring of {@link JweMetricsAutoConfiguration}: a {@link MicrometerJweMetrics}
 * bean is contributed only when a {@link MeterRegistry} is present, and absent otherwise (graceful no-op).
 */
class JweMetricsAutoConfigurationTest {

    private static final String[] STATIC_MODE = {
            "jeap.jwe.enabled=true",
            "jeap.jwe.test.enabled=true",
            "jeap.jwe.test.keys[0]=" + JweTestKeys.rsa4096Pem(0)};

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class, JweMetricsAutoConfiguration.class))
            .withPropertyValues(STATIC_MODE);

    @Test
    void contributesMicrometerMetricsWhenMeterRegistryPresent() {
        runner.withUserConfiguration(MeterRegistryConfig.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JweMetrics.class);
            assertThat(context.getBean(JweMetrics.class)).isInstanceOf(MicrometerJweMetrics.class);
        });
    }

    @Test
    void noMetricsBeanWhenNoMeterRegistry() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(JweMetrics.class);
        });
    }

    @Test
    void emitsZeroGovernanceGaugeWhenJweDisabled() {
        new ApplicationContextRunner()
                // MetricsAutoConfiguration registers the MeterRegistryPostProcessor that binds MeterBinder
                // beans (the governance gauge) to the registry - the mechanism Spring Boot uses in a real app.
                .withConfiguration(AutoConfigurations.of(MetricsAutoConfiguration.class,
                        JweAutoConfiguration.class, JweMetricsAutoConfiguration.class))
                .withUserConfiguration(MeterRegistryConfig.class)
                .withPropertyValues("jeap.jwe.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    // No full metrics (no key store to bind) ...
                    assertThat(context).doesNotHaveBean(JweMetrics.class);
                    // ... but the governance gauge is still present and reads 0, so a disabled service
                    // stays visible to a `jeap_jwe_encryption_active == 0` governance scrape.
                    MeterRegistry registry = context.getBean(MeterRegistry.class);
                    assertThat(registry.get("jeap.jwe.encryption.active").gauge().value()).isEqualTo(0.0);
                });
    }

    @Configuration
    static class MeterRegistryConfig {
        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }
    }
}
