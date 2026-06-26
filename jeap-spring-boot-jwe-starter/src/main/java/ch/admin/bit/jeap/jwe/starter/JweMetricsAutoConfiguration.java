package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.keymanagement.JweMetrics;
import ch.admin.bit.jeap.jwe.keymanagement.MicrometerJweMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Contributes the Micrometer-backed {@link JweMetrics} when a {@link MeterRegistry} is available, so
 * the starter exposes its metrics (decryption outcome/latency, response-encryption outcome, Vault
 * refresh status, active/current key versions and the governance "encryption active" signal) through
 * the application's registry (Prometheus, OpenTelemetry, ...).
 *
 * <p>Gated on Micrometer being present ({@link ConditionalOnClass}) and an actual {@link MeterRegistry}
 * bean ({@link ConditionalOnBean}). When absent, no metrics bean is created and the filter, refresher
 * and key store fall back to {@link JweMetrics#NOOP} - no metrics, no behavioural change.
 *
 * <p>Ordered after {@link JweAutoConfiguration} (it needs the {@link JweKeyStore}) and after Spring
 * Boot's meter-registry auto-configurations so the {@link ConditionalOnBean} check sees the registry
 * (both the Spring Boot 4 {@code o.s.b.micrometer.metrics.autoconfigure.*} and the Spring Boot 3
 * {@code o.s.b.actuate.autoconfigure.metrics.*} package names are listed; unknown names are ignored).
 * Ordered before the web and refresh configurations so they can inject the metrics bean.
 */
@AutoConfiguration(after = JweAutoConfiguration.class,
        afterName = {
                "org.springframework.boot.micrometer.metrics.autoconfigure.CompositeMeterRegistryAutoConfiguration",
                "org.springframework.boot.micrometer.metrics.autoconfigure.export.simple.SimpleMetricsExportAutoConfiguration",
                "org.springframework.boot.actuate.autoconfigure.metrics.CompositeMeterRegistryAutoConfiguration",
                "org.springframework.boot.actuate.autoconfigure.metrics.export.simple.SimpleMetricsExportAutoConfiguration"},
        before = {JweWebAutoConfiguration.class, JweRefreshAutoConfiguration.class})
@ConditionalOnClass(MeterRegistry.class)
@ConditionalOnProperty(prefix = "jeap.jwe", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JweMetricsAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JweMetrics.class)
    @ConditionalOnBean({MeterRegistry.class, JweKeyStore.class})
    JweMetrics jweMetrics(MeterRegistry meterRegistry, JweKeyStore keyStore, JweProperties properties) {
        JweProperties.Filter filter = properties.getFilter();
        return new MicrometerJweMetrics(meterRegistry, keyStore,
                filter.isRequireEncryptedRequest(), filter.isRequireEncryptedResponse());
    }
}
