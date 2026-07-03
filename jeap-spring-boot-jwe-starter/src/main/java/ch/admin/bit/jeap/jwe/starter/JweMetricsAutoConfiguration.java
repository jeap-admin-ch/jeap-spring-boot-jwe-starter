package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.keymanagement.JweMetrics;
import ch.admin.bit.jeap.jwe.keymanagement.MicrometerJweMetrics;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
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
 * <p>{@link MicrometerJweMetrics} is contributed as a {@link MeterBinder}, so Spring Boot registers its
 * meters only after all {@code MeterFilter}s have been applied. Registering them earlier (the bean is
 * created during servlet web-server initialization, pulled in by the JWE servlet filter) would trigger
 * the PrometheusMeterRegistry "MeterFilter is being configured after a Meter has been registered"
 * warning.
 *
 * <p>Ordered after {@link JweAutoConfiguration} (it needs the {@link JweKeyStore}) and after Spring
 * Boot's meter-registry auto-configurations so the {@link ConditionalOnBean} check sees the registry
 * (both the Spring Boot 4 {@code o.s.b.micrometer.metrics.autoconfigure.*} and the Spring Boot 3
 * {@code o.s.b.actuate.autoconfigure.metrics.*} package names are listed; unknown names are ignored).
 * Ordered before the web and refresh configurations so they can inject the metrics bean.
 *
 * <p>When JWE is disabled ({@code jeap.jwe.enabled=false}) the full metrics are not contributed - there
 * is no {@link JweKeyStore} to bind - but the governance gauge {@code jeap.jwe.encryption.active} is
 * still registered with a constant {@code 0}. That keeps a disabled service visible to a governance
 * scrape (an absent series would otherwise never match {@code jeap_jwe_encryption_active == 0}).
 */
@AutoConfiguration(after = JweAutoConfiguration.class,
        afterName = {
                "org.springframework.boot.micrometer.metrics.autoconfigure.CompositeMeterRegistryAutoConfiguration",
                "org.springframework.boot.micrometer.metrics.autoconfigure.export.simple.SimpleMetricsExportAutoConfiguration",
                "org.springframework.boot.actuate.autoconfigure.metrics.CompositeMeterRegistryAutoConfiguration",
                "org.springframework.boot.actuate.autoconfigure.metrics.export.simple.SimpleMetricsExportAutoConfiguration"},
        before = {JweWebAutoConfiguration.class, JweRefreshAutoConfiguration.class})
@ConditionalOnClass(MeterRegistry.class)
public class JweMetricsAutoConfiguration {

    private static final String METRIC_ENCRYPTION_ACTIVE = "jeap.jwe.encryption.active";
    private static final String ENCRYPTION_ACTIVE_DESCRIPTION =
            "1 if JWE end-to-end encryption is enforced (request+response) and keyed, else 0";

    // The declared return type must be the concrete class: Spring Boot's MeterRegistryPostProcessor
    // collects binders by the bean definition's declared type, and only the concrete type exposes both
    // the JweMetrics view (injected by the web and refresh configurations) and the MeterBinder view
    // (through which the meters get registered). With JweMetrics as return type, bindTo would never run.
    @Bean
    @ConditionalOnMissingBean(JweMetrics.class)
    @ConditionalOnBean({MeterRegistry.class, JweKeyStore.class})
    @ConditionalOnProperty(prefix = "jeap.jwe", name = "enabled", havingValue = "true", matchIfMissing = true)
    MicrometerJweMetrics jweMetrics(JweKeyStore keyStore, JweProperties properties) {
        JweProperties.Filter filter = properties.getFilter();
        return new MicrometerJweMetrics(keyStore,
                filter.isRequireEncryptedRequest(), filter.isRequireEncryptedResponse());
    }

    /**
     * Governance gauge for a service that has turned JWE off entirely: encryption is never active, so the
     * gauge reads a constant {@code 0}. Only registered when JWE is disabled; when enabled the live gauge
     * contributed by {@link MicrometerJweMetrics} is used instead.
     *
     * <p>Contributed as a {@link MeterBinder} - the idiomatic Micrometer/Spring Boot way to register
     * meters: Spring Boot binds it to every {@link MeterRegistry} in the context, so no {@code Gauge} bean
     * leaks into the application context as an injectable bean.
     */
    @Bean
    @ConditionalOnBean(MeterRegistry.class)
    @ConditionalOnProperty(prefix = "jeap.jwe", name = "enabled", havingValue = "false")
    MeterBinder jweEncryptionInactiveGauge() {
        return registry -> Gauge.builder(METRIC_ENCRYPTION_ACTIVE, () -> 0.0)
                .description(ENCRYPTION_ACTIVE_DESCRIPTION)
                .register(registry);
    }
}
