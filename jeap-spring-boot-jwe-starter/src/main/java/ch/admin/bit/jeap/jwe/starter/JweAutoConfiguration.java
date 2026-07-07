package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.crypto.JweCryptoProvider;
import ch.admin.bit.jeap.jwe.keymanagement.*;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.time.Duration;

/**
 * Auto-configuration entry point for the jEAP JWE end-to-end encryption starter.
 *
 * <p>The starter is active by default when on the classpath; set {@code jeap.jwe.enabled=false} to
 * disable it. When active it derives sensible defaults (the Vault transit secret-engine path from
 * {@code jeap.vault.system-name}) and validates the configuration for the selected mode.
 *
 * <p>Vault-backed beans are additionally gated on {@code spring.cloud.vault.enabled} (matching if
 * missing); the static test mode ({@code jeap.jwe.test.enabled=true}) needs no Vault connection.
 */
@Slf4j
@AutoConfiguration
@EnableConfigurationProperties(JweProperties.class)
@ConditionalOnProperty(prefix = "jeap.jwe", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JweAutoConfiguration {

    /**
     * {@code kid} name component for static test keys when no Vault transit key name is configured.
     */
    static final String DEFAULT_STATIC_KEY_NAME = "jwe-static-test-key";

    private final JweProperties properties;
    private final Environment environment;

    public JweAutoConfiguration(JweProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    /**
     * Static, Vault-free key source for the test mode. The Vault-backed source is contributed
     * by its own auto-configuration and takes the place of this bean in Vault mode.
     */
    @Bean
    @ConditionalOnProperty(prefix = "jeap.jwe.test", name = "enabled", havingValue = "true")
    JweKeySource staticJweKeySource() {
        return new StaticJweKeySource(staticKeyName(), properties.getTest().getKeys());
    }

    /**
     * The in-memory key store consumed by the rest of the starter; populated by {@link #jweKeyLoader}.
     */
    @Bean
    @ConditionalOnMissingBean(JweKeyStore.class)
    InMemoryJweKeyStore jweKeyStore() {
        return new InMemoryJweKeyStore();
    }

    /**
     * Performs the initial key load during startup and <strong>fails fast</strong>: if no key
     * source is available, or the source fails, or it yields no active key, the context refuses to
     * start instead of coming up with no usable keys. A periodic refresh reuses the loader to
     * swap the snapshot atomically; a transient outage there keeps the cached keys.
     */
    @Bean
    JweKeyLoader jweKeyLoader(InMemoryJweKeyStore keyStore, ObjectProvider<JweKeySource> keySource) {
        JweKeySource source = keySource.getIfAvailable();
        if (source == null) {
            throw new JweKeyLoadException(
                    "JWE encryption is enabled but no key source is available. In Vault mode, configure Spring "
                            + "Cloud Vault (spring.cloud.vault.*) so a VaultOperations bean exists; for tests without "
                            + "Vault, set jeap.jwe.test.enabled=true and provide jeap.jwe.test.keys.");
        }
        JweKeyLoader loader = new JweKeyLoader(keyStore, source);
        loader.loadOrThrow();
        return loader;
    }

    private String staticKeyName() {
        String transitKeyName = properties.getVault().getTransitKeyName();
        return StringUtils.hasText(transitKeyName) ? transitKeyName : DEFAULT_STATIC_KEY_NAME;
    }

    @PostConstruct
    void initializeConfiguration() {
        validate();
        validateRefresh();
        // Install the crypto provider eagerly so the native-library load, its self-test and any
        // platform-fallback warning happen at startup instead of during the first encrypted request.
        JweCryptoProvider.ensureInstalled();
        logConfiguration();
    }

    /**
     * Logs the effective starter configuration at INFO on startup. Sensitive values are never logged:
     * the only secret carried by {@link JweProperties} is the static test key material, which its
     * {@code toString()} already redacts; Vault credentials live in {@code spring.cloud.vault.*} and
     * are not part of this configuration. The resolved secret-engine path is added in Vault mode
     * because it may be derived from {@code jeap.vault.system-name} rather than configured directly.
     */
    private void logConfiguration() {
        boolean vaultMode = isVaultMode();
        log.info("jEAP JWE encryption enabled (mode={}{}). Effective configuration (key material redacted): {}",
                vaultMode ? "vault" : "static-test",
                vaultMode ? ", resolvedSecretEnginePath=" + resolveSecretEnginePath(properties, environment) : "",
                properties);
    }

    /**
     * Resolves the effective Vault transit secret-engine path without mutating the configuration: the
     * explicitly configured value, or {@code transit/<jeap.vault.system-name>} when only the system name
     * is set, or {@code null} when neither is available.
     */
    static String resolveSecretEnginePath(JweProperties properties, Environment environment) {
        String configured = properties.getVault().getSecretEnginePath();
        if (StringUtils.hasText(configured)) {
            return configured;
        }
        String systemName = environment.getProperty("jeap.vault.system-name");
        return StringUtils.hasText(systemName) ? "transit/" + systemName : null;
    }

    private void validate() {
        if (isVaultMode()) {
            if (!StringUtils.hasText(properties.getVault().getTransitKeyName())) {
                throw new IllegalStateException(
                        "jeap.jwe.vault.transit-key-name must be set when JWE encryption is enabled with Vault. " +
                                "For tests without Vault, set jeap.jwe.test.enabled=true.");
            }
            if (resolveSecretEnginePath(properties, environment) == null) {
                throw new IllegalStateException(
                        "jeap.jwe.vault.secret-engine-path must be set, or provide jeap.vault.system-name " +
                                "to derive transit/<system-name>.");
            }
        } else if (properties.getTest().getKeys().isEmpty()) {
            throw new IllegalStateException(
                    "jeap.jwe.test.keys must provide at least one static RSA key when " +
                            "jeap.jwe.test.enabled=true.");
        }
    }

    /**
     * Validates the periodic-refresh parameters up front so a misconfiguration fails the context with
     * a clear message instead of surfacing later at scheduling time.
     */
    private void validateRefresh() {
        JweProperties.Refresh refresh = properties.getRefresh();
        requirePositive("jeap.jwe.refresh.interval", refresh.getInterval());
        requireNonNegative("jeap.jwe.refresh.initial-backoff", refresh.getInitialBackoff());
        requireNonNegative("jeap.jwe.refresh.max-backoff", refresh.getMaxBackoff());
        if (refresh.getMaxAttempts() < 1) {
            throw new IllegalStateException(
                    "jeap.jwe.refresh.max-attempts must be >= 1 but was " + refresh.getMaxAttempts() + ".");
        }
        if (refresh.getBackoffMultiplier() < 1.0) {
            throw new IllegalStateException(
                    "jeap.jwe.refresh.backoff-multiplier must be >= 1.0 but was " + refresh.getBackoffMultiplier() + ".");
        }
    }

    private static void requirePositive(String name, Duration value) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw new IllegalStateException(name + " must be a positive duration but was " + value + ".");
        }
    }

    private static void requireNonNegative(String name, Duration value) {
        if (value == null || value.isNegative()) {
            throw new IllegalStateException(name + " must not be negative but was " + value + ".");
        }
    }

    /**
     * Vault mode is active unless the static test mode is explicitly enabled and
     * {@code spring.cloud.vault.enabled} is not set to false.
     */
    private boolean isVaultMode() {
        if (properties.getTest().isEnabled()) {
            return false;
        }
        return environment.getProperty("spring.cloud.vault.enabled", Boolean.class, true);
    }
}
