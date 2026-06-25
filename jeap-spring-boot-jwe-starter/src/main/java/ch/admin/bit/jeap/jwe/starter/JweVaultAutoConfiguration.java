package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeySource;
import ch.admin.bit.jeap.jwe.keymanagement.VaultJweKeySource;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.vault.core.VaultOperations;

/**
 * Contributes the Vault-backed key source that {@link JweAutoConfiguration}'s key store loads
 * from in production.
 *
 * <p>Ordered after Spring Cloud Vault's auto-configuration so the {@link VaultOperations} bean it reads
 * from is already defined; gated so it only contributes when the starter is enabled, Vault is enabled
 * ({@code spring.cloud.vault.enabled}, matching if missing), the static test mode is off, and a
 * {@link VaultOperations} bean is present. Static and Vault sources are therefore mutually exclusive.
 */
@AutoConfiguration(afterName = "org.springframework.cloud.vault.config.VaultAutoConfiguration", before = JweAutoConfiguration.class)
@ConditionalOnClass(VaultOperations.class)
@ConditionalOnProperty(prefix = "jeap.jwe", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JweVaultAutoConfiguration {

    @Bean
    @ConditionalOnBean(VaultOperations.class)
    @ConditionalOnMissingBean(JweKeySource.class)
    @ConditionalOnProperty(prefix = "jeap.jwe.test", name = "enabled", havingValue = "false", matchIfMissing = true)
    JweKeySource vaultJweKeySource(VaultOperations vaultOperations, JweProperties properties, Environment environment) {
        return new VaultJweKeySource(
                vaultOperations,
                JweAutoConfiguration.resolveSecretEnginePath(properties, environment),
                properties.getVault().getTransitKeyName(),
                properties.getVault().getMinKeyVersion());
    }
}
