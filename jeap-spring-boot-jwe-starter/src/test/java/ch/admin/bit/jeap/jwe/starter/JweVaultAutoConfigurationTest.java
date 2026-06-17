package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeySource;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.keymanagement.VaultJweKeySource;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.vault.core.VaultOperations;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the Vault key-source wiring without a Vault container: when the starter is enabled, Vault mode is
 * active and a {@link VaultOperations} bean is present, the Vault-backed {@link JweKeySource} is
 * contributed and the key store is populated from it. The Vault calls are stubbed because Vault
 * integration itself is covered by {@code VaultJweKeySourceIT} against a real container.
 */
class JweVaultAutoConfigurationTest {

    private static final String ENGINE = "transit";
    private static final String KEY_NAME = "my-jwe-key";
    public static final String JEAP_JWE_VAULT_TRANSIT_KEY_NAME = "jeap.jwe.vault.transit-key-name=";
    public static final String JEAP_JWE_ENABLED_TRUE = "jeap.jwe.enabled=true";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class, JweVaultAutoConfiguration.class));

    @Test
    void vaultMode_withVaultOperationsContributesVaultSourceAndPopulatesStore() {
        runner.withBean(VaultOperations.class, () -> StubVaultTransit.withSingleVersion(ENGINE, KEY_NAME))
                .withPropertyValues(
                        JEAP_JWE_ENABLED_TRUE,
                        JEAP_JWE_VAULT_TRANSIT_KEY_NAME + KEY_NAME,
                        "jeap.jwe.vault.secret-engine-path=" + ENGINE)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JweKeySource.class);
                    assertThat(context.getBean(JweKeySource.class)).isInstanceOf(VaultJweKeySource.class);
                    assertThat(context.getBean(JweKeyStore.class).currentEncryptionKey()).get()
                            .extracting(JWK::getKeyID).isEqualTo(KEY_NAME + ":1");
                });
    }

    @Test
    void vaultModeDerivesSecretEnginePathFromSystemName() {
        // No explicit secret-engine-path: it is derived as transit/<system-name>; the stub answers only
        // on that derived path, so a successful load proves the derivation was applied.
        runner.withBean(VaultOperations.class, () -> StubVaultTransit.withSingleVersion("transit/my-system", KEY_NAME))
                .withPropertyValues(
                        JEAP_JWE_ENABLED_TRUE,
                        JEAP_JWE_VAULT_TRANSIT_KEY_NAME + KEY_NAME,
                        "jeap.vault.system-name=my-system")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(JweProperties.class).getVault().getSecretEnginePath())
                            .isEqualTo("transit/my-system");
                    assertThat(context.getBean(JweKeyStore.class).currentEncryptionKey()).get()
                            .extracting(JWK::getKeyID).isEqualTo(KEY_NAME + ":1");
                });
    }

    @Test
    void testModeDoesNotContributeVaultSource() {
        runner.withBean(VaultOperations.class, () -> StubVaultTransit.withSingleVersion(ENGINE, KEY_NAME))
                .withPropertyValues(
                        JEAP_JWE_ENABLED_TRUE,
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.test.keys[0]=" + JweTestKeys.rsa4096Pem(0))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(VaultJweKeySource.class);
                });
    }

    @Test
    void vaultModeWithoutVaultOperationsBeanFailsFast() {
        // No VaultOperations bean -> no Vault key source -> the startup load fails fast.
        runner.withPropertyValues(
                        JEAP_JWE_ENABLED_TRUE,
                        JEAP_JWE_VAULT_TRANSIT_KEY_NAME + KEY_NAME,
                        "jeap.jwe.vault.secret-engine-path=" + ENGINE)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context).getFailure().hasStackTraceContaining("no key source is available");
                });
    }
}
