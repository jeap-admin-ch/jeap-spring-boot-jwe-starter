package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that in static test mode the auto-configuration eagerly populates a
 * {@link JweKeyStore} from the configured keys, with no Vault connection.
 */
class JweKeyStoreWiringTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class));

    @Test
    void staticMode_populatesKeyStoreNewestVersionFirst() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.vault.transit-key-name=my-jwe-key",
                        "jeap.jwe.test.keys[0]=" + JweTestKeys.rsa4096Pem(0),
                        "jeap.jwe.test.keys[1]=" + JweTestKeys.rsa4096Pem(1))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(JweKeyStore.class);

                    JweKeyStore store = context.getBean(JweKeyStore.class);
                    assertThat(store.activeKeys())
                            .extracting(JWK::getKeyID)
                            .containsExactly("my-jwe-key:2", "my-jwe-key:1");
                    assertThat(store.currentEncryptionKey()).get()
                            .extracting(JWK::getKeyID).isEqualTo("my-jwe-key:2");
                    assertThat(store.findByKeyId("my-jwe-key:1")).isPresent();
                });
    }

    @Test
    void staticMode_withoutTransitKeyName_usesDefaultKidName() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.test.keys[0]=" + JweTestKeys.rsa4096Pem(0))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    JweKeyStore store = context.getBean(JweKeyStore.class);
                    assertThat(store.currentEncryptionKey()).get()
                            .extracting(JWK::getKeyID)
                            .isEqualTo(JweAutoConfiguration.DEFAULT_STATIC_KEY_NAME + ":1");
                });
    }

    @Test
    void staticMode_invalidKeyFailsContextFast() {
        runner.withPropertyValues(
                        "jeap.jwe.enabled=true",
                        "jeap.jwe.test.enabled=true",
                        "jeap.jwe.test.keys[0]=not-a-pem-key")
                .run(context -> assertThat(context).hasFailed());
    }
}
