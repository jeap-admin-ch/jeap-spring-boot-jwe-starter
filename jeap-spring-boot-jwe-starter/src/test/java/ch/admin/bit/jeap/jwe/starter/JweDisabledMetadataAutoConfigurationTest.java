package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import ch.admin.bit.jeap.jwe.web.JweJwksController;
import ch.admin.bit.jeap.jwe.web.JweMetadataController;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the gating of {@link JweDisabledMetadataAutoConfiguration}: with the starter switched off the
 * protocol-metadata endpoint is still contributed - and nothing else - so a client can discover the
 * disabled state instead of running into a 404 it would have to treat as a failure.
 */
class JweDisabledMetadataAutoConfigurationTest {

    private static final String[] STATIC_MODE = {
            "jeap.jwe.enabled=true",
            "jeap.jwe.test.enabled=true",
            "jeap.jwe.test.keys[0]=" + JweTestKeys.rsa4096Pem(0)
    };

    private final WebApplicationContextRunner servletRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class, JweWebAutoConfiguration.class,
                    JweDisabledMetadataAutoConfiguration.class));

    private final ApplicationContextRunner nonWebRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class, JweWebAutoConfiguration.class,
                    JweDisabledMetadataAutoConfiguration.class));

    @Test
    void disabledStarterStillRegistersMetadataControllerButNothingElse() {
        servletRunner.withPropertyValues("jeap.jwe.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JweMetadataController.class);
            assertThat(context.getBean(JweMetadataController.class).configuration().enabled()).isFalse();
            // No key material, no JWKS endpoint and no filter - only the switch is published.
            assertThat(context).doesNotHaveBean(JweJwksController.class);
        });
    }

    @Test
    void disabledMetadataCarriesOnlyTheSwitch() {
        servletRunner.withPropertyValues("jeap.jwe.enabled=false").run(context -> {
            var metadata = context.getBean(JweMetadataController.class).configuration();
            assertThat(metadata.enabled()).isFalse();
            assertThat(metadata.contentTypeAllowlist()).isEmpty();
            assertThat(metadata.includedPaths()).isEmpty();
            assertThat(metadata.excludedPaths()).isEmpty();
            assertThat(metadata.jwksPath()).isNull();
            assertThat(metadata.responseKeyHeader()).isNull();
            assertThat(metadata.keyEncryptionAlgorithm()).isNull();
            assertThat(metadata.contentEncryptionMethod()).isNull();
        });
    }

    @Test
    void enabledStarterKeepsTheMetadataFromTheWebConfiguration() {
        servletRunner.withPropertyValues(STATIC_MODE).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JweMetadataController.class);
            assertThat(context.getBean(JweMetadataController.class).configuration().enabled()).isTrue();
        });
    }

    @Test
    void optingOutSuppressesTheEndpointEntirely() {
        servletRunner
                .withPropertyValues("jeap.jwe.enabled=false", "jeap.jwe.metadata.publish-when-disabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(JweMetadataController.class);
                });
    }

    @Test
    void nonWebAppRegistersNoMetadataController() {
        // The metadata endpoint is servlet-only, exactly like the rest of the web layer.
        nonWebRunner.withPropertyValues("jeap.jwe.enabled=false").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(JweMetadataController.class);
        });
    }
}
