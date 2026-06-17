package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import ch.admin.bit.jeap.jwe.web.JweJwksController;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the servlet gating of the JWKS endpoint registration: the controller is registered
 * only for a servlet web application and only when the starter is enabled. Reactive stacks are not
 * supported and a non-web context must not register it.
 */
class JweWebAutoConfigurationTest {

    private static final String[] STATIC_MODE = {
            "jeap.jwe.enabled=true",
            "jeap.jwe.test.enabled=true",
            "jeap.jwe.test.keys[0]=" + JweTestKeys.rsa4096Pem(0)
    };

    private final WebApplicationContextRunner servletRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class, JweWebAutoConfiguration.class));

    private final ApplicationContextRunner nonWebRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JweAutoConfiguration.class, JweWebAutoConfiguration.class));

    @Test
    void servletAppEnabledRegistersJwksController() {
        servletRunner.withPropertyValues(STATIC_MODE).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JweJwksController.class);
        });
    }

    @Test
    void nonWebAppRegistersControllerAndKeyStore() {
        nonWebRunner.withPropertyValues(STATIC_MODE).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JweJwksController.class);
            assertThat(context).hasSingleBean(JweKeyStore.class);
        });
    }

    @Test
    void servletAppDisabledDoesNotRegisterController() {
        servletRunner.withPropertyValues("jeap.jwe.enabled=false").run(context ->
                assertThat(context).doesNotHaveBean(JweJwksController.class));
    }
}
