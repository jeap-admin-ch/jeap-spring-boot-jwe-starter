package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.web.JweJwksController;
import jakarta.annotation.PostConstruct;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Registers the web-facing parts of the JWE starter.
 */
@AutoConfiguration(after = JweAutoConfiguration.class)
@ConditionalOnProperty(prefix = "jeap.jwe", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JweWebAutoConfiguration {

    private static final String DEFAULT_ACTUATOR_BASE_PATH = "/actuator";

    private final JweProperties properties;
    private final Environment environment;

    public JweWebAutoConfiguration(JweProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @Bean
    @ConditionalOnBean(JweKeyStore.class)
    @ConditionalOnMissingBean
    JweJwksController jweJwksController(JweKeyStore keyStore) {
        return new JweJwksController(keyStore);
    }

    /**
     * Fails fast if the configured JWKS path collides with the actuator base path.
     */
    @PostConstruct
    void validateJwksPathDoesNotClashWithActuator() {
        String jwksPath = properties.getJwks().getPath();
        String actuatorBasePath = environment.getProperty(
                "management.endpoints.web.base-path", DEFAULT_ACTUATOR_BASE_PATH);
        if (jwksPath.equals(actuatorBasePath) || jwksPath.startsWith(actuatorBasePath + "/")) {
            throw new IllegalStateException(
                    "Configured JWKS path '%s' overlaps the actuator base path '%s'. Configure a distinct jeap.jwe.jwks.path."
                            .formatted(jwksPath, actuatorBasePath));
        }
    }
}
