package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.web.JweConfigurationMetadata;
import ch.admin.bit.jeap.jwe.web.JweMetadataController;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Keeps the protocol-metadata endpoint answering when the starter is switched off
 * ({@code jeap.jwe.enabled=false}), so a client can discover that state instead of having to be
 * configured with its own copy of the switch.
 *
 * <p>Without this, {@link JweWebAutoConfiguration} - and with it the {@link JweMetadataController} -
 * backs off entirely and the endpoint answers {@code 404}. A client that loads the metadata before its
 * first request cannot distinguish that from an unreachable or misconfigured backend, so it must fail
 * closed rather than silently send plaintext. The result is that a frontend built with encryption
 * turned on is unusable against a stage that has it turned off - exactly the deployment parity this
 * endpoint exists to support. Answering {@code 200} with {@code "enabled": false} lets the same
 * frontend artifact run on every stage.
 *
 * <p>The published document carries only the switch: with no filter, no key material and no JWKS
 * endpoint in the context there is nothing else to advertise (see
 * {@link JweConfigurationMetadata#disabled()}). Nothing else of the starter is contributed - the
 * endpoint is read-only and holds no security-sensitive material.
 *
 * <p>Set {@code jeap.jwe.metadata.publish-when-disabled=false} to keep the pre-existing behaviour and
 * have a disabled starter contribute no endpoint at all.
 *
 * <p>{@link JweProperties} is enabled here as well: {@link JweAutoConfiguration}, which normally does
 * it, is gated on the very switch that has to be {@code false} for this configuration to apply, so the
 * properties bean would not exist otherwise.
 *
 * <p>Ordered <em>after</em> {@link JweWebAutoConfiguration} so the {@code @ConditionalOnMissingBean}
 * on the controller can see that configuration's bean definition and really back off. The two are
 * mutually exclusive through their {@code jeap.jwe.enabled} conditions today; the guard keeps a
 * duplicate {@code @RestController} on the same path from becoming an ambiguous-mapping startup
 * failure should that ever drift.
 */
@Slf4j
@AutoConfiguration(after = JweWebAutoConfiguration.class)
@EnableConfigurationProperties(JweProperties.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "jeap.jwe", name = "enabled", havingValue = "false")
@ConditionalOnProperty(prefix = "jeap.jwe.metadata", name = "publish-when-disabled",
        havingValue = "true", matchIfMissing = true)
public class JweDisabledMetadataAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(JweMetadataController.class)
    JweMetadataController jweDisabledMetadataController() {
        log.info("jEAP JWE encryption is disabled. Publishing the disabled state at the protocol-metadata " +
                "endpoint so clients can follow the switch; set jeap.jwe.metadata.publish-when-disabled=false " +
                "to suppress the endpoint.");
        return new JweMetadataController(JweConfigurationMetadata.disabled());
    }
}
