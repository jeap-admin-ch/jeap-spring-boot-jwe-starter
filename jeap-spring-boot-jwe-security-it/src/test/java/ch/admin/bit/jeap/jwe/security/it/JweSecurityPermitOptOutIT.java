package ch.admin.bit.jeap.jwe.security.it;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import ch.admin.bit.jeap.security.test.jws.JwsBuilder;
import ch.admin.bit.jeap.security.test.resource.configuration.JeapOAuth2IntegrationTestResourceConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * Opt-out regression with real jeap-security: with
 * {@code jeap.jwe.security.permit-well-known-endpoints=false} the JWE starter does not contribute its
 * security chain, so the JWKS endpoint falls through to jeap-security's protect-all chain and an
 * unauthenticated request is rejected with 401. Runs on its own port so it does not clash with the
 * cached {@link JweSecurityIntegrationIT} context (both use a fixed port).
 */
@SpringBootTest(
        classes = {JweSecurityTestApplication.class, SecuredEchoController.class},
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
                "server.port=28073",
                "spring.application.name=jwe-security-optout-it",
                "jeap.jwe.enabled=true",
                "jeap.jwe.test.enabled=true",
                "jeap.jwe.jwks.path=/jwe/jwks.json",
                "jeap.jwe.metadata.path=/jwe/jwe-configuration",
                "jeap.jwe.security.permit-well-known-endpoints=false",
                "jeap.jwe.vault.transit-key-name=static-key",
                "spring.cloud.vault.enabled=false",
                "jeap.security.oauth2.resourceserver.authorization-server.issuer=" + JwsBuilder.DEFAULT_ISSUER,
                "jeap.security.oauth2.resourceserver.authorization-server.jwk-set-uri=http://localhost:28073/.well-known/jwks.json"
        })
@Import(JeapOAuth2IntegrationTestResourceConfiguration.class)
class JweSecurityPermitOptOutIT {

    private static final int PORT = 28073;

    @DynamicPropertySource
    static void staticKeys(DynamicPropertyRegistry registry) {
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
    }

    @Test
    void jwksEndpointIsProtectedWhenOptedOut() {
        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class,
                () -> RestClient.create("http://localhost:" + PORT)
                        .get().uri("/jwe/jwks.json").retrieve().toBodilessEntity());
        assertThat(ex.getStatusCode().value()).isEqualTo(401);
    }
}
