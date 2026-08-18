package ch.admin.bit.jeap.jwe.security.it;

import ch.admin.bit.jeap.security.test.jws.JwsBuilder;
import ch.admin.bit.jeap.security.test.resource.configuration.JeapOAuth2IntegrationTestResourceConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * Proves that the disabled-state protocol metadata stays reachable with real jeap-security in front of it.
 * jeap-security protects every path by default, so without the JWE starter's own security chain a service
 * with {@code jeap.jwe.enabled=false} would answer the unauthenticated discovery request with 401 - and a
 * client cannot tell that apart from "not authenticated yet", so it could not follow the switch.
 *
 * <p>The endpoint is placed off {@code /.well-known/**} on purpose (see {@link JweSecurityIntegrationIT}):
 * the jeap-security test support already permits that prefix, so only a path outside it proves the permit
 * actually comes from the JWE starter. Runs on its own port so it does not clash with the other cached
 * contexts (all use a fixed port).
 */
@SpringBootTest(
        classes = {JweSecurityTestApplication.class, SecuredEchoController.class},
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
                "server.port=28074",
                "spring.application.name=jwe-security-disabled-it",
                "jeap.jwe.enabled=false",
                "jeap.jwe.jwks.path=/jwe/jwks.json",
                "jeap.jwe.metadata.path=/jwe/jwe-configuration",
                "spring.cloud.vault.enabled=false",
                "jeap.security.oauth2.resourceserver.authorization-server.issuer=" + JwsBuilder.DEFAULT_ISSUER,
                "jeap.security.oauth2.resourceserver.authorization-server.jwk-set-uri=http://localhost:28074/.well-known/jwks.json"
        })
@Import(JeapOAuth2IntegrationTestResourceConfiguration.class)
class JweSecurityDisabledMetadataIT {

    private static final int PORT = 28074;

    @Test
    void disabledMetadataReachableWithoutAuthentication() {
        ResponseEntity<String> response = RestClient.create("http://localhost:" + PORT)
                .get().uri("/jwe/jwe-configuration").retrieve().toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"enabled\":false");
    }

    @Test
    void jwksPathIsNotPermittedWhenDisabled() {
        // With JWE off there is no JWKS endpoint, so the path is left out of the permitting chain and
        // falls through to jeap-security's protect-all chain rather than being waved through to a 404.
        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class,
                () -> RestClient.create("http://localhost:" + PORT)
                        .get().uri("/jwe/jwks.json").retrieve().toBodilessEntity());
        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void applicationEndpointsStayProtected() {
        // The narrow permitting chain must not open anything else: the app's own paths keep needing a token.
        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class,
                () -> RestClient.create("http://localhost:" + PORT)
                        .get().uri("/api/secure/whoami").retrieve().toBodilessEntity());
        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
