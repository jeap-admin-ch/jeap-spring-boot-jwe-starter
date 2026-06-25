package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that overriding {@code jeap.jwe.jwks.path} moves the JWKS endpoint to the configured route,
 * and that the default route is then no longer served.
 */
@SpringBootTest(classes = JweTestApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JweJwksCustomPathTest {

    private static final String CUSTOM_PATH = "/internal/keys.json";

    @DynamicPropertySource
    static void jweProperties(DynamicPropertyRegistry registry) {
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.test.enabled", () -> true);
        registry.add("spring.cloud.vault.enabled", () -> false);
        registry.add("jeap.jwe.jwks.path", () -> CUSTOM_PATH);
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
    }

    @LocalServerPort
    private int port;

    @Test
    void customPathServesJwkSet() throws Exception {
        ResponseEntity<String> response = client()
                .get().uri(CUSTOM_PATH)
                .retrieve().toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(JWKSet.parse(response.getBody()).getKeys()).hasSize(1);
    }

    @Test
    void defaultPathNotServedWhenOverridden() {
        HttpStatusCode status = client()
                .get().uri("/.well-known/jwks.json")
                .exchange((_, response) -> response.getStatusCode());

        // The default path is no longer the JWKS route, and it is not an API path the filter applies
        // to, so it is simply not served (404) rather than a JWK set.
        assertThat(status).isEqualTo(HttpStatus.NOT_FOUND);
    }

    private RestClient client() {
        return RestClient.create("http://localhost:" + port);
    }
}
