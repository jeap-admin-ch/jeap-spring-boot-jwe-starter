package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end test of the JWKS endpoint over real HTTP in static key mode (no Vault). Verifies
 * the default path, the newest-active-version-first ordering, and that no private material leaks.
 */
@SpringBootTest(classes = JweTestApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JweJwksEndpointTest {

    @DynamicPropertySource
    static void jweProperties(DynamicPropertyRegistry registry) {
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.test.enabled", () -> true);
        // Static test mode: no Vault - disable Spring Cloud Vault's own auto-configuration.
        registry.add("spring.cloud.vault.enabled", () -> false);
        registry.add("jeap.jwe.vault.transit-key-name", () -> "my-jwe-key");
        // Later entries are newer versions; the store orders them newest-first.
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
        registry.add("jeap.jwe.test.keys[1]", () -> JweTestKeys.rsa4096Pem(1));
    }

    @LocalServerPort
    private int port;

    @Test
    void getDefaultPathReturnsPublicJwkSetNewestKeyFirst() throws Exception {
        ResponseEntity<String> response = RestClient.create("http://localhost:" + port)
                .get().uri("/.well-known/jwks.json")
                .retrieve().toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();

        String body = response.getBody();
        assertThat(body).isNotNull();

        JWKSet jwkSet = JWKSet.parse(body);
        assertThat(jwkSet.getKeys()).hasSize(2);
        // Newest active version (highest version = my-jwe-key:2) must be exposed first (keys[0]).
        assertThat(jwkSet.getKeys().get(0).getKeyID()).isEqualTo("my-jwe-key:2");
        assertThat(jwkSet.getKeys().get(1).getKeyID()).isEqualTo("my-jwe-key:1");

        // Only public material is returned: no private RSA parameters in the JSON.
        assertThat(body)
                .doesNotContain("\"d\":")
                .doesNotContain("\"p\":")
                .doesNotContain("\"q\":")
                .doesNotContain("\"dp\":")
                .doesNotContain("\"dq\":")
                .doesNotContain("\"qi\":");
        assertThat(jwkSet.getKeys()).allSatisfy(key -> assertThat(key.isPrivate()).isFalse());
    }
}
