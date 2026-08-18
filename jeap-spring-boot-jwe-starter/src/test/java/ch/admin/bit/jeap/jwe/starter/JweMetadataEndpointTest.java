package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
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
 * Verifies the protocol-metadata endpoint: it is served as plain JSON at the configured path,
 * is excluded from encryption (no 406 enforcement), and reflects the live content-type allowlist
 * and the effective include/exclude path patterns.
 */
@SpringBootTest(classes = JweTestApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JweMetadataEndpointTest {

    @DynamicPropertySource
    static void jweProperties(DynamicPropertyRegistry registry) {
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.test.enabled", () -> true);
        registry.add("spring.cloud.vault.enabled", () -> false);
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
        registry.add("jeap.jwe.filter.content-type-allowlist[0]", () -> "application/json");
        registry.add("jeap.jwe.filter.content-type-allowlist[1]", () -> "application/cbor");
        // A custom exclude on top of the built-in jEAP defaults, to assert it surfaces in the metadata.
        registry.add("jeap.jwe.filter.excluded-paths[0]", () -> "/api/public/**");
    }

    @LocalServerPort
    private int port;

    @Test
    void metadataEndpointIsServedUnencryptedAndReflectsConfiguration() {
        ResponseEntity<String> response = RestClient.create("http://localhost:" + port)
                .get().uri("/.well-known/jwe-configuration")
                .retrieve().toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();

        String body = response.getBody();
        // Effective include is the default API pattern; excludes carry the jEAP defaults plus the custom one.
        assertThat(body).isNotNull()
                .contains("\"enabled\":true")
                .contains("\"contentTypeAllowlist\":[\"application/json\",\"application/cbor\"]")
                .contains("\"keyEncryptionAlgorithm\":\"RSA-OAEP-256\"")
                .contains("\"contentEncryptionMethod\":\"A256GCM\"")
                .contains("\"jwksPath\":\"/.well-known/jwks.json\"")
                .contains("\"responseKeyHeader\":\"JWE-Response-Key\"")
                .contains("\"includedPaths\":[\"/*api*/**\"]")
                .contains("\"excludedPaths\":[")
                .contains("\"/actuator/**\"")
                .contains("\"/.well-known/jwks.json\"")
                .contains("\"/.well-known/jwe-configuration\"")
                .contains("\"/api/public/**\"");
    }
}
