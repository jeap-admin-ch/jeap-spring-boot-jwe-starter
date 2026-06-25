package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that, under a {@code server.servlet.context-path}, the metadata endpoint publishes the
 * include/exclude path patterns and the JWKS path <strong>prefixed with the context path</strong>, so
 * a client matching full request URLs can use them directly against the origin. The configuration
 * properties themselves stay application-relative (the filter strips the context path before matching).
 */
@SpringBootTest(classes = JweTestApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JweMetadataContextPathTest {

    @DynamicPropertySource
    static void jweProperties(DynamicPropertyRegistry registry) {
        registry.add("server.servlet.context-path", () -> "/myapp");
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.test.enabled", () -> true);
        registry.add("spring.cloud.vault.enabled", () -> false);
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
        registry.add("jeap.jwe.filter.excluded-paths[0]", () -> "/api/public/**");
    }

    @LocalServerPort
    private int port;

    @Test
    void metadataPublishesContextPrefixedPaths() {
        ResponseEntity<String> response = RestClient.create("http://localhost:" + port)
                .get().uri("/myapp/.well-known/jwe-configuration")
                .retrieve().toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        String body = response.getBody();
        // Include, exclude and JWKS paths are all prefixed with the context path.
        assertThat(body).isNotNull()
                .contains("\"includedPaths\":[\"/myapp/*api*/**\"]")
                .contains("\"jwksPath\":\"/myapp/.well-known/jwks.json\"")
                .contains("\"/myapp/actuator/**\"")
                .contains("\"/myapp/.well-known/jwks.json\"")
                .contains("\"/myapp/.well-known/jwe-configuration\"")
                .contains("\"/myapp/api/public/**\"");
    }
}
