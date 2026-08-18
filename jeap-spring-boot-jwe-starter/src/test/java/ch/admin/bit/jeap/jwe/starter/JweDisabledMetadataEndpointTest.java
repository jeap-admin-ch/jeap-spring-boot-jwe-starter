package ch.admin.bit.jeap.jwe.starter;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * Verifies that a service with {@code jeap.jwe.enabled=false} still answers the protocol-metadata
 * endpoint, publishing {@code "enabled": false}. A client loads this document before its first request
 * and must fail closed on an error, so a 404 here would make a frontend built with encryption turned on
 * unusable against a stage that has it turned off.
 */
@SpringBootTest(classes = JweTestApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "jeap.jwe.enabled=false",
                "spring.cloud.vault.enabled=false"
        })
class JweDisabledMetadataEndpointTest {

    @LocalServerPort
    private int port;

    @Test
    void metadataEndpointPublishesTheDisabledState() {
        ResponseEntity<String> response = RestClient.create("http://localhost:" + port)
                .get().uri("/.well-known/jwe-configuration")
                .retrieve().toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();
        assertThat(response.getBody()).isNotNull()
                .contains("\"enabled\":false")
                .contains("\"includedPaths\":[]")
                .contains("\"excludedPaths\":[]");
    }

    @Test
    void jwksEndpointStaysAbsent() {
        // Nothing but the metadata endpoint is contributed: there is no key material to serve.
        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class,
                () -> RestClient.create("http://localhost:" + port)
                        .get().uri("/.well-known/jwks.json").retrieve().toBodilessEntity());
        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
