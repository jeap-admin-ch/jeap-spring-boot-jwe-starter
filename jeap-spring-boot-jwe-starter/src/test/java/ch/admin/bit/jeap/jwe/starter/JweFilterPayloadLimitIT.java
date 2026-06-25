package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import java.util.Objects;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * Verifies that an encrypted request exceeding {@code jeap.jwe.filter.max-payload-bytes} is rejected
 * with HTTP 413 over real HTTP (a real 4096-bit-key JWE comfortably exceeds the tiny limit set here).
 */
@SpringBootTest(classes = {JweTestApplication.class, JweEchoController.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JweFilterPayloadLimitIT {

    @DynamicPropertySource
    static void jweProperties(DynamicPropertyRegistry registry) {
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.test.enabled", () -> true);
        registry.add("spring.cloud.vault.enabled", () -> false);
        registry.add("jeap.jwe.vault.transit-key-name", () -> "limit-key");
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
        registry.add("jeap.jwe.filter.max-payload-bytes", () -> 128);
    }

    @LocalServerPort
    private int port;

    @Test
    void oversizedEncryptedRequestYields413() throws Exception {
        RSAKey publicKey = JWKSet.parse(Objects.requireNonNull(
                        RestClient.create("http://localhost:" + port)
                                .get().uri("/.well-known/jwks.json").retrieve().toEntity(String.class).getBody()))
                .getKeys().getFirst().toRSAKey();
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(publicKey.getKeyID()).contentType("application/json").build(),
                new Payload("{\"order\":42}"));
        jwe.encrypt(new RSAEncrypter(publicKey.toRSAPublicKey()));

        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class,
                () -> RestClient.create("http://localhost:" + port)
                        .post().uri("/api/echo")
                        .header("Content-Type", "application/jose")
                        .body(jwe.serialize().getBytes(US_ASCII))
                        .retrieve().toBodilessEntity());

        assertThat(ex.getStatusCode().value()).isEqualTo(413);
        assertThat(ex.getResponseBodyAsString()).contains("\"code\":\"JWE_PAYLOAD_TOO_LARGE\"");
    }
}
