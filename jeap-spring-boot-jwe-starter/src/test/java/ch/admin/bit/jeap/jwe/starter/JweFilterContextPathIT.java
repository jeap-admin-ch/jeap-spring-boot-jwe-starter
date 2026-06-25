package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end test that the filter works correctly when the application is deployed under a
 * {@code server.servlet.context-path} (the common jEAP setup). The include/exclude patterns are
 * application-relative, so the default API include still matches {@code /myapp/api/...} after the
 * context path is stripped, while a non-API path under the same context is left untouched. The JWKS
 * and metadata endpoints remain reachable under the context path too.
 */
@SpringBootTest(classes = {JweTestApplication.class, JweEchoController.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JweFilterContextPathIT {

    private static final String CONTEXT_PATH = "/myapp";

    @DynamicPropertySource
    static void jweProperties(DynamicPropertyRegistry registry) {
        registry.add("server.servlet.context-path", () -> CONTEXT_PATH);
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.test.enabled", () -> true);
        registry.add("spring.cloud.vault.enabled", () -> false);
        registry.add("jeap.jwe.vault.transit-key-name", () -> "static-key");
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
    }

    @LocalServerPort
    private int port;

    @Test
    void encryptedRoundTripWorksUnderContextPath() throws Exception {
        RSAKey publicKey = publicKey();
        SecretKey responseCek = aes256();

        ResponseEntity<byte[]> response = client().post().uri("/api/echo")
                .header("Content-Type", "application/jose")
                .header("Accept", "application/jose")
                .header("JWE-Response-Key", responseKeyEnvelope(publicKey, responseCek))
                .body(encryptRequest(publicKey, "{\"secret\":\"ctx\"}").getBytes(US_ASCII))
                .retrieve().toEntity(byte[].class);

        assertThat(contentType(response)).isEqualTo("application/jose");
        assertThat(decrypt(response.getBody(), responseCek)).contains("ctx");
    }

    @Test
    void nonApiPathUnderContextPathIsServedPlain() {
        ResponseEntity<String> response = client().get().uri("/public/info")
                .retrieve().toEntity(String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).contains("\"info\":\"public\"");
    }

    @Test
    void jwksAndMetadataAreReachableUnderContextPath() {
        assertThat(client().get().uri("/.well-known/jwks.json").retrieve().toEntity(String.class).getBody())
                .contains("\"keys\"");
        assertThat(client().get().uri("/.well-known/jwe-configuration").retrieve().toEntity(String.class).getBody())
                .contains("\"includedPaths\":[\"/myapp/*api*/**\"]");
    }

    // --- Helpers (the test acts as the client, using the context-rooted base URL) ----------------

    private RestClient client() {
        return RestClient.create("http://localhost:" + port + CONTEXT_PATH);
    }

    private RSAKey publicKey() throws Exception {
        String jwks = client().get().uri("/.well-known/jwks.json").retrieve().toEntity(String.class).getBody();
        return JWKSet.parse(Objects.requireNonNull(jwks)).getKeys().get(0).toRSAKey();
    }

    private static SecretKey aes256() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    private static String encryptRequest(RSAKey publicKey, String json) throws Exception {
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(publicKey.getKeyID()).contentType("application/json").build(),
                new Payload(json));
        jwe.encrypt(new RSAEncrypter(publicKey.toRSAPublicKey()));
        return jwe.serialize();
    }

    private static String responseKeyEnvelope(RSAKey publicKey, SecretKey cek) throws Exception {
        JWEObject envelope = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(publicKey.getKeyID()).build(),
                new Payload(cek.getEncoded()));
        envelope.encrypt(new RSAEncrypter(publicKey.toRSAPublicKey()));
        return envelope.serialize();
    }

    private static String decrypt(byte[] body, SecretKey cek) throws Exception {
        JWEObject parsed = JWEObject.parse(new String(Objects.requireNonNull(body), US_ASCII));
        parsed.decrypt(new DirectDecrypter(cek));
        return new String(parsed.getPayload().toBytes(), UTF_8);
    }

    private static String contentType(ResponseEntity<byte[]> response) {
        return Objects.requireNonNull(response.getHeaders().getContentType()).toString();
    }
}
