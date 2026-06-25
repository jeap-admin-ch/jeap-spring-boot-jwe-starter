package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * Vault-free end-to-end integration test of the JWE servlet filter in static test mode: a
 * real servlet context, a real HTTP client, and static keys - no Vault, no Docker. Owns the broad
 * filter contract (happy paths, multi-version, exclusions, the full error table, statelessness, no
 * secret leakage). The Vault key lifecycle and the real-Vault-key round trip stay in
 * {@link JweStarterVaultIT}.
 */
@SpringBootTest(classes = {JweTestApplication.class, JweEchoController.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class JweFilterStaticModeIT {

    private static final String SECRET_MARKER = "sup3r-secret-marker-42";

    @DynamicPropertySource
    static void jweProperties(DynamicPropertyRegistry registry) {
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.test.enabled", () -> true);
        registry.add("spring.cloud.vault.enabled", () -> false);
        registry.add("jeap.jwe.vault.transit-key-name", () -> "static-key");
        // Two versions to exercise multi-version decryption; the store orders them newest-first.
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
        registry.add("jeap.jwe.test.keys[1]", () -> JweTestKeys.rsa4096Pem(1));
    }

    @LocalServerPort
    private int port;

    // --- Happy paths -----------------------------------------------------------------------------

    @Test
    void postRoundTripDecryptsRequestAndEncryptsResponse() throws Exception {
        RSAKey publicKey = publicKey(0);
        SecretKey responseCek = aes256();

        ResponseEntity<byte[]> response = postEncrypted(publicKey, responseCek,
                "{\"secret\":\"" + SECRET_MARKER + "\"}");

        assertThat(contentType(response)).isEqualTo("application/jose");
        assertThat(decrypt(response.getBody(), responseCek)).contains(SECRET_MARKER);
    }

    @Test
    void getRoundTripEncryptsResponseWithResponseKeyEnvelope() throws Exception {
        RSAKey publicKey = publicKey(0);
        SecretKey cek = aes256();

        ResponseEntity<byte[]> response = client().get().uri("/api/echo")
                .header("Accept", "application/jose")
                .header("JWE-Response-Key", responseKeyEnvelope(publicKey, cek))
                .retrieve().toEntity(byte[].class);

        assertThat(contentType(response)).isEqualTo("application/jose");
        assertThat(decrypt(response.getBody(), cek)).contains("\"message\":\"hello\"");
    }

    @Test
    void requestEncryptedWithOlderActiveKeyVersionStillDecrypts() throws Exception {
        // keys[1] is the older version (the JWK set is newest-first, so index 1 is the prior version).
        RSAKey olderKey = publicKey(1);
        SecretKey responseCek = aes256();

        ResponseEntity<byte[]> response = postEncrypted(olderKey, responseCek, "{\"v\":\"old\"}");

        assertThat(decrypt(response.getBody(), responseCek)).contains("\"v\":\"old\"");
    }

    @Test
    void statelessAcrossIndependentRequests() throws Exception {
        // Two independent round trips, each with its own request and response CEK, succeed without
        // any shared state.
        for (int i = 0; i < 2; i++) {
            SecretKey responseCek = aes256();
            ResponseEntity<byte[]> response = postEncrypted(publicKey(0), responseCek, "{\"i\":" + i + "}");
            assertThat(decrypt(response.getBody(), responseCek)).contains("\"i\":" + i);
        }
    }

    // --- Exclusions ------------------------------------------------------------------------------

    @Test
    void jwksAndMetadataEndpointsAreExcludedAndServedPlain() {
        assertThat(client().get().uri("/.well-known/jwks.json").retrieve().toEntity(String.class).getBody())
                .contains("\"keys\"");
        assertThat(client().get().uri("/.well-known/jwe-configuration").retrieve().toEntity(String.class).getBody())
                .contains("contentTypeAllowlist");
    }

    @Test
    void nonApiPathIsNotFilteredAndServedPlain() {
        // The default include "/*api*" leaves non-API paths (static resources, the SPA shell) alone:
        // a plain GET to /public/info is served as plain JSON, not rejected with 406.
        ResponseEntity<String> response = client().get().uri("/public/info").retrieve().toEntity(String.class);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).contains("\"info\":\"public\"");
    }

    // --- Error table -----------------------------------------------------------------------------

    @Test
    void plainJsonPostYields415() {
        assertProblem(() -> client().post().uri("/api/echo")
                .header("Content-Type", "application/json").body("{}")
                .retrieve().toBodilessEntity(), 415, "JWE_REQUEST_ENCRYPTION_REQUIRED");
    }

    @Test
    void getWithoutJoseAcceptYields406() {
        assertProblem(() -> client().get().uri("/api/echo")
                .header("Accept", "application/json")
                .retrieve().toBodilessEntity(), 406, "JWE_RESPONSE_ENCRYPTION_REQUIRED");
    }

    @Test
    void getWithJoseAcceptButNoResponseKeyYields400() {
        assertProblem(() -> client().get().uri("/api/echo")
                .header("Accept", "application/jose")
                .retrieve().toBodilessEntity(), 400, "JWE_RESPONSE_KEY_REQUIRED");
    }

    @Test
    void malformedJweYields400() {
        assertProblem(() -> client().post().uri("/api/echo")
                .header("Content-Type", "application/jose").body("garbage")
                .retrieve().toBodilessEntity(), 400, "JWE_MALFORMED");
    }

    @Test
    void unknownKidYields400WithRefreshHint() throws Exception {
        RSAKey publicKey = publicKey(0);
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID("static-key:99").contentType("application/json").build(),
                new Payload("{}"));
        jwe.encrypt(new RSAEncrypter(publicKey.toRSAPublicKey()));
        String body = jwe.serialize();

        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class,
                () -> client().post().uri("/api/echo")
                        .header("Content-Type", "application/jose").body(body)
                        .retrieve().toBodilessEntity());
        assertThat(ex.getStatusCode().value()).isEqualTo(400);
        assertThat(ex.getResponseBodyAsString()).contains("\"code\":\"JWE_UNKNOWN_KEY_ID\"")
                .containsIgnoringCase("refresh your JWKS");
    }

    // --- No secret leakage -----------------------------------------------------------------------

    @Test
    void doesNotLogPlaintextOrKeyMaterial(CapturedOutput output) throws Exception {
        SecretKey responseCek = aes256();

        postEncrypted(publicKey(0), responseCek, "{\"secret\":\"" + SECRET_MARKER + "\"}");

        assertThat(output.getAll())
                .doesNotContain(SECRET_MARKER)
                .doesNotContain(Base64.getEncoder().encodeToString(responseCek.getEncoded()))
                .doesNotContain(Base64.getUrlEncoder().withoutPadding().encodeToString(responseCek.getEncoded()));
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private RestClient client() {
        return RestClient.create("http://localhost:" + port);
    }

    private RSAKey publicKey(int index) throws Exception {
        String jwks = client().get().uri("/.well-known/jwks.json").retrieve().toEntity(String.class).getBody();
        return JWKSet.parse(Objects.requireNonNull(jwks)).getKeys().get(index).toRSAKey();
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

    /**
     * POSTs an encrypted body and requests an encrypted response with the given response CEK.
     */
    private ResponseEntity<byte[]> postEncrypted(RSAKey publicKey, SecretKey responseCek, String json) throws Exception {
        return client().post().uri("/api/echo")
                .header("Content-Type", "application/jose")
                .header("Accept", "application/jose")
                .header("JWE-Response-Key", responseKeyEnvelope(publicKey, responseCek))
                .body(encryptRequest(publicKey, json).getBytes(US_ASCII))
                .retrieve().toEntity(byte[].class);
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

    private static void assertProblem(org.assertj.core.api.ThrowableAssert.ThrowingCallable call,
                                      int expectedStatus, String expectedCode) {
        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class, call);
        assertThat(ex).as("expected an HTTP error").isNotNull();
        assertThat(ex.getStatusCode().value()).isEqualTo(expectedStatus);
        assertThat(ex.getResponseBodyAsString()).contains("\"code\":\"" + expectedCode + "\"");
    }
}
