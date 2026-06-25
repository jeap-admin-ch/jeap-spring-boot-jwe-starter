package ch.admin.bit.jeap.jwe.starter;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.*;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.web.client.RestClient;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * End-to-end integration test of the full JWE starter lifecycle backed by a real Vault dev container.
 * Exercises auto-configuration, Vault-backed startup key loading, the JWKS endpoint over real HTTP,
 * periodic key refresh picking up Vault rotations, and min-version eviction - all wired together
 * with no mocking.
 *
 * <p>Tests are ordered because they exercise a sequential lifecycle: startup → rotation → eviction.
 *
 * <p>The whole suite runs under a {@code server.servlet.context-path} so the full-fledged end-to-end
 * path (JWKS, encrypted round-trips) is exercised the way jEAP apps are typically deployed.
 */
@SpringBootTest(classes = {JweTestApplication.class, JweEchoController.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
// Test helpers chain several Nimbus/JCA calls that each throw a different checked exception; declaring
// the 'throws Exception' union is idiomatic JUnit, so S112 is suppressed for this test class.
@SuppressWarnings("java:S112")
class JweStarterVaultIT {

    private static final String TOKEN = "root-token";
    private static final String ENGINE = "transit";
    private static final String KEY_NAME = "jwe-e2e-key";
    private static final String CONTEXT_PATH = "/myapp";
    private static final String APPLICATION_JOSE = "application/jose";

    @SuppressWarnings("resource")
    private static final VaultContainer<?> VAULT =
            new VaultContainer<>(DockerImageName.parse("hashicorp/vault:1.21.2")
                    .asCompatibleSubstituteFor("hashicorp/vault"))
                    .withVaultToken(TOKEN)
                    .withInitCommand(
                            "secrets enable transit",
                            "write -f transit/keys/" + KEY_NAME + " type=rsa-4096 exportable=true");
    public static final String KEYS = "/keys/";

    static {
        VAULT.start();
    }

    private static VaultOperations vaultOps;

    @BeforeAll
    static void setupVaultClient() {
        VaultEndpoint endpoint = VaultEndpoint.from(URI.create(VAULT.getHttpHostAddress()));
        vaultOps = new VaultTemplate(endpoint, new TokenAuthentication(TOKEN));
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("server.servlet.context-path", () -> CONTEXT_PATH);
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.vault.transit-key-name", () -> KEY_NAME);
        registry.add("jeap.jwe.vault.secret-engine-path", () -> ENGINE);
        registry.add("jeap.jwe.refresh.interval", () -> "1s");
        registry.add("spring.cloud.vault.uri", VAULT::getHttpHostAddress);
        registry.add("spring.cloud.vault.token", () -> TOKEN);
        registry.add("spring.cloud.vault.authentication", () -> "TOKEN");
    }

    @LocalServerPort
    private int port;

    @Test
    @Order(1)
    void startupJwksEndpointReturnsPublicKeysWithNoPrivateMaterial() throws Exception {
        ResponseEntity<String> response = jwksGet();
        String body = response.getBody();
        assertThat(body).isNotNull();

        JWKSet jwkSet = JWKSet.parse(body);
        assertThat(jwkSet.getKeys()).isNotEmpty();
        assertThat(jwkSet.getKeys().getFirst().getKeyID()).isEqualTo(KEY_NAME + ":1");

        // No private RSA parameters in the HTTP response.
        assertThat(body)
                .doesNotContain("\"d\":")
                .doesNotContain("\"p\":")
                .doesNotContain("\"q\":")
                .doesNotContain("\"dp\":")
                .doesNotContain("\"dq\":")
                .doesNotContain("\"qi\":");
        assertThat(jwkSet.getKeys()).allSatisfy(key -> assertThat(key.isPrivate()).isFalse());
    }

    @Test
    @Order(2)
    void refreshPicksUpRotatedKeyAsNewestVersion() throws Exception {
        // Rotate the transit key: latest_version becomes 2.
        vaultOps.write(ENGINE + KEYS + KEY_NAME + "/rotate", Map.of());

        // Wait for the periodic refresh to pick up the new version via the real HTTP endpoint.
        await().atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(500))
                .untilAsserted(() -> {
                    JWKSet jwkSet = JWKSet.parse(Objects.requireNonNull(jwksGet().getBody()));
                    assertThat(jwkSet.getKeys()).hasSizeGreaterThanOrEqualTo(2);
                    // Newest version is served first.
                    assertThat(jwkSet.getKeys().getFirst().getKeyID()).isEqualTo(KEY_NAME + ":2");
                });

        // Prior version remains available.
        JWKSet jwkSet = JWKSet.parse(Objects.requireNonNull(jwksGet().getBody()));
        assertThat(jwkSet.getKeys()).extracting(JWK::getKeyID).contains(KEY_NAME + ":1");
    }

    @Test
    @Order(3)
    void refreshEvictsVersionsBelowMinDecryptionVersion() {
        // Rotate once more so we have versions 1, 2, 3.
        vaultOps.write(ENGINE + KEYS + KEY_NAME + "/rotate", Map.of());

        await().atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(500))
                .untilAsserted(() -> {
                    JWKSet jwkSet = JWKSet.parse(Objects.requireNonNull(jwksGet().getBody()));
                    assertThat(jwkSet.getKeys().getFirst().getKeyID()).isEqualTo(KEY_NAME + ":3");
                });

        // Advance min_decryption_version to evict versions 1 and 2.
        vaultOps.write(ENGINE + KEYS + KEY_NAME + "/config", Map.of("min_decryption_version", 3));

        // Wait for the refresh to evict old versions from the JWKS response.
        await().atMost(Duration.ofSeconds(10))
                .pollInterval(Duration.ofMillis(500))
                .untilAsserted(() -> {
                    JWKSet jwkSet = JWKSet.parse(Objects.requireNonNull(jwksGet().getBody()));
                    assertThat(jwkSet.getKeys()).hasSize(1);
                    assertThat(jwkSet.getKeys().getFirst().getKeyID()).isEqualTo(KEY_NAME + ":3");
                });
    }

    @Test
    @Order(4)
    void postRoundTripDecryptsRequestAndEncryptsResponseWithRealVaultKey() throws Exception {
        // Real-key proof: encrypt the request against the live Vault-exported public key and decrypt
        // the response with the separate response CEK we supplied in the JWE-Response-Key header.
        RSAKey publicKey = currentPublicKey();
        // Precondition: after the eviction test (Order 3) only version 3 remains active.
        assertThat(publicKey.getKeyID()).isEqualTo(KEY_NAME + ":3");
        SecretKey responseCek = aes256();
        String requestJwe = encryptRequest(publicKey, "{\"order\":\"42\"}");

        ResponseEntity<byte[]> response = RestClient.create(baseUrl())
                .post().uri("/api/echo")
                .header("Content-Type", APPLICATION_JOSE)
                .header("Accept", APPLICATION_JOSE)
                .header("JWE-Response-Key", encryptResponseKeyEnvelope(publicKey, responseCek))
                .body(requestJwe.getBytes(US_ASCII))
                .retrieve().toEntity(byte[].class);

        assertThat(Objects.requireNonNull(response.getHeaders().getContentType()))
                .hasToString(APPLICATION_JOSE);
        assertThat(decryptResponse(response.getBody(), responseCek)).contains("\"order\":\"42\"");
    }

    @Test
    @Order(5)
    void getRoundTripEncryptsResponseWithResponseKeyEnvelope() throws Exception {
        RSAKey publicKey = currentPublicKey();
        assertThat(publicKey.getKeyID()).isEqualTo(KEY_NAME + ":3");
        SecretKey cek = aes256();
        String envelope = encryptResponseKeyEnvelope(publicKey, cek);

        ResponseEntity<byte[]> response = RestClient.create(baseUrl())
                .get().uri("/api/echo")
                .header("Accept", APPLICATION_JOSE)
                .header("JWE-Response-Key", envelope)
                .retrieve().toEntity(byte[].class);

        assertThat(Objects.requireNonNull(response.getHeaders().getContentType()))
                .hasToString(APPLICATION_JOSE);
        assertThat(decryptResponse(response.getBody(), cek)).contains("\"message\":\"hello\"");
    }

    private RSAKey currentPublicKey() throws Exception {
        JWKSet jwkSet = JWKSet.parse(Objects.requireNonNull(jwksGet().getBody()));
        return jwkSet.getKeys().getFirst().toRSAKey();
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

    private static String encryptResponseKeyEnvelope(RSAKey publicKey, SecretKey cek) throws Exception {
        JWEObject envelope = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(publicKey.getKeyID()).build(),
                new Payload(cek.getEncoded()));
        envelope.encrypt(new RSAEncrypter(publicKey.toRSAPublicKey()));
        return envelope.serialize();
    }

    private static String decryptResponse(byte[] body, SecretKey cek) throws Exception {
        JWEObject parsed = JWEObject.parse(new String(Objects.requireNonNull(body), US_ASCII));
        parsed.decrypt(new DirectDecrypter(cek));
        return new String(parsed.getPayload().toBytes(), UTF_8);
    }

    private String baseUrl() {
        return "http://localhost:" + port + CONTEXT_PATH;
    }

    private ResponseEntity<String> jwksGet() {
        return RestClient.create(baseUrl())
                .get().uri("/.well-known/jwks.json")
                .retrieve().toEntity(String.class);
    }
}

