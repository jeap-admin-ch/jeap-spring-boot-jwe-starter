package ch.admin.bit.jeap.jwe.starter;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
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

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * End-to-end integration test of the full JWE starter lifecycle backed by a real Vault dev container.
 * Exercises auto-configuration, Vault-backed startup key loading, the JWKS endpoint over real HTTP,
 * periodic key refresh picking up Vault rotations, and min-version eviction - all wired together
 * with no mocking.
 *
 * <p>Tests are ordered because they exercise a sequential lifecycle: startup → rotation → eviction.
 */
@SpringBootTest(classes = JweTestApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JweStarterVaultIT {

    private static final String TOKEN = "root-token";
    private static final String ENGINE = "transit";
    private static final String KEY_NAME = "jwe-e2e-key";

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

    private ResponseEntity<String> jwksGet() {
        return RestClient.create("http://localhost:" + port)
                .get().uri("/.well-known/jwks.json")
                .retrieve().toEntity(String.class);
    }
}

