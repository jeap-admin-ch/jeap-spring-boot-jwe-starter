package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestClient;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end test of the JWE metrics: boots the starter with actuator + a Prometheus registry in
 * static-key mode, drives real encrypted and failing requests, and asserts the {@code jeap.jwe.*}
 * meters both through the autowired {@link MeterRegistry} and via the {@code /actuator/prometheus}
 * scrape endpoint.
 */
@SpringBootTest(classes = {JweTestApplication.class, JweEchoController.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JweMetricsIT {

    @DynamicPropertySource
    static void jweProperties(DynamicPropertyRegistry registry) {
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.test.enabled", () -> true);
        registry.add("spring.cloud.vault.enabled", () -> false);
        registry.add("jeap.jwe.vault.transit-key-name", () -> "static-key");
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
        registry.add("jeap.jwe.test.keys[1]", () -> JweTestKeys.rsa4096Pem(1));
        registry.add("management.endpoints.web.exposure.include", () -> "prometheus,metrics");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private MeterRegistry meterRegistry;

    @Test
    void keyVersionAndGovernanceGaugesAreExposed() {
        assertThat(meterRegistry.get("jeap.jwe.keys.active").gauge().value()).isEqualTo(2.0);
        assertThat(meterRegistry.get("jeap.jwe.keys.current.version").gauge().value()).isEqualTo(2.0);
        // Default config enforces request + response encryption and keys are loaded -> E2E active.
        assertThat(meterRegistry.get("jeap.jwe.encryption.active").gauge().value()).isEqualTo(1.0);
    }

    @Test
    void successfulRoundTripIncrementsDecryptionAndResponseEncryptionMeters() throws Exception {
        double before = decryptionCount("success", "none");

        RSAKey publicKey = currentPublicKey();
        SecretKey responseCek = aes256();
        client().post().uri("/api/echo")
                .header("Content-Type", "application/jose")
                .header("Accept", "application/jose")
                .header("JWE-Response-Key", responseKeyEnvelope(publicKey, responseCek))
                .body(encryptRequest(publicKey, "{\"hello\":\"world\"}").getBytes(US_ASCII))
                .retrieve().toEntity(byte[].class);

        assertThat(decryptionCount("success", "none")).isEqualTo(before + 1);
        assertThat(meterRegistry.get("jeap.jwe.decryption").tag("result", "success").timer()
                .totalTime(java.util.concurrent.TimeUnit.NANOSECONDS)).isGreaterThan(0.0);
        assertThat(meterRegistry.get("jeap.jwe.response.encryption").tag("result", "success").counter().count())
                .isGreaterThanOrEqualTo(1.0);
    }

    @Test
    void failedDecryptionIsCountedWithReasonTag() {
        double before = decryptionCount("failure", "malformed");

        // A malformed JWE body triggers a MALFORMED protocol failure.
        try {
            client().post().uri("/api/echo")
                    .header("Content-Type", "application/jose")
                    .header("Accept", "application/jose")
                    .body("not-a-jwe")
                    .retrieve().toBodilessEntity();
        } catch (RuntimeException expected) {
            // 400 problem+json
        }

        assertThat(decryptionCount("failure", "malformed")).isEqualTo(before + 1);
    }

    @Test
    void metricsAreExportedOnThePrometheusScrapeEndpoint() {
        String scrape = client().get().uri("/actuator/prometheus").retrieve().body(String.class);
        assertThat(scrape)
                .contains("jeap_jwe_keys_active")
                .contains("jeap_jwe_encryption_active")
                .contains("jeap_jwe_decryption_seconds");
    }

    private double decryptionCount(String result, String reason) {
        var timer = meterRegistry.find("jeap.jwe.decryption").tag("result", result).tag("reason", reason).timer();
        return timer == null ? 0.0 : timer.count();
    }

    private RestClient client() {
        return RestClient.create("http://localhost:" + port);
    }

    private RSAKey currentPublicKey() throws Exception {
        String jwks = client().get().uri("/.well-known/jwks.json").retrieve().toEntity(String.class).getBody();
        return JWKSet.parse(Objects.requireNonNull(jwks)).getKeys().getFirst().toRSAKey();
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
}
