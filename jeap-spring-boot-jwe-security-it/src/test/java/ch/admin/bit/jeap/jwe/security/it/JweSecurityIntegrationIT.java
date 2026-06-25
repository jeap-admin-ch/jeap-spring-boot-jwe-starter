package ch.admin.bit.jeap.jwe.security.it;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import ch.admin.bit.jeap.security.resource.token.JeapAuthenticationContext;
import ch.admin.bit.jeap.security.test.jws.JwsBuilder;
import ch.admin.bit.jeap.security.test.jws.JwsBuilderFactory;
import ch.admin.bit.jeap.security.test.resource.configuration.JeapOAuth2IntegrationTestResourceConfiguration;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * End-to-end integration test proving that the JWE starter and {@code jeap-spring-boot-security-starter}
 * coexist on the same servlet chain. jeap-security authenticates the request (Bearer token, filter chain
 * at order {@code -100}) and the JWE filter (order {@code 0}) then transparently decrypts the request body
 * and encrypts the response — the two are independent, which this test pins down across the full matrix:
 *
 * <table border="1">
 *   <caption>Coexistence matrix (authentication × encryption)</caption>
 *   <tr><th></th><th>encrypted (under {@code /*api*})</th><th>not encrypted</th></tr>
 *   <tr><th>OAuth-protected</th><td>{@code /api/secure/**} — token + JWE round-trip</td><td>(enforced: 406/415)</td></tr>
 *   <tr><th>public</th><td>{@code /api/public/**} — JWE round-trip, no token</td><td>{@code /public/**} — plain, no token</td></tr>
 * </table>
 *
 * <p>Ordering is asserted too: an unauthenticated call to a protected path is rejected (401) by security
 * <em>before</em> any RSA decryption, while an authenticated-but-unencrypted call is rejected (406/415) by
 * the JWE filter <em>after</em> authentication. Encryption applies regardless of authentication — a public
 * {@code /api/public/**} endpoint is still encrypted, and the relevant security customization
 * ({@link PublicEndpointsSecurityConfiguration}) only opens the public paths; jeap-security protects
 * everything else by default, with no OAuth wiring of our own.
 *
 * <p><strong>Public discovery endpoints.</strong> The JWE JWKS and protocol-metadata endpoints are placed
 * under {@code /jwe/**} (<em>not</em> {@code /.well-known/**}) on purpose: jeap-security protects every
 * path by default, and the jeap-security test support already permits {@code /.well-known/**} (where it
 * serves its own token-signing JWKS at {@code /.well-known/jwks.json}). Keeping the JWE endpoints off
 * {@code /.well-known/**} means their unauthenticated reachability can only come from the JWE starter's
 * own security auto-configuration ({@code JweSecurityAutoConfiguration}) — so the test actually exercises
 * that feature rather than the test support. The happy-path tests fetch the public key over an
 * unauthenticated {@code GET}, and {@link #jweJwksReachableWithoutAuthentication()} /
 * {@link #jweMetadataReachableWithoutAuthentication()} assert it directly.
 */
@SpringBootTest(
        classes = {JweSecurityTestApplication.class, SecuredEchoController.class,
                PublicEndpointsController.class, PublicEndpointsSecurityConfiguration.class},
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
                "server.port=28072",
                "spring.application.name=jwe-security-it",
                "jeap.jwe.enabled=true",
                "jeap.jwe.test.enabled=true",
                // Off /.well-known/** on purpose: reachability must come from the JWE starter's own
                // security auto-configuration, not the jeap-security test support's /.well-known/** permit.
                "jeap.jwe.jwks.path=/jwe/jwks.json",
                "jeap.jwe.metadata.path=/jwe/jwe-configuration",
                "jeap.jwe.vault.transit-key-name=static-key",
                "spring.cloud.vault.enabled=false",
                // Validate the test tokens against the jeap-security test-support JWKS mock served by this app.
                "jeap.security.oauth2.resourceserver.authorization-server.issuer=" + JwsBuilder.DEFAULT_ISSUER,
                "jeap.security.oauth2.resourceserver.authorization-server.jwk-set-uri=http://localhost:28072/.well-known/jwks.json"
        })
@Import(JeapOAuth2IntegrationTestResourceConfiguration.class)
// Test helpers chain several Nimbus/JCA calls that each throw a different checked exception; declaring
// the 'throws Exception' union is idiomatic JUnit, so S112 is suppressed for this test class.
@SuppressWarnings("java:S112")
class JweSecurityIntegrationIT {

    private static final int PORT = 28072;
    private static final String JWE_JWKS_PATH = "/jwe/jwks.json";
    private static final String JWE_METADATA_PATH = "/jwe/jwe-configuration";
    private static final String SUBJECT = "11111111-1111-1111-1111-111111111111";
    private static final String SECRET_MARKER = "sup3r-secret-marker-42";
    private static final String SECURE_ECHO_PATH = "/api/secure/echo";
    private static final String SECURE_WHOAMI_PATH = "/api/secure/whoami";
    private static final String APPLICATION_JOSE = "application/jose";
    private static final String APPLICATION_JSON = "application/json";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String HEADER_CONTENT_TYPE = "Content-Type";
    private static final String HEADER_ACCEPT = "Accept";
    private static final String HEADER_RESPONSE_KEY = "JWE-Response-Key";
    private static final String BEARER_PREFIX = "Bearer ";

    @Autowired
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    private JwsBuilderFactory jwsBuilderFactory;

    @DynamicPropertySource
    static void staticKeys(DynamicPropertyRegistry registry) {
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
    }

    // --- Happy paths -----------------------------------------------------------------------------

    @Test
    void authenticatedEncryptedPostRoundTrips() throws Exception {
        RSAKey publicKey = jwePublicKey();
        SecretKey responseCek = aes256();

        ResponseEntity<byte[]> response = client().post().uri(SECURE_ECHO_PATH)
                .header(HEADER_AUTHORIZATION, BEARER_PREFIX + validToken())
                .header(HEADER_CONTENT_TYPE, APPLICATION_JOSE)
                .header(HEADER_ACCEPT, APPLICATION_JOSE)
                .header(HEADER_RESPONSE_KEY, responseKeyEnvelope(publicKey, responseCek))
                .body(encryptRequest(publicKey, "{\"secret\":\"" + SECRET_MARKER + "\"}").getBytes(US_ASCII))
                .retrieve().toEntity(byte[].class);

        assertThat(contentType(response)).isEqualTo(APPLICATION_JOSE);
        assertThat(decrypt(response.getBody(), responseCek)).contains(SECRET_MARKER);
    }

    @Test
    void authenticatedEncryptedGetReturnsEncryptedPrincipal() throws Exception {
        RSAKey publicKey = jwePublicKey();
        SecretKey responseCek = aes256();

        ResponseEntity<byte[]> response = client().get().uri(SECURE_WHOAMI_PATH)
                .header(HEADER_AUTHORIZATION, BEARER_PREFIX + validToken())
                .header(HEADER_ACCEPT, APPLICATION_JOSE)
                .header(HEADER_RESPONSE_KEY, responseKeyEnvelope(publicKey, responseCek))
                .retrieve().toEntity(byte[].class);

        assertThat(contentType(response)).isEqualTo(APPLICATION_JOSE);
        assertThat(decrypt(response.getBody(), responseCek)).contains(SUBJECT);
    }

    // --- Non-OAuth endpoints (public) ------------------------------------------------------------

    @Test
    void publicEncryptedEndpointRoundTripsWithoutAuthentication() throws Exception {
        // non-OAuth + encrypted: /api/public is permitted without a token, yet still matches the JWE
        // include (/*api*), so the body is decrypted and the response encrypted just like a secured path.
        RSAKey publicKey = jwePublicKey();
        SecretKey responseCek = aes256();

        ResponseEntity<byte[]> response = client().post().uri("/api/public/echo")
                .header(HEADER_CONTENT_TYPE, APPLICATION_JOSE)
                .header(HEADER_ACCEPT, APPLICATION_JOSE)
                .header(HEADER_RESPONSE_KEY, responseKeyEnvelope(publicKey, responseCek))
                .body(encryptRequest(publicKey, "{\"secret\":\"" + SECRET_MARKER + "\"}").getBytes(US_ASCII))
                .retrieve().toEntity(byte[].class);

        assertThat(contentType(response)).isEqualTo(APPLICATION_JOSE);
        assertThat(decrypt(response.getBody(), responseCek)).contains(SECRET_MARKER);
    }

    @Test
    void publicPlainEndpointServedWithoutAuthenticationOrEncryption() {
        // non-OAuth + non-encrypted: /public is neither secured nor under /*api*, so it is served as
        // plain JSON without a token and without any JWE involvement.
        ResponseEntity<String> response = client().get().uri("/public/info")
                .retrieve().toEntity(String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getContentType().toString()).startsWith(APPLICATION_JSON);
        assertThat(response.getBody()).contains("\"info\":\"public\"");
    }

    // --- Public discovery endpoints (opened by the JWE starter's security auto-configuration) -----

    @Test
    void jweJwksReachableWithoutAuthentication() {
        // /jwe/** is not under the test-support's /.well-known/** permit, so a 200 here proves the JWE
        // starter's own security chain opened it - jeap-security would otherwise reject it with 401.
        int status = client().get().uri(JWE_JWKS_PATH)
                .retrieve().toBodilessEntity().getStatusCode().value();
        assertThat(status).isEqualTo(200);
    }

    @Test
    void jweMetadataReachableWithoutAuthentication() {
        int status = client().get().uri(JWE_METADATA_PATH)
                .retrieve().toBodilessEntity().getStatusCode().value();
        assertThat(status).isEqualTo(200);
    }

    // --- Ordering: security gates before the JWE filter ------------------------------------------

    @Test
    void unauthenticatedRequestToSecuredPathIsRejectedBeforeDecryption() {
        // No token on a protected path: jeap-security (order -100) rejects with 401 before the JWE filter
        // (order 0) performs any RSA work.
        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class,
                () -> client().get().uri(SECURE_WHOAMI_PATH)
                        .header(HEADER_ACCEPT, APPLICATION_JOSE)
                        .retrieve().toBodilessEntity());

        assertThat(ex.getStatusCode().value()).isEqualTo(401);
    }

    // --- Ordering: the JWE filter still enforces encryption after auth ---------------------------

    @Test
    void authenticatedPlaintextPostIsRejectedByJweFilter() {
        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class,
                () -> client().post().uri(SECURE_ECHO_PATH)
                        .header(HEADER_AUTHORIZATION, BEARER_PREFIX + validToken())
                        .header(HEADER_CONTENT_TYPE, APPLICATION_JSON)
                        .body("{\"plain\":true}")
                        .retrieve().toBodilessEntity());

        assertThat(ex.getStatusCode().value()).isEqualTo(415);
        assertThat(ex.getResponseBodyAsString()).contains("\"code\":\"JWE_REQUEST_ENCRYPTION_REQUIRED\"");
    }

    @Test
    void authenticatedGetWithoutJoseAcceptIsRejectedByJweFilter() {
        HttpClientErrorException ex = catchThrowableOfType(HttpClientErrorException.class,
                () -> client().get().uri(SECURE_WHOAMI_PATH)
                        .header(HEADER_AUTHORIZATION, BEARER_PREFIX + validToken())
                        .header(HEADER_ACCEPT, APPLICATION_JSON)
                        .retrieve().toBodilessEntity());

        assertThat(ex.getStatusCode().value()).isEqualTo(406);
        assertThat(ex.getResponseBodyAsString()).contains("\"code\":\"JWE_RESPONSE_ENCRYPTION_REQUIRED\"");
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private String validToken() {
        return jwsBuilderFactory.createValidForFixedLongPeriodBuilder(SUBJECT, JeapAuthenticationContext.SYS)
                .build().serialize();
    }

    private RestClient client() {
        return RestClient.create("http://localhost:" + PORT);
    }

    private RSAKey jwePublicKey() throws Exception {
        String jwks = client().get().uri(JWE_JWKS_PATH).retrieve().toEntity(String.class).getBody();
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
                        .keyID(publicKey.getKeyID()).contentType(APPLICATION_JSON).build(),
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
