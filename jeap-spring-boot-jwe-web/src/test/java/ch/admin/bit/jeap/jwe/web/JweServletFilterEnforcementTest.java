package ch.admin.bit.jeap.jwe.web;

import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.List;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies mandatory-encryption enforcement and the {@code application/problem+json} error
 * contract: each row of the HTTP error table maps to the right status and stable {@code code}.
 */
class JweServletFilterEnforcementTest {

    private static final String KID = "enf-key:1";
    private static RSAKey key;
    private static JweKeyStore keyStore;

    @BeforeAll
    static void setUp() {
        key = JweRsaKeys.from(JweTestKeys.rsa4096(0), KID);
        keyStore = TestJweKeyStores.single(key);
    }

    private JweServletFilter filter() {
        return new JweServletFilter(new JweFilterPaths(List.of("/**"), List.of("/actuator/**")), keyStore,
                new JweFilterSettings(List.of("application/json"), "JWE-Response-Key"));
    }

    private String jwe(JWEAlgorithm alg, EncryptionMethod enc, String kid, String cty) throws Exception {
        JWEHeader.Builder header = new JWEHeader.Builder(alg, enc).keyID(kid);
        if (cty != null) {
            header.contentType(cty);
        }
        JWEObject jwe = new JWEObject(header.build(), new Payload("{\"a\":1}"));
        jwe.encrypt(new RSAEncrypter(key.toRSAPublicKey()));
        return jwe.serialize();
    }

    private String runExpectingProblem(MockHttpServletRequest request, int expectedStatus) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter().doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(expectedStatus);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(chain.getRequest()).as("chain must not be invoked on a rejected request").isNull();
        String body = response.getContentAsString();
        assertThat(body).contains("\"status\":" + expectedStatus);
        assertThat(body).contains("\"type\":\"" + JweFilterSettings.DEFAULT_PROBLEM_TYPE_BASE_URI);
        return body;
    }

    private static MockHttpServletRequest post(String contentType, byte[] body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/orders");
        request.setContentType(contentType);
        request.setContent(body);
        return request;
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "PUT", "PATCH"})
    void plainBodyOnBodyMethodYields415(String method) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/api/orders");
        request.setContentType("application/json");
        request.setContent("{}".getBytes(US_ASCII));
        String problem = runExpectingProblem(request, 415);
        assertThat(problem).contains("\"code\":\"JWE_REQUEST_ENCRYPTION_REQUIRED\"")
                .contains("\"requiredContentType\":\"application/jose\"");
    }

    @Test
    void getWithoutJoseAcceptYields406() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders/1");
        request.addHeader("Accept", "application/json");
        String problem = runExpectingProblem(request, 406);
        assertThat(problem).contains("\"code\":\"JWE_RESPONSE_ENCRYPTION_REQUIRED\"")
                .contains("\"requiredAccept\":\"application/jose\"");
    }

    @Test
    void postWithValidBodyButNoResponseKeyYields406() throws Exception {
        // The body decrypts fine, but the client did not request an encrypted response.
        String body = jwe(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, KID, "application/json");
        String problem = runExpectingProblem(post("application/jose", body.getBytes(US_ASCII)), 406);
        assertThat(problem).contains("\"code\":\"JWE_RESPONSE_ENCRYPTION_REQUIRED\"");
    }

    @Test
    void getWithJoseAcceptButNoResponseKeyYields400() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders/1");
        request.addHeader("Accept", "application/jose");
        String problem = runExpectingProblem(request, 400);
        assertThat(problem).contains("\"code\":\"JWE_RESPONSE_KEY_REQUIRED\"")
                .contains("\"requiredHeader\":\"JWE-Response-Key\"");
    }

    @Test
    void getWithMalformedResponseKeyYields400() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders/1");
        request.addHeader("Accept", "application/jose");
        request.addHeader("JWE-Response-Key", "not-a-jwe");
        String problem = runExpectingProblem(request, 400);
        assertThat(problem).contains("\"code\":\"JWE_RESPONSE_KEY_INVALID\"");
    }

    @Test
    void malformedJweBodyYields400() throws Exception {
        String problem = runExpectingProblem(post("application/jose", "garbage".getBytes(US_ASCII)), 400);
        assertThat(problem).contains("\"code\":\"JWE_MALFORMED\"");
    }

    @Test
    void unknownKidYields400WithRefreshHint() throws Exception {
        String body = jwe(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, "missing:9", "application/json");
        String problem = runExpectingProblem(post("application/jose", body.getBytes(US_ASCII)), 400);
        assertThat(problem).contains("\"code\":\"JWE_UNKNOWN_KEY_ID\"")
                .containsIgnoringCase("refresh your JWKS");
    }

    @Test
    void unsupportedEncryptionMethodYields400() throws Exception {
        String body = jwe(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM, KID, "application/json");
        String problem = runExpectingProblem(post("application/jose", body.getBytes(US_ASCII)), 400);
        assertThat(problem).contains("\"code\":\"JWE_UNSUPPORTED_ALGORITHM\"");
    }

    @Test
    void disallowedContentTypeYields400() throws Exception {
        String body = jwe(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, KID, "text/plain");
        String problem = runExpectingProblem(post("application/jose", body.getBytes(US_ASCII)), 400);
        assertThat(problem).contains("\"code\":\"JWE_INVALID_CONTENT_TYPE\"");
    }

    @Test
    void excludedPathIsNotEnforced() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
        assertThat(filter().shouldNotFilter(request)).isTrue();
    }

    @Test
    void enforcementCanBeDisabled() throws Exception {
        JweServletFilter lenient = lenientFilter(JweFilterSettings.DEFAULT_MAX_PAYLOAD_BYTES);
        MockHttpServletRequest request = post("application/json", "{}".getBytes(US_ASCII));
        MockFilterChain chain = new MockFilterChain();

        lenient.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
    }

    @Test
    void lenientModeWithValidResponseKeyEncryptsResponse() throws Exception {
        SecretKey responseCek = aes256();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders/1");
        request.addHeader("JWE-Response-Key", responseKeyEnvelope(responseCek));
        MockHttpServletResponse response = new MockHttpServletResponse();

        lenientFilter(JweFilterSettings.DEFAULT_MAX_PAYLOAD_BYTES).doFilter(request, response, JSON_CONTROLLER);

        assertThat(response.getContentType()).isEqualTo(JweProtocol.APPLICATION_JOSE_VALUE);
        assertThat(decrypt(response, responseCek)).isEqualTo("{\"status\":\"ok\"}");
    }

    @Test
    void lenientModeWithMalformedResponseKeyYields400() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders/1");
        request.addHeader("JWE-Response-Key", "not-a-jwe");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        lenientFilter(JweFilterSettings.DEFAULT_MAX_PAYLOAD_BYTES).doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(chain.getRequest()).as("chain must not be invoked on a rejected request").isNull();
        assertThat(response.getContentAsString()).contains("\"code\":\"JWE_RESPONSE_KEY_INVALID\"");
    }

    @Test
    void lenientModeWithOversizedResponseKeyYields413() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders/1");
        request.addHeader("JWE-Response-Key", responseKeyEnvelope(aes256()));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        // A tiny payload limit makes any real envelope exceed maxPayloadBytes before RSA decryption.
        lenientFilter(16).doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(chain.getRequest()).as("chain must not be invoked on a rejected request").isNull();
        assertThat(response.getContentAsString()).contains("\"code\":\"JWE_PAYLOAD_TOO_LARGE\"");
    }

    private static JweServletFilter lenientFilter(long maxPayloadBytes) {
        return new JweServletFilter(new JweFilterPaths(List.of("/**"), List.of()), keyStore,
                new JweFilterSettings(List.of("application/json"), "JWE-Response-Key", false, false,
                        JweFilterSettings.DEFAULT_PROBLEM_TYPE_BASE_URI, maxPayloadBytes));
    }

    private static final FilterChain JSON_CONTROLLER = (request, response) -> {
        response.setContentType("application/json");
        response.getOutputStream().write("{\"status\":\"ok\"}".getBytes(UTF_8));
    };

    private static SecretKey aes256() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    private static String responseKeyEnvelope(SecretKey responseCek) throws Exception {
        JWEObject envelope = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).keyID(KID).build(),
                new Payload(responseCek.getEncoded()));
        envelope.encrypt(new RSAEncrypter(key.toRSAPublicKey()));
        return envelope.serialize();
    }

    private static String decrypt(MockHttpServletResponse response, SecretKey cek) throws Exception {
        JWEObject parsed = JWEObject.parse(new String(response.getContentAsByteArray(), US_ASCII));
        parsed.decrypt(new DirectDecrypter(cek));
        return parsed.getPayload().toString();
    }
}
