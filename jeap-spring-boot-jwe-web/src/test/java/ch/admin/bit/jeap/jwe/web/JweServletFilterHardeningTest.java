package ch.admin.bit.jeap.jwe.web;

import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import java.util.concurrent.atomic.AtomicReference;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Hardening behaviours of {@link JweServletFilter}: payload size limit (413), method scoping of
 * response encryption, and response-capture commit/error/empty handling. The response is always
 * encrypted with the client's {@code JWE-Response-Key} CEK, so the encrypted-request builder attaches
 * it together with {@code Accept: application/jose}.
 */
class JweServletFilterHardeningTest {

    private static final String KID = "harden-key:1";
    private static RSAKey key;
    private static JweKeyStore keyStore;

    @BeforeAll
    static void setUp() {
        key = JweRsaKeys.from(JweTestKeys.rsa4096(0), KID);
        keyStore = TestJweKeyStores.single(key);
    }

    private JweServletFilter filter(long maxPayloadBytes) {
        return new JweServletFilter(new JweFilterPaths(List.of("/**"), List.of()), keyStore,
                new JweFilterSettings(List.of("application/json"), "JWE-Response-Key", true, true,
                        JweFilterSettings.DEFAULT_PROBLEM_TYPE_BASE_URI, maxPayloadBytes));
    }

    private static SecretKey aes256() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    /**
     * An encrypted request body with its own (random) request CEK.
     */
    private String encryptedBody() throws Exception {
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(KID).contentType("application/json").build(),
                new Payload("{\"order\":42}"));
        jwe.encrypt(new RSAEncrypter(key.toRSAPublicKey()));
        return jwe.serialize();
    }

    /**
     * A {@code JWE-Response-Key} envelope wrapping the given response CEK.
     */
    private String responseKeyEnvelope(SecretKey responseCek) throws Exception {
        JWEObject envelope = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).keyID(KID).build(),
                new Payload(responseCek.getEncoded()));
        envelope.encrypt(new RSAEncrypter(key.toRSAPublicKey()));
        return envelope.serialize();
    }

    /**
     * An encrypted body request that also requests an encrypted response with the given CEK.
     */
    private MockHttpServletRequest encryptedRequest(String method, SecretKey responseCek) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/api/orders");
        request.setContentType(JweProtocol.APPLICATION_JOSE_VALUE);
        request.addHeader("Accept", "application/jose");
        request.addHeader("JWE-Response-Key", responseKeyEnvelope(responseCek));
        request.setContent(encryptedBody().getBytes(US_ASCII));
        return request;
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "PUT", "PATCH"})
    void decryptsBodyForAllBodyMethods(String method) throws Exception {
        MockHttpServletRequest request = encryptedRequest(method, aes256());
        AtomicReference<String> seenBody = new AtomicReference<>();
        FilterChain controller = (req, res) ->
                seenBody.set(new String(req.getInputStream().readAllBytes(), US_ASCII));

        filter(1_000_000).doFilter(request, new MockHttpServletResponse(), controller);

        assertThat(seenBody.get()).isEqualTo("{\"order\":42}");
    }

    @Test
    void oversizedRequestBodyYields413() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/orders");
        request.setContentType(JweProtocol.APPLICATION_JOSE_VALUE);
        request.setContent(encryptedBody().getBytes(US_ASCII));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter(8).doFilter(request, response, chain); // tiny limit, rejected before the controller

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentAsString()).contains("\"code\":\"JWE_PAYLOAD_TOO_LARGE\"");
        assertThat(chain.getRequest()).isNull();
    }

    @Test
    void deleteWithResponseKeyHeaderIsNotDecryptedAndPassesThrough() throws Exception {
        // Response encryption is scoped to GET/body methods; DELETE must not trigger RSA decryption of
        // attacker-supplied headers nor be rejected for a malformed envelope.
        MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/api/orders/1");
        request.addHeader("Accept", "application/jose");
        request.addHeader("JWE-Response-Key", "not-a-jwe");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter(1_000_000).doFilter(request, response, chain);

        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void controllerFlushBufferDoesNotPreventEncryption() throws Exception {
        MockHttpServletRequest request = encryptedRequest("POST", aes256());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain controller = (req, res) -> {
            res.setContentType("application/json");
            res.getOutputStream().write("{\"ok\":true}".getBytes(US_ASCII));
            res.flushBuffer();
        };

        filter(1_000_000).doFilter(request, response, controller);

        assertThat(response.getContentType()).isEqualTo(JweProtocol.APPLICATION_JOSE_VALUE);
    }

    @Test
    void errorStatusResponseIsNotEncrypted() throws Exception {
        MockHttpServletRequest request = encryptedRequest("POST", aes256());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain controller = (req, res) -> {
            ((HttpServletResponse) res).setStatus(500);
            res.setContentType("application/json");
            res.getOutputStream().write("{\"error\":\"boom\"}".getBytes(US_ASCII));
        };

        filter(1_000_000).doFilter(request, response, controller);

        assertThat(response.getStatus()).isEqualTo(500);
        assertThat(response.getContentType()).isEqualTo("application/json");
        assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"boom\"}");
        assertThat(response.getContentLength()).isEqualTo("{\"error\":\"boom\"}".getBytes(US_ASCII).length);
    }

    @Test
    void controllerSendErrorPassesThroughUnencrypted() throws Exception {
        MockHttpServletRequest request = encryptedRequest("POST", aes256());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain controller = (req, res) -> ((HttpServletResponse) res).sendError(404, "nope");

        filter(1_000_000).doFilter(request, response, controller);

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getContentType()).isNotEqualTo(JweProtocol.APPLICATION_JOSE_VALUE);
    }

    @Test
    void emptyResponseIsNotEncrypted() throws Exception {
        MockHttpServletRequest request = encryptedRequest("POST", aes256());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain controller = (req, res) -> ((HttpServletResponse) res).setStatus(204);

        filter(1_000_000).doFilter(request, response, controller);

        assertThat(response.getContentType()).isNotEqualTo(JweProtocol.APPLICATION_JOSE_VALUE);
        assertThat(response.getContentAsByteArray()).isEmpty();
    }

    @Test
    void downstreamAcceptHeaderIsRewrittenForContentNegotiation() throws Exception {
        // The client sends Accept: application/jose for enforcement, but the controller must see an
        // MVC-friendly Accept (the allowlist) so content negotiation matches its real output.
        MockHttpServletRequest request = encryptedRequest("POST", aes256());
        AtomicReference<String> downstreamAccept = new AtomicReference<>();
        FilterChain controller = (req, res) ->
                downstreamAccept.set(((HttpServletRequest) req).getHeader("Accept"));

        filter(1_000_000).doFilter(request, new MockHttpServletResponse(), controller);

        assertThat(downstreamAccept.get()).isEqualTo("application/json");
    }
}
