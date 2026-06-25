package ch.admin.bit.jeap.jwe.web;

import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the request-decryption behaviour of {@link JweServletFilter}: an encrypted request body is
 * decrypted and the controller (here, the downstream filter chain) sees plaintext with the {@code cty}
 * content type. Response encryption is disabled here to keep the focus on request decryption.
 */
class JweServletFilterDecryptionTest {

    private static final String KID = "filter-test-key:1";
    private static final String PLAINTEXT = "{\"order\":42}";
    private static RSAKey key;
    private static JweKeyStore keyStore;

    @BeforeAll
    static void setUp() {
        key = JweRsaKeys.from(JweTestKeys.rsa4096(0), KID);
        keyStore = TestJweKeyStores.single(key);
    }

    private JweServletFilter filter() {
        // require-encrypted-request = true, require-encrypted-response = false (this test ignores responses).
        return new JweServletFilter(
                new JweFilterPaths(List.of("/**"), List.of()),
                keyStore,
                new JweFilterSettings(List.of("application/json"), "JWE-Response-Key", true, false,
                        JweFilterSettings.DEFAULT_PROBLEM_TYPE_BASE_URI, JweFilterSettings.DEFAULT_MAX_PAYLOAD_BYTES));
    }

    private JweServletFilter filterAllowing(String... contentTypes) {
        return new JweServletFilter(
                new JweFilterPaths(List.of("/**"), List.of()),
                keyStore,
                new JweFilterSettings(List.of(contentTypes), "JWE-Response-Key", true, false,
                        JweFilterSettings.DEFAULT_PROBLEM_TYPE_BASE_URI, JweFilterSettings.DEFAULT_MAX_PAYLOAD_BYTES));
    }

    private String encryptedBody() throws Exception {
        return encrypted("application/json", PLAINTEXT.getBytes(UTF_8));
    }

    private String encrypted(String cty, byte[] payload) throws Exception {
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(KID)
                        .contentType(cty)
                        .build(),
                new Payload(payload));
        jwe.encrypt(new RSAEncrypter(key.toRSAPublicKey()));
        return jwe.serialize();
    }

    @Test
    void decryptsJweRequestSoControllerSeesPlaintextJson() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/orders");
        request.setContentType(JweProtocol.APPLICATION_JOSE_VALUE);
        request.setContent(encryptedBody().getBytes(US_ASCII));
        MockFilterChain chain = new MockFilterChain();

        filter().doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest downstream = (HttpServletRequest) chain.getRequest();
        assertThat(downstream.getContentType()).isEqualTo("application/json");
        assertThat(downstream.getHeader("Content-Type")).isEqualTo("application/json");
        assertThat(new String(downstream.getInputStream().readAllBytes(), UTF_8)).isEqualTo(PLAINTEXT);
        assertThat(downstream.getContentLength()).isEqualTo(PLAINTEXT.getBytes(UTF_8).length);
    }

    @Test
    void decryptsAllowedTextContentType() throws Exception {
        // A non-JSON content type on the allowlist decrypts and is surfaced as the downstream cty.
        String text = "the quick brown fox";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/notes");
        request.setContentType(JweProtocol.APPLICATION_JOSE_VALUE);
        request.setContent(encrypted("text/plain", text.getBytes(UTF_8)).getBytes(US_ASCII));
        MockFilterChain chain = new MockFilterChain();

        filterAllowing("application/json", "text/plain").doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest downstream = (HttpServletRequest) chain.getRequest();
        assertThat(downstream.getContentType()).isEqualTo("text/plain");
        assertThat(new String(downstream.getInputStream().readAllBytes(), UTF_8)).isEqualTo(text);
    }

    @Test
    void decryptsAllowedBinaryOctetStreamContentType() throws Exception {
        // Binary payloads survive byte-for-byte: the filter never assumes the plaintext is text/JSON.
        byte[] binary = {0, 1, 2, (byte) 0xFF, (byte) 0x80, 0x7F, 0x00, (byte) 0xAB, (byte) 0xCD};
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/blobs");
        request.setContentType(JweProtocol.APPLICATION_JOSE_VALUE);
        request.setContent(encrypted("application/octet-stream", binary).getBytes(US_ASCII));
        MockFilterChain chain = new MockFilterChain();

        filterAllowing("application/octet-stream").doFilter(request, new MockHttpServletResponse(), chain);

        HttpServletRequest downstream = (HttpServletRequest) chain.getRequest();
        assertThat(downstream.getContentType()).isEqualTo("application/octet-stream");
        assertThat(downstream.getInputStream().readAllBytes()).isEqualTo(binary);
    }

    @Test
    void plainJsonPostIsRejectedWith415() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/orders");
        request.setContentType("application/json");
        request.setContent(PLAINTEXT.getBytes(UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter().doFilter(request, response, chain);

        // Mandatory encryption is enforced for body methods.
        assertThat(response.getStatus()).isEqualTo(415);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(chain.getRequest()).isNull();
    }
}
