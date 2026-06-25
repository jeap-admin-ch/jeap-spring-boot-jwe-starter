package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * Unit tests for {@link JweResponseEncryptor}: direct encryption round-trips with a given CEK, and a
 * {@code JWE-Response-Key} envelope is unwrapped to the CEK it carries.
 */
class JweResponseEncryptorTest {

    private static final String KID = "resp-key:1";
    private static RSAKey rsaKey;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        rsaKey = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey(pair.getPrivate())
                .keyID(KID)
                .build();
    }

    private static SecretKey aes256() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }

    @Test
    void encryptsWithDirectEncryptionAndRoundTrips() throws Exception {
        SecretKey cek = aes256();
        String payload = "{\"result\":\"ok\"}";

        String compact = JweResponseEncryptor.encrypt(payload.getBytes(UTF_8), cek, "application/json");

        JWEObject parsed = JWEObject.parse(compact);
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWEAlgorithm.DIR);
        assertThat(parsed.getHeader().getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
        assertThat(parsed.getHeader().getContentType()).isEqualTo("application/json");
        parsed.decrypt(new DirectDecrypter(cek));
        assertThat(parsed.getPayload()).hasToString(payload);
    }

    @Test
    void recoversResponseCekFromEnvelope() throws Exception {
        SecretKey cek = aes256();
        JWEObject envelope = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).keyID(KID).build(),
                new Payload(cek.getEncoded()));
        envelope.encrypt(new RSAEncrypter(rsaKey.toRSAPublicKey()));

        SecretKey recovered = JweResponseEncryptor.recoverResponseCek(
                envelope.serialize(), keyId -> KID.equals(keyId) ? Optional.of(rsaKey) : Optional.empty());

        assertThat(recovered.getEncoded()).isEqualTo(cek.getEncoded());
    }

    @Test
    void rejectsResponseKeyEnvelopeWithWrongLengthPayload() throws Exception {
        // A 16-byte payload is not a valid 256-bit CEK.
        JWEObject envelope = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).keyID(KID).build(),
                new Payload(new byte[16]));
        envelope.encrypt(new RSAEncrypter(rsaKey.toRSAPublicKey()));

        JweProtocolException ex = catchThrowableOfType(JweProtocolException.class,
                () -> JweResponseEncryptor.recoverResponseCek(envelope.serialize(),
                        keyId -> KID.equals(keyId) ? Optional.of(rsaKey) : Optional.empty()));
        assertThat(ex.getReason()).isEqualTo(JweProtocolException.Reason.MALFORMED);
    }
}
