package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for {@link JweRequestDecryptor}: a JWE built with Nimbus round-trips to the original
 * plaintext, and protocol violations surface as categorised {@link JweProtocolException}s. A 2048-bit
 * key keeps the test fast (the decryptor does not enforce key size; that is {@link JweRsaKeys}' job).
 */
class JweRequestDecryptorTest {

    private static final String KID = "test-key:1";
    private static final String PLAINTEXT = "{\"hello\":\"world\"}";
    private static RSAKey key;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        key = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey(pair.getPrivate())
                .keyID(KID)
                .build();
    }

    private JweRequestDecryptor.PrivateKeyResolver resolver() {
        return keyId -> KID.equals(keyId) ? Optional.of(key) : Optional.empty();
    }

    private String encrypt(JWEAlgorithm alg, EncryptionMethod enc, String kid, String cty) throws Exception {
        JWEHeader.Builder header = new JWEHeader.Builder(alg, enc);
        if (kid != null) {
            header.keyID(kid);
        }
        if (cty != null) {
            header.contentType(cty);
        }
        JWEObject jwe = new JWEObject(header.build(), new Payload(PLAINTEXT));
        jwe.encrypt(new RSAEncrypter(key.toRSAPublicKey()));
        return jwe.serialize();
    }

    @Test
    void decryptionWithWrongPrivateKeyFails() throws Exception {
        // Encrypt to a different key pair but resolve the kid to our key -> RSA-OAEP unwrap fails.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAPublicKey otherPublic = (RSAPublicKey) generator.generateKeyPair().getPublic();
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(KID).contentType("application/json").build(),
                new Payload(PLAINTEXT));
        jwe.encrypt(new RSAEncrypter(otherPublic));

        JweProtocolException ex = catchThrowableOfType(JweProtocolException.class,
                () -> JweRequestDecryptor.decrypt(jwe.serialize(), resolver()));
        assertThat(ex.getReason()).isEqualTo(JweProtocolException.Reason.DECRYPTION_FAILED);
    }

    @Test
    void decryptsValidJweToPlaintextWithCty() throws Exception {
        String compact = encrypt(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, KID, "application/json");

        DecryptedJwe decrypted = JweRequestDecryptor.decrypt(compact, resolver());

        assertThat(new String(decrypted.plaintext(), UTF_8)).isEqualTo(PLAINTEXT);
        assertThat(decrypted.contentType()).isEqualTo("application/json");
    }

    @Test
    void malformedTokenIsRejected() {
        assertThatThrownBy(() -> JweRequestDecryptor.decrypt("not-a-valid-jwe", resolver()))
                .isInstanceOfSatisfying(JweProtocolException.class,
                        e -> assertThat(e.getReason()).isEqualTo(JweProtocolException.Reason.MALFORMED));
    }

    @Test
    void unsupportedEncryptionMethodIsRejected() throws Exception {
        String compact = encrypt(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM, KID, "application/json");

        JweProtocolException ex = catchThrowableOfType(JweProtocolException.class,
                () -> JweRequestDecryptor.decrypt(compact, resolver()));
        assertThat(ex.getReason()).isEqualTo(JweProtocolException.Reason.UNSUPPORTED_ALGORITHM);
    }

    @Test
    void missingKeyIdIsRejected() throws Exception {
        String compact = encrypt(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, null, "application/json");

        JweProtocolException ex = catchThrowableOfType(JweProtocolException.class,
                () -> JweRequestDecryptor.decrypt(compact, resolver()));
        assertThat(ex.getReason()).isEqualTo(JweProtocolException.Reason.MISSING_KEY_ID);
    }

    @Test
    void unknownKeyIdIsRejected() throws Exception {
        String compact = encrypt(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, "other-key:9", "application/json");

        JweProtocolException ex = catchThrowableOfType(JweProtocolException.class,
                () -> JweRequestDecryptor.decrypt(compact, resolver()));
        assertThat(ex.getReason()).isEqualTo(JweProtocolException.Reason.UNKNOWN_KEY_ID);
    }
}
