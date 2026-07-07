package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link JweRsaOaep256Decrypter}'s guard branches; the happy path is covered by the
 * round-trip tests in {@link JweRequestDecryptorTest}. A 2048-bit key keeps the test fast (the
 * decrypter does not enforce key size; that is {@link JweRsaKeys}' job).
 */
class JweRsaOaep256DecrypterTest {

    private static final Base64URL DUMMY = Base64URL.encode(new byte[12]);

    private static KeyPair keyPair;
    private static JweRsaOaep256Decrypter decrypter;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        decrypter = new JweRsaOaep256Decrypter(keyPair.getPrivate());
    }

    @Test
    void unsupportedAlgorithmIsRejected() {
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_384, EncryptionMethod.A256GCM);

        assertThatThrownBy(() -> decrypter.decrypt(header, DUMMY, DUMMY, DUMMY, DUMMY, new byte[0]))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("Unsupported JWE algorithm");
    }

    @Test
    void missingEncryptedKeyIsRejected() {
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

        assertThatThrownBy(() -> decrypter.decrypt(header, null, DUMMY, DUMMY, DUMMY, new byte[0]))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("Missing JWE encrypted key");
    }

    @Test
    void missingIvIsRejected() {
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

        assertThatThrownBy(() -> decrypter.decrypt(header, DUMMY, null, DUMMY, DUMMY, new byte[0]))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("Missing JWE initialization vector");
    }

    @Test
    void missingAuthTagIsRejected() {
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

        assertThatThrownBy(() -> decrypter.decrypt(header, DUMMY, DUMMY, DUMMY, null, new byte[0]))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("Missing JWE authentication tag");
    }

    @Test
    void unknownCriticalHeaderParameterIsRejected() {
        // RFC 7516 requires rejecting a JWE whose 'crit' header lists parameters this recipient
        // does not process.
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .customParam("foo", "bar")
                .criticalParams(Set.of("foo"))
                .build();

        assertThatThrownBy(() -> decrypter.decrypt(header, DUMMY, DUMMY, DUMMY, DUMMY, new byte[0]))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("critical");
    }

    @Test
    void wrongLengthCekIsRejected() throws Exception {
        // A CEK that unwraps correctly but is 128-bit instead of the 256 bits A256GCM requires.
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        Base64URL wrappedShortCek = Base64URL.encode(cipher.doFinal(new byte[16]));
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

        assertThatThrownBy(() -> decrypter.decrypt(header, wrappedShortCek, DUMMY, DUMMY, DUMMY, new byte[0]))
                .isInstanceOf(JOSEException.class)
                .hasMessageContaining("length");
    }
}
