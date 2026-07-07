package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Optional;
import java.util.Set;

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
        key = newKey(KID);
    }

    private static RSAKey newKey(String kid) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey(pair.getPrivate())
                .keyID(kid)
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

    @Test
    void unknownCriticalHeaderParameterIsRejected() throws Exception {
        // RFC 7516 requires rejecting a JWE whose 'crit' header lists parameters this recipient
        // does not process, instead of silently ignoring them.
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(KID)
                        .customParam("foo", "bar")
                        .criticalParams(Set.of("foo"))
                        .build(),
                new Payload(PLAINTEXT));
        jwe.encrypt(new RSAEncrypter(key.toRSAPublicKey()));

        JweProtocolException ex = catchThrowableOfType(JweProtocolException.class,
                () -> JweRequestDecryptor.decrypt(jwe.serialize(), resolver()));
        assertThat(ex.getReason()).isEqualTo(JweProtocolException.Reason.DECRYPTION_FAILED);
    }

    @Test
    void emptyIvOrAuthTagIsRejected() throws Exception {
        // JWEObject.parse turns an empty IV or auth-tag segment into null; such incomplete JWEs
        // must surface as a categorised protocol error, not an unhandled NPE.
        String compact = encrypt(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM, KID, "application/json");
        String[] parts = compact.split("\\.");
        String emptyIv = String.join(".", parts[0], parts[1], "", parts[3], parts[4]);
        String emptyAuthTag = String.join(".", parts[0], parts[1], parts[2], parts[3], "");

        for (String crafted : List.of(emptyIv, emptyAuthTag)) {
            JweProtocolException ex = catchThrowableOfType(JweProtocolException.class,
                    () -> JweRequestDecryptor.decrypt(crafted, resolver()));
            assertThat(ex.getReason()).isEqualTo(JweProtocolException.Reason.DECRYPTION_FAILED);
        }
    }

    @Test
    void decrypterIsCachedPerKeyAndEvictedByRetainOnly() throws Exception {
        RSAKey valueEqualCopy = new RSAKey.Builder(key).build();
        RSAKey rotatedKey = newKey("test-key:2");

        JweRsaOaep256Decrypter cached = JweRequestDecryptor.decrypterFor(KID, key);

        // Value-equal keys (as produced by store refreshes) reuse the cached decrypter; a rotated
        // key version gets its own.
        assertThat(JweRequestDecryptor.decrypterFor(KID, valueEqualCopy)).isSameAs(cached);
        assertThat(JweRequestDecryptor.decrypterFor("test-key:2", rotatedKey)).isNotSameAs(cached);

        // Retaining only the rotated key evicts the retired version's decrypter, so a later lookup
        // derives a fresh one.
        JweRequestDecryptor.retainOnly(List.of(rotatedKey));
        assertThat(JweRequestDecryptor.decrypterFor(KID, key)).isNotSameAs(cached);
    }

    @Test
    void keyWithoutPrivatePartIsRejectedAndNotCached() {
        RSAKey publicOnly = key.toPublicJWK();

        // The failed derivation must not poison the cache: every attempt fails the same way instead
        // of returning a broken cached decrypter.
        for (int attempt = 0; attempt < 2; attempt++) {
            JweProtocolException ex = catchThrowableOfType(JweProtocolException.class,
                    () -> JweRequestDecryptor.decrypterFor(KID, publicOnly));
            assertThat(ex.getReason()).isEqualTo(JweProtocolException.Reason.DECRYPTION_FAILED);
        }
    }
}
