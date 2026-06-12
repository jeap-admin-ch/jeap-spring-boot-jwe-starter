package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.List;

/**
 * Thin factory and policy layer around Nimbus JOSE+JWT for the JWE starter.
 *
 * <p>The in-memory key model is the Nimbus {@link RSAKey} itself - no custom key model or JWK
 * Set container is introduced. This class only adds what is genuinely ours: the 4096-bit
 * policy check, the {@code kid} scheme, and a factory that assembles an {@link RSAKey} (with
 * the JWE key use and algorithm) from a {@link KeyPair} or a PEM string.
 *
 * <p>All keys are validated on construction so every {@link RSAKey} handed out is guaranteed
 * to be exactly {@value #REQUIRED_KEY_SIZE_BITS} bits. The public JWK Set is produced by
 * Nimbus ({@link JWKSet#toPublicJWKSet()}), so private material is never emitted.
 */
public final class JweRsaKeys {

    /**
     * RSA keys must be exactly this size; smaller (and other) keys are rejected.
     */
    public static final int REQUIRED_KEY_SIZE_BITS = 4096;

    /**
     * Algorithm used to encrypt the content-encryption-key (RSA-OAEP-256).
     */
    public static final JWEAlgorithm KEY_ENCRYPTION_ALGORITHM = JWEAlgorithm.RSA_OAEP_256;

    private JweRsaKeys() {
    }

    /**
     * The {@code kid} scheme: {@code <transitKeyName>:<version>}. Deterministic, so
     * the Vault source and the static source produce identical kids for the same key, and a
     * public key can be mapped back to its decryption key version.
     */
    public static String keyId(String transitKeyName, int version) {
        if (transitKeyName == null || transitKeyName.isBlank()) {
            throw new JweKeyValidationException("transitKeyName must not be blank");
        }
        if (version < 1) {
            throw new JweKeyValidationException("Key version must be >= 1 but was " + version);
        }
        return transitKeyName + ":" + version;
    }

    /**
     * Builds a validated encryption {@link RSAKey} from a {@link KeyPair}. The private key is
     * included when present (the resulting {@link RSAKey} is then usable for decryption).
     */
    public static RSAKey from(KeyPair keyPair, String kid) {
        if (!(keyPair.getPublic() instanceof RSAPublicKey publicKey)) {
            throw new JweKeyValidationException(
                    "Expected an RSA public key but got " + describe(keyPair.getPublic().getAlgorithm()));
        }
        RSAKey.Builder builder = new RSAKey.Builder(publicKey)
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(KEY_ENCRYPTION_ALGORITHM)
                .keyID(kid);
        if (keyPair.getPrivate() != null) {
            builder.privateKey(keyPair.getPrivate());
        }
        return validated(builder.build());
    }

    /**
     * Parses a PEM-encoded RSA key (as exported by Vault transit) into a validated encryption
     * {@link RSAKey}, delegating PEM handling to {@link JWK#parseFromPEMEncodedObjects(String)}.
     */
    public static RSAKey fromPem(String pem, String kid) {
        JWK jwk;
        try {
            jwk = JWK.parseFromPEMEncodedObjects(pem);
        } catch (JOSEException e) {
            throw new JweKeyValidationException("Could not parse PEM-encoded RSA key", e);
        }
        if (!(jwk instanceof RSAKey parsed)) {
            throw new JweKeyValidationException("Expected an RSA key in PEM but got key type " + jwk.getKeyType());
        }
        RSAKey rebuilt = new RSAKey.Builder(parsed)
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(KEY_ENCRYPTION_ALGORITHM)
                .keyID(kid)
                .build();
        return validated(rebuilt);
    }

    /**
     * Returns a public-only {@link JWKSet} (RFC 7517) for the given keys. Private parameters
     * are stripped by Nimbus, not by hand.
     */
    public static JWKSet toPublicJwkSet(Collection<RSAKey> keys) {
        List<JWK> jwks = keys.stream().map(JWK.class::cast).toList();
        return new JWKSet(jwks).toPublicJWKSet();
    }

    /**
     * Serializes {@link #toPublicJwkSet(Collection)} to its RFC 7517 JSON representation.
     */
    public static String toPublicJwkSetJson(Collection<RSAKey> keys) {
        return toPublicJwkSet(keys).toString();
    }

    private static RSAKey validated(RSAKey key) {
        int size = key.size();
        if (size != REQUIRED_KEY_SIZE_BITS) {
            throw new JweKeyValidationException(
                    "RSA key size must be exactly " + REQUIRED_KEY_SIZE_BITS + " bits but was " + size + " bits");
        }
        return key;
    }

    private static String describe(String algorithm) {
        return algorithm == null ? "an unknown key type" : algorithm;
    }
}
