package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Decrypts an inbound compact JWE into plaintext using the starter's supported algorithms
 * (RSA-OAEP-256 for the CEK, A256GCM for the payload).
 *
 * <p>This is a thin layer over Nimbus and the JCA - no cryptographic primitive is implemented. The
 * CEK unwrap is routed through the generic JCA OAEP transformation so the Amazon Corretto Crypto
 * Provider serves the RSA private-key operation (see {@link JweRsaOaep256Decrypter}), and the
 * decrypter incl. the derived JCA private key is cached per key version. The request's
 * content-encryption key is not exposed: response encryption uses a separate CEK from the client's
 * {@code JWE-Response-Key} header. All failures are surfaced as a categorised
 * {@link JweProtocolException}.
 */
public final class JweRequestDecryptor {

    // Ready-to-use decrypter per key, so the JCA private key is derived from the JWK parameters
    // (an expensive KeyFactory operation) only once per key version instead of on every decrypt
    // call. Keys are value-equal across store refreshes, so an unchanged key version keeps hitting
    // the same entry; retired versions are evicted via retainOnly on every key refresh so their
    // private key material becomes garbage-collectible. Key material never leaves the JVM heap.
    private static final ConcurrentMap<RSAKey, JweRsaOaep256Decrypter> DECRYPTERS = new ConcurrentHashMap<>();

    /**
     * Resolves the private {@link RSAKey} for a {@code kid}, typically the in-memory key store.
     */
    @FunctionalInterface
    public interface PrivateKeyResolver {
        Optional<RSAKey> resolve(String keyId);
    }

    private JweRequestDecryptor() {
    }

    public static DecryptedJwe decrypt(String compactJwe, PrivateKeyResolver resolver) {
        JWEObject jwe;
        try {
            jwe = JWEObject.parse(compactJwe);
        } catch (ParseException e) {
            throw new JweProtocolException(JweProtocolException.Reason.MALFORMED, "Could not parse compact JWE", e);
        }

        JWEHeader header = jwe.getHeader();
        if (!JweRsaKeys.KEY_ENCRYPTION_ALGORITHM.equals(header.getAlgorithm())
                || !EncryptionMethod.A256GCM.equals(header.getEncryptionMethod())) {
            throw new JweProtocolException(JweProtocolException.Reason.UNSUPPORTED_ALGORITHM,
                    "Unsupported JWE algorithms: alg=" + header.getAlgorithm() + ", enc=" + header.getEncryptionMethod());
        }

        String keyId = header.getKeyID();
        if (keyId == null || keyId.isBlank()) {
            throw new JweProtocolException(JweProtocolException.Reason.MISSING_KEY_ID,
                    "JWE protected header is missing a 'kid'");
        }

        RSAKey rsaKey = resolver.resolve(keyId).orElseThrow(() -> new JweProtocolException(
                JweProtocolException.Reason.UNKNOWN_KEY_ID, "No active key found for kid '" + keyId + "'"));

        try {
            JweCryptoProvider.ensureInstalled();
            jwe.decrypt(decrypterFor(keyId, rsaKey));
        } catch (JOSEException e) {
            throw new JweProtocolException(JweProtocolException.Reason.DECRYPTION_FAILED, "JWE decryption failed", e);
        }

        return new DecryptedJwe(jwe.getPayload().toBytes(), header.getContentType());
    }

    /**
     * Drops the cached decrypters of all keys except the given active ones, so retired key versions
     * (including their derived JCA private keys) become garbage-collectible after a key refresh. A
     * decrypt racing with the eviction may momentarily re-add a just-retired key's decrypter; the
     * next refresh evicts it again.
     */
    public static void retainOnly(Collection<RSAKey> activeKeys) {
        DECRYPTERS.keySet().retainAll(Set.copyOf(activeKeys));
    }

    static JweRsaOaep256Decrypter decrypterFor(String keyId, RSAKey rsaKey) {
        return DECRYPTERS.computeIfAbsent(rsaKey, key -> {
            PrivateKey privateKey;
            try {
                privateKey = key.toPrivateKey();
            } catch (JOSEException e) {
                throw new JweProtocolException(JweProtocolException.Reason.DECRYPTION_FAILED,
                        "Selected key for kid '" + keyId + "' has no usable private key", e);
            }
            if (privateKey == null) {
                throw new JweProtocolException(JweProtocolException.Reason.DECRYPTION_FAILED,
                        "Selected key for kid '" + keyId + "' has no usable private key");
            }
            return new JweRsaOaep256Decrypter(privateKey);
        });
    }
}
