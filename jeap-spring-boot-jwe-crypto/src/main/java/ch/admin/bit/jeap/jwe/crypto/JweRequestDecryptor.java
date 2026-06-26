package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Optional;

/**
 * Decrypts an inbound compact JWE into plaintext using the starter's supported algorithms
 * (RSA-OAEP-256 for the CEK, A256GCM for the payload).
 *
 * <p>This is a thin, stateless layer over Nimbus - no custom cryptography is implemented. The
 * request's content-encryption key is not exposed: response encryption uses a separate CEK from the
 * client's {@code JWE-Response-Key} header. All failures are surfaced as a categorised
 * {@link JweProtocolException}.
 */
public final class JweRequestDecryptor {

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

        PrivateKey privateKey;
        try {
            privateKey = rsaKey.toPrivateKey();
        } catch (JOSEException e) {
            throw new JweProtocolException(JweProtocolException.Reason.DECRYPTION_FAILED,
                    "Selected key for kid '" + keyId + "' has no usable private key", e);
        }
        if (privateKey == null) {
            throw new JweProtocolException(JweProtocolException.Reason.DECRYPTION_FAILED,
                    "Selected key for kid '" + keyId + "' has no usable private key");
        }

        try {
            JweCryptoProvider.ensureInstalled();
            jwe.decrypt(new RSADecrypter(privateKey));
        } catch (JOSEException e) {
            throw new JweProtocolException(JweProtocolException.Reason.DECRYPTION_FAILED, "JWE decryption failed", e);
        }

        return new DecryptedJwe(jwe.getPayload().toBytes(), header.getContentType());
    }
}
