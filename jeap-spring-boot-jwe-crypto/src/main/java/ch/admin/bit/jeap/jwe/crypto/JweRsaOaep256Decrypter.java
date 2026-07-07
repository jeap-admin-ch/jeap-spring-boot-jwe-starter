package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.spec.MGF1ParameterSpec;
import java.util.Set;

/**
 * JWE decrypter for RSA-OAEP-256 + A256GCM that unwraps the content-encryption key through the
 * generic JCA {@code RSA/ECB/OAEPPadding} transformation with explicit SHA-256 OAEP parameters,
 * instead of the {@code RSA/ECB/OAEPWithSHA-256AndMGF1Padding} transformation Nimbus's own
 * {@code RSADecrypter} requests. The Amazon Corretto Crypto Provider registers only the generic
 * transformation, so this routing keeps the expensive RSA private-key operation on ACCP (installed
 * at top JCA priority) instead of silently falling back to the pure-Java JDK cipher; on platforms
 * without ACCP the generic transformation resolves to the JDK provider just the same.
 *
 * <p>No cryptographic primitive is implemented here: the CEK unwrap is a parameterised JCA cipher
 * call, and payload decryption is delegated to Nimbus's {@link ContentCryptoProvider}.
 *
 * <p>Instances are immutable and thread-safe (a fresh {@link Cipher} is obtained per call) and are
 * cached per key by {@link JweRequestDecryptor}.
 */
final class JweRsaOaep256Decrypter implements JWEDecrypter {

    private static final String OAEP_TRANSFORMATION = "RSA/ECB/OAEPPadding";
    private static final OAEPParameterSpec OAEP_SHA_256_PARAMETERS = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    // RFC 7516 requires rejecting a JWE whose 'crit' header lists parameters the recipient does not
    // process. No critical parameters are deferred to the application here, matching Nimbus's own
    // RSADecrypter default policy. The instance is never mutated, so sharing it is thread-safe.
    private static final CriticalHeaderParamsDeferral CRIT_POLICY = new CriticalHeaderParamsDeferral();

    private final PrivateKey privateKey;
    private final JWEJCAContext jcaContext = new JWEJCAContext();

    JweRsaOaep256Decrypter(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return Set.of(JWEAlgorithm.RSA_OAEP_256);
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return Set.of(EncryptionMethod.A256GCM);
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return jcaContext;
    }

    @Override
    public byte[] decrypt(JWEHeader header, Base64URL encryptedKey, Base64URL iv, Base64URL cipherText,
                          Base64URL authTag, byte[] aad) throws JOSEException {
        // Reject incomplete JWEs up front, mirroring Nimbus's RSADecrypter: JWEObject.parse turns
        // empty compact-serialization parts into nulls, which would otherwise NPE deep inside the
        // content decryption instead of surfacing as a categorised protocol error.
        if (encryptedKey == null) {
            throw new JOSEException("Missing JWE encrypted key");
        }
        if (iv == null) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }
        if (authTag == null) {
            throw new JOSEException("Missing JWE authentication tag");
        }
        CRIT_POLICY.ensureHeaderPasses(header);
        if (!JWEAlgorithm.RSA_OAEP_256.equals(header.getAlgorithm())) {
            throw new JOSEException("Unsupported JWE algorithm " + header.getAlgorithm());
        }
        SecretKey cek = unwrapCek(encryptedKey.decode());
        return ContentCryptoProvider.decrypt(header, aad, encryptedKey, iv, cipherText, authTag, cek, jcaContext);
    }

    private SecretKey unwrapCek(byte[] encryptedCek) throws JOSEException {
        try {
            Provider provider = jcaContext.getKeyEncryptionProvider();
            Cipher cipher = provider != null
                    ? Cipher.getInstance(OAEP_TRANSFORMATION, provider)
                    : Cipher.getInstance(OAEP_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SHA_256_PARAMETERS);
            return new SecretKeySpec(cipher.doFinal(encryptedCek), "AES");
        } catch (GeneralSecurityException e) {
            throw new JOSEException("RSA-OAEP-256 unwrapping of the content-encryption key failed", e);
        }
    }
}
