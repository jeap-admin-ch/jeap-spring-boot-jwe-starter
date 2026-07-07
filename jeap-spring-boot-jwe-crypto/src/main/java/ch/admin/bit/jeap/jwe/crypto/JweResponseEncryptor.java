package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Encrypts a response payload as a compact JWE using direct encryption ({@code alg: dir},
 * {@code enc: A256GCM}) with the content-encryption key (CEK) the client supplied in the
 * {@code JWE-Response-Key} envelope, which {@link #recoverResponseCek} unwraps. The response CEK is
 * always the client's response key, never the request's CEK.
 *
 * <p>Thin, stateless layer over Nimbus - no custom cryptography. A fresh IV is generated per call by
 * Nimbus from a shared {@link SecureRandom}.
 */
public final class JweResponseEncryptor {

    /**
     * AES-256 CEK length in bytes.
     */
    private static final int CEK_LENGTH_BYTES = 32;

    // Shared IV source: Nimbus allocates a fresh SecureRandom per encrypter when none is supplied;
    // one shared, thread-safe instance avoids that per-response allocation and seeding.
    private static final SecureRandom IV_RANDOM = new SecureRandom();

    private JweResponseEncryptor() {
    }

    /**
     * Encrypts the given plaintext with direct A256GCM encryption under the supplied CEK.
     *
     * @param plaintext   the response body bytes
     * @param cek         the AES-256 content-encryption key
     * @param contentType the {@code cty} to declare (the client uses it to interpret the plaintext)
     * @return the compact JWE serialization
     */
    public static String encrypt(byte[] plaintext, SecretKey cek, String contentType) {
        JWEHeader.Builder header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
        if (contentType != null) {
            header.contentType(contentType);
        }
        JWEObject jwe = new JWEObject(header.build(), new Payload(plaintext));
        try {
            JweCryptoProvider.ensureInstalled();
            DirectEncrypter encrypter = new DirectEncrypter(cek);
            encrypter.getJCAContext().setSecureRandom(IV_RANDOM);
            jwe.encrypt(encrypter);
        } catch (JOSEException e) {
            throw new JweEncryptionException("Could not encrypt the response", e);
        }
        return jwe.serialize();
    }

    /**
     * Recovers the response CEK from a client-supplied {@code JWE-Response-Key} envelope: a compact
     * JWE (RSA-OAEP-256 + A256GCM) whose decrypted payload is the raw 32-byte CEK to use for the
     * response.
     */
    public static SecretKey recoverResponseCek(String compactEnvelope, JweRequestDecryptor.PrivateKeyResolver resolver) {
        byte[] cekBytes = JweRequestDecryptor.decrypt(compactEnvelope, resolver).plaintext();
        if (cekBytes.length != CEK_LENGTH_BYTES) {
            throw new JweProtocolException(JweProtocolException.Reason.MALFORMED,
                    "Response-key envelope payload must be a " + CEK_LENGTH_BYTES + "-byte CEK but was "
                            + cekBytes.length + " bytes");
        }
        return new SecretKeySpec(cekBytes, "AES");
    }
}
