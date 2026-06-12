package ch.admin.bit.jeap.jwe.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Reusable RSA test keys for the jEAP JWE starter's test suites.
 *
 * <p>Generating 4096-bit RSA key pairs is expensive, so the production-sized keys are generated lazily
 * and cached per index for the lifetime of the JVM. Tests that need several distinct active versions
 * (e.g. the multi-key JWKS test) ask for keys by index; the same index always yields the same key.
 */
public final class JweTestKeys {

    private static final List<KeyPair> POOL = new ArrayList<>();

    private JweTestKeys() {
    }

    /**
     * A cached 4096-bit RSA key pair for the given index (0-based); the same index returns the same pair.
     */
    public static synchronized KeyPair rsa4096(int index) {
        while (POOL.size() <= index) {
            POOL.add(generate(4096));
        }
        return POOL.get(index);
    }

    /**
     * PEM (public + private) of the cached 4096-bit key pair at the given index, as Vault export would emit.
     */
    public static String rsa4096Pem(int index) {
        return pem(rsa4096(index));
    }

    /**
     * Generates a fresh RSA key pair of the given size - for tests that need an undersized (rejected) key.
     */
    public static KeyPair generate(int sizeBits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(sizeBits);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA key pair generation is not available", e);
        }
    }

    /**
     * Encodes a key pair as concatenated PEM blocks (public key then private key), matching Vault transit export.
     */
    public static String pem(KeyPair keyPair) {
        return block("PUBLIC KEY", keyPair.getPublic().getEncoded())
                + "\n"
                + block("PRIVATE KEY", keyPair.getPrivate().getEncoded());
    }

    private static String block(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----";
    }
}
