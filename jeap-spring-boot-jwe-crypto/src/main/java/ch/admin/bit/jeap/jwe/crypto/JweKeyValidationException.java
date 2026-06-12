package ch.admin.bit.jeap.jwe.crypto;

/**
 * Thrown when an RSA key does not satisfy the JWE policy - most importantly when its size is
 * not exactly {@value JweRsaKeys#REQUIRED_KEY_SIZE_BITS} bits, or when a non-RSA / unparseable
 * key is supplied.
 */
public class JweKeyValidationException extends RuntimeException {

    public JweKeyValidationException(String message) {
        super(message);
    }

    public JweKeyValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
