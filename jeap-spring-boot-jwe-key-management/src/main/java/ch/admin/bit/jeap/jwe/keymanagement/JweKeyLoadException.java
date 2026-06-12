package ch.admin.bit.jeap.jwe.keymanagement;

/**
 * Thrown when JWE encryption keys cannot be loaded. At startup this fails the application fast
 * rather than letting it run in a broken state that would silently reject encrypted traffic.
 */
public class JweKeyLoadException extends RuntimeException {

    public JweKeyLoadException(String message) {
        super(message);
    }

    public JweKeyLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}
