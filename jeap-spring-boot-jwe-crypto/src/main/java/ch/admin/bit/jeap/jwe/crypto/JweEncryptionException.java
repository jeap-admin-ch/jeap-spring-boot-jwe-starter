package ch.admin.bit.jeap.jwe.crypto;

/**
 * Thrown when the server fails to encrypt a response. Unlike {@link JweProtocolException} (a client
 * protocol error rendered as a 4xx), this is a <strong>server-side</strong> fault and must surface as
 * a 5xx - it is never caused by client input.
 */
public class JweEncryptionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public JweEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
