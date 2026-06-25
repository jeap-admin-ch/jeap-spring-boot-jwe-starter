package ch.admin.bit.jeap.jwe.crypto;

/**
 * Signals that an inbound JWE could not be processed because it violates the JWE protocol the
 * starter implements (malformed token, unsupported algorithms, unknown key, failed decryption, ...).
 *
 * <p>The {@link Reason} categorises the failure so the web layer can map it to the appropriate HTTP
 * status and structured error response. Messages never contain key material or plaintext.
 */
public class JweProtocolException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * The category of protocol failure, used by the web layer to choose the HTTP error response.
     */
    public enum Reason {
        /**
         * The compact JWE could not be parsed.
         */
        MALFORMED,
        /**
         * The {@code alg}/{@code enc} are not the supported RSA-OAEP-256 / A256GCM pair.
         */
        UNSUPPORTED_ALGORITHM,
        /**
         * The protected header carries no {@code kid}.
         */
        MISSING_KEY_ID,
        /**
         * The {@code kid} does not match any active (non-decommissioned) key.
         */
        UNKNOWN_KEY_ID,
        /**
         * The {@code cty} is missing or not on the configured content-type allowlist.
         */
        INVALID_CONTENT_TYPE,
        /**
         * Decryption (CEK unwrap or payload decrypt) failed.
         */
        DECRYPTION_FAILED
    }

    private final Reason reason;

    public JweProtocolException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public JweProtocolException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
