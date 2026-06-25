package ch.admin.bit.jeap.jwe.web;

import ch.admin.bit.jeap.jwe.crypto.JweProtocolException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The catalogue of JWE protocol errors and their {@code application/problem+json} representation
 * (RFC 7807). Each entry carries the HTTP status, a stable machine-readable {@code code}, a human
 * {@code title}/{@code detail} and, where useful, a single contextual {@link Hint} that tells the
 * client what to do.
 */
public enum JweErrorCode {

    REQUEST_ENCRYPTION_REQUIRED(415, "encryption-required", "JWE_REQUEST_ENCRYPTION_REQUIRED",
            "Encrypted request body required",
            "This endpoint requires requests with Content-Type application/jose.",
            new Hint("requiredContentType", "application/jose")),

    RESPONSE_ENCRYPTION_REQUIRED(406, "encrypted-response-required", "JWE_RESPONSE_ENCRYPTION_REQUIRED",
            "Encrypted response required",
            "This endpoint only returns encrypted responses. Send Accept: application/jose.",
            new Hint("requiredAccept", "application/jose")),

    RESPONSE_KEY_REQUIRED(400, "response-key-required", "JWE_RESPONSE_KEY_REQUIRED",
            "JWE response key required",
            "This endpoint requires the JWE-Response-Key header for encrypted responses.",
            new Hint("requiredHeader", "JWE-Response-Key")),

    RESPONSE_KEY_INVALID(400, "response-key-invalid", "JWE_RESPONSE_KEY_INVALID",
            "Invalid JWE response key",
            "The JWE-Response-Key header is not a valid response-key envelope.",
            null),

    MALFORMED(400, "malformed", "JWE_MALFORMED",
            "Malformed JWE",
            "The request JWE could not be parsed or decrypted.",
            null),

    UNSUPPORTED_ALGORITHM(400, "unsupported-algorithm", "JWE_UNSUPPORTED_ALGORITHM",
            "Unsupported JWE algorithm",
            "The JWE uses unsupported parameters. Use alg RSA-OAEP-256 and enc A256GCM.",
            null),

    INVALID_CONTENT_TYPE(400, "invalid-content-type", "JWE_INVALID_CONTENT_TYPE",
            "Invalid JWE content type",
            "The JWE 'cty' protected-header value is missing or not allowed.",
            null),

    UNKNOWN_KEY_ID(400, "unknown-kid", "JWE_UNKNOWN_KEY_ID",
            "Unknown or decommissioned key",
            "The JWE was encrypted with an unknown or decommissioned key. Refresh your JWKS and retry.",
            null),

    PAYLOAD_TOO_LARGE(413, "payload-too-large", "JWE_PAYLOAD_TOO_LARGE",
            "Encrypted payload too large",
            "The encrypted request exceeds the maximum allowed size.",
            null);

    /**
     * A single RFC 7807 extension member guiding the client (e.g. {@code requiredContentType}).
     */
    private record Hint(String field, String value) {
    }

    private final int status;
    private final String typeSuffix;
    private final String code;
    private final String title;
    private final String detail;
    private final Hint hint;

    JweErrorCode(int status, String typeSuffix, String code, String title, String detail, Hint hint) {
        this.status = status;
        this.typeSuffix = typeSuffix;
        this.code = code;
        this.title = title;
        this.detail = detail;
        this.hint = hint;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    /**
     * Builds the RFC 7807 problem body as an ordered map, ready to be serialised to JSON.
     *
     * @param typeBaseUri base URI for the {@code type} member; the {@link #typeSuffix} is appended.
     */
    public Map<String, Object> toProblemDetail(String typeBaseUri) {
        Map<String, Object> problem = new LinkedHashMap<>();
        problem.put("type", typeBaseUri.endsWith("/") ? typeBaseUri + typeSuffix : typeBaseUri + "/" + typeSuffix);
        problem.put("title", title);
        problem.put("status", status);
        problem.put("detail", detail);
        problem.put("code", code);
        if (hint != null) {
            problem.put(hint.field(), hint.value());
        }
        return problem;
    }

    /**
     * Maps a {@link JweProtocolException} raised while decrypting a request body to the matching error.
     */
    public static JweErrorCode forRequestFailure(JweProtocolException.Reason reason) {
        return switch (reason) {
            case UNSUPPORTED_ALGORITHM -> UNSUPPORTED_ALGORITHM;
            case INVALID_CONTENT_TYPE -> INVALID_CONTENT_TYPE;
            case UNKNOWN_KEY_ID -> UNKNOWN_KEY_ID;
            case MALFORMED, MISSING_KEY_ID, DECRYPTION_FAILED -> MALFORMED;
        };
    }
}
