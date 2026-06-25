package ch.admin.bit.jeap.jwe.web;

import java.util.Locale;

/**
 * Shared JWE protocol constants and helpers for the web layer (the content type used on the wire and
 * content-type normalisation per the JWA {@code cty} convention).
 */
public final class JweProtocol {

    /**
     * Media type of a compact JWE on the wire, for both encrypted requests and responses.
     */
    public static final String APPLICATION_JOSE_VALUE = "application/jose";

    private JweProtocol() {
    }

    /**
     * @return {@code true} if the given Content-Type denotes a compact JWE ({@code application/jose}),
     * ignoring any parameters and case.
     */
    public static boolean isJose(String contentType) {
        return contentType != null && baseType(contentType).equals(APPLICATION_JOSE_VALUE);
    }

    /**
     * Normalises a {@code cty}/Content-Type for comparison: lower-cased, parameters stripped, and the
     * implicit {@code application/} prefix added when the JWA short form (no {@code /}) is used.
     */
    public static String normalizeContentType(String contentType) {
        if (contentType == null) {
            return null;
        }
        String base = baseType(contentType);
        return base.contains("/") ? base : "application/" + base;
    }

    private static String baseType(String contentType) {
        String value = contentType.trim().toLowerCase(Locale.ROOT);
        int semicolon = value.indexOf(';');
        return (semicolon >= 0 ? value.substring(0, semicolon) : value).trim();
    }
}
