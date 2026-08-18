package ch.admin.bit.jeap.jwe.web;

import java.util.List;

/**
 * Client-facing JWE protocol metadata: the master switch, the content-type allowlist plus the other
 * facts a client needs to interoperate (supported algorithms, the JWKS path, the response-key header
 * name, and the effective include/exclude path patterns). Served as plain JSON by
 * {@link JweMetadataController}; contains no security-sensitive material.
 *
 * <p>{@code enabled} mirrors {@code jeap.jwe.enabled}. It lets a client follow the server's master
 * switch instead of carrying its own build-time copy of it, which is what keeps a single frontend
 * artifact deployable against a stage where JWE is turned off. The metadata endpoint therefore answers
 * in both states - see the disabled-state metadata built by {@link #disabled()}.
 *
 * <p>{@code includedPaths} and {@code excludedPaths} are the <em>effective</em> patterns the server's
 * filter applies — includes evaluated first, excludes second (excludes win). {@code excludedPaths}
 * already contains the built-in jEAP defaults (actuator, JWKS, metadata, SSE) in addition to any
 * configured ones, so a client can replicate the server's "is this request encrypted?" decision
 * exactly: a request is encrypted iff its path matches an include and no exclude.
 *
 * @param enabled                 whether JWE is switched on; when {@code false} the server encrypts nothing
 * @param contentTypeAllowlist    accepted JWE payload {@code cty} values
 * @param keyEncryptionAlgorithm  JWE {@code alg} for the CEK (RSA-OAEP-256)
 * @param contentEncryptionMethod JWE {@code enc} for the payload (A256GCM)
 * @param jwksPath                path of the JWKS endpoint serving the public keys
 * @param responseKeyHeader       header carrying the response-key envelope for GET responses
 * @param includedPaths           effective include patterns ({@code PathPattern} syntax) the filter applies to
 * @param excludedPaths           effective exclude patterns ({@code PathPattern} syntax), including the jEAP defaults
 */
public record JweConfigurationMetadata(
        boolean enabled,
        List<String> contentTypeAllowlist,
        String keyEncryptionAlgorithm,
        String contentEncryptionMethod,
        String jwksPath,
        String responseKeyHeader,
        List<String> includedPaths,
        List<String> excludedPaths) {

    public JweConfigurationMetadata {
        contentTypeAllowlist = List.copyOf(contentTypeAllowlist);
        includedPaths = List.copyOf(includedPaths);
        excludedPaths = List.copyOf(excludedPaths);
    }

    /**
     * Metadata for a service that has JWE turned off ({@code jeap.jwe.enabled=false}). Only the switch
     * carries information: there is no key material, no JWKS endpoint and no filter, so the algorithms
     * and the response-key header are absent and the path lists are empty. Publishing empty lists rather
     * than the configured patterns keeps the document honest - no filter is installed, so no path is
     * protected.
     */
    public static JweConfigurationMetadata disabled() {
        return new JweConfigurationMetadata(false, List.of(), null, null, null, null, List.of(), List.of());
    }
}
