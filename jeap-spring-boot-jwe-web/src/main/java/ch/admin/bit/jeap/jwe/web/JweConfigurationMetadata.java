package ch.admin.bit.jeap.jwe.web;

import java.util.List;

/**
 * Client-facing JWE protocol metadata: the content-type allowlist plus the other facts a client
 * needs to interoperate (supported algorithms, the JWKS path, the response-key header name, and the
 * effective include/exclude path patterns). Served as plain JSON by {@link JweMetadataController};
 * contains no security-sensitive material.
 *
 * <p>{@code includedPaths} and {@code excludedPaths} are the <em>effective</em> patterns the server's
 * filter applies — includes evaluated first, excludes second (excludes win). {@code excludedPaths}
 * already contains the built-in jEAP defaults (actuator, JWKS, metadata, SSE) in addition to any
 * configured ones, so a client can replicate the server's "is this request encrypted?" decision
 * exactly: a request is encrypted iff its path matches an include and no exclude.
 *
 * @param contentTypeAllowlist    accepted JWE payload {@code cty} values
 * @param keyEncryptionAlgorithm  JWE {@code alg} for the CEK (RSA-OAEP-256)
 * @param contentEncryptionMethod JWE {@code enc} for the payload (A256GCM)
 * @param jwksPath                path of the JWKS endpoint serving the public keys
 * @param responseKeyHeader       header carrying the response-key envelope for GET responses
 * @param includedPaths           effective include patterns ({@code PathPattern} syntax) the filter applies to
 * @param excludedPaths           effective exclude patterns ({@code PathPattern} syntax), including the jEAP defaults
 */
public record JweConfigurationMetadata(
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
}
