package ch.admin.bit.jeap.jwe.web;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Runtime settings for the {@link JweServletFilter}, derived from {@code jeap.jwe.filter.*}. Decouples
 * the web module from the starter's configuration-properties type.
 */
public final class JweFilterSettings {

    /**
     * Default base URI for the {@code type} member of {@code problem+json} error responses.
     */
    public static final String DEFAULT_PROBLEM_TYPE_BASE_URI = "https://jeap.bit.admin.ch/problems/jwe";

    /**
     * Default maximum size (bytes) of an encrypted request body and the response-key header (5 MiB) -
     * comfortably above the 1 MB payload target including base64url/JWE overhead.
     */
    public static final long DEFAULT_MAX_PAYLOAD_BYTES = 5L * 1024 * 1024;

    private final Set<String> allowedContentTypes;
    private final String downstreamAcceptHeader;
    private final String responseKeyHeader;
    private final boolean requireEncryptedRequest;
    private final boolean requireEncryptedResponse;
    private final String problemTypeBaseUri;
    private final long maxPayloadBytes;

    public JweFilterSettings(List<String> contentTypeAllowlist, String responseKeyHeader,
                             boolean requireEncryptedRequest, boolean requireEncryptedResponse,
                             String problemTypeBaseUri, long maxPayloadBytes) {
        Objects.requireNonNull(contentTypeAllowlist, "contentTypeAllowlist");
        this.responseKeyHeader = Objects.requireNonNull(responseKeyHeader, "responseKeyHeader");
        this.problemTypeBaseUri = Objects.requireNonNull(problemTypeBaseUri, "problemTypeBaseUri");
        this.allowedContentTypes = contentTypeAllowlist.stream()
                .map(JweProtocol::normalizeContentType)
                .collect(Collectors.toUnmodifiableSet());
        this.downstreamAcceptHeader = allowedContentTypes.isEmpty()
                ? "*/*" : String.join(", ", allowedContentTypes);
        this.requireEncryptedRequest = requireEncryptedRequest;
        this.requireEncryptedResponse = requireEncryptedResponse;
        this.maxPayloadBytes = maxPayloadBytes;
    }

    /**
     * Test-only convenience constructor with secure defaults (encryption mandatory, default problem
     * type URI, default payload limit).
     */
    JweFilterSettings(List<String> contentTypeAllowlist, String responseKeyHeader) {
        this(contentTypeAllowlist, responseKeyHeader, true, true, DEFAULT_PROBLEM_TYPE_BASE_URI,
                DEFAULT_MAX_PAYLOAD_BYTES);
    }

    /**
     * @return {@code true} if the given JWE {@code cty} is on the configured content-type allowlist.
     */
    public boolean isAllowedContentType(String contentType) {
        return contentType != null && allowedContentTypes.contains(JweProtocol.normalizeContentType(contentType));
    }

    /**
     * @return the header name carrying the client-supplied response-key envelope for GET responses.
     */
    public String responseKeyHeader() {
        return responseKeyHeader;
    }

    public boolean requireEncryptedRequest() {
        return requireEncryptedRequest;
    }

    public boolean requireEncryptedResponse() {
        return requireEncryptedResponse;
    }

    public String problemTypeBaseUri() {
        return problemTypeBaseUri;
    }

    /**
     * @return the maximum size in bytes of an encrypted request body and the response-key header value.
     */
    public long maxPayloadBytes() {
        return maxPayloadBytes;
    }

    /**
     * @return the {@code Accept} header value to present to the {@code DispatcherServlet} when the
     * response will be encrypted, so MVC content negotiation matches the controller's real output.
     */
    public String downstreamAcceptHeader() {
        return downstreamAcceptHeader;
    }
}
