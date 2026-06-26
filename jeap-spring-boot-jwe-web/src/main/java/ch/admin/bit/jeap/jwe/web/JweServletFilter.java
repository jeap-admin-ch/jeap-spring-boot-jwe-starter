package ch.admin.bit.jeap.jwe.web;

import ch.admin.bit.jeap.jwe.crypto.DecryptedJwe;
import ch.admin.bit.jeap.jwe.crypto.JweProtocolException;
import ch.admin.bit.jeap.jwe.crypto.JweRequestDecryptor;
import ch.admin.bit.jeap.jwe.crypto.JweResponseEncryptor;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import ch.admin.bit.jeap.jwe.keymanagement.JweMetrics;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;
import org.springframework.web.util.ServletRequestPathUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

/**
 * Servlet filter that carries the transparent JWE request/response cryptography on the servlet
 * stack. Registered only for servlet web applications (reactive/WebFlux is not supported).
 *
 * <ul>
 *   <li>Decrypts an inbound {@code application/jose} request body and exposes the plaintext to the
 *   controller via {@link DecryptedHttpServletRequest}.</li>
 *   <li>Encrypts the response as {@code dir}/A256GCM with the content-encryption key the client
 *   supplied in the {@code JWE-Response-Key} header. The response CEK is always the client's response
 *   key, never the request's CEK - request and response use separate CEKs.</li>
 *   <li>Enforces mandatory encryption on non-excluded paths and renders every protocol failure as an
 *   {@code application/problem+json} error (never encrypted).</li>
 * </ul>
 *
 * <p>Path exclusion matches the parsed, normalised {@link org.springframework.http.server.RequestPath}
 * Spring MVC routes on (cached via {@link ServletRequestPathUtils}), so the filter's view of the path
 * cannot diverge from the dispatcher's. Excluded paths are skipped via
 * {@link #shouldNotFilter(HttpServletRequest)}.
 *
 * <p>Request-body decryption applies to POST/PUT/PATCH; response encryption applies to GET and
 * POST/PUT/PATCH (both driven by the {@code JWE-Response-Key} header). Other methods pass through.
 * Async/streaming responses on encrypted paths are not supported.
 */
public final class JweServletFilter extends OncePerRequestFilter {

    /**
     * Fallback JWE {@code cty} when the controller produced a body but set no content type. This is
     * the content type declared <em>inside</em> the JWE, not the HTTP Content-Type (always
     * {@code application/jose}).
     */
    private static final String FALLBACK_RESPONSE_CTY = MediaType.APPLICATION_JSON_VALUE;

    /**
     * Methods that carry a request body whose encryption is enforced.
     */
    private static final Set<HttpMethod> BODY_METHODS = Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH);

    /**
     * Methods that return a body the client may want encrypted (driven by the {@code JWE-Response-Key}
     * header). Excludes HEAD/OPTIONS/TRACE/DELETE so CORS preflights and bodyless calls pass through.
     */
    private static final Set<HttpMethod> RESPONSE_METHODS =
            Set.of(HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH);

    private final JweFilterPaths filterPaths;
    private final JweKeyStore keyStore;
    private final JweFilterSettings settings;
    private final JweProblemWriter problemWriter;
    private final JweMetrics metrics;

    public JweServletFilter(JweFilterPaths filterPaths, JweKeyStore keyStore, JweFilterSettings settings) {
        this(filterPaths, keyStore, settings, JweMetrics.NOOP);
    }

    public JweServletFilter(JweFilterPaths filterPaths, JweKeyStore keyStore, JweFilterSettings settings,
                            JweMetrics metrics) {
        this.filterPaths = filterPaths;
        this.keyStore = keyStore;
        this.settings = settings;
        this.problemWriter = new JweProblemWriter(settings.problemTypeBaseUri());
        this.metrics = metrics;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !filterPaths.appliesTo(ServletRequestPathUtils.parseAndCache(request).pathWithinApplication());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            process(request, response, filterChain);
        } catch (JweProtocolException e) {
            // Client protocol error -> structured problem+json (4xx). Server-side encryption faults
            // (JweEncryptionException) are deliberately NOT caught here and surface as 500.
            problemWriter.write(request, response, JweErrorCode.forRequestFailure(e.getReason()));
        }
    }

    private void process(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Unknown/custom methods yield a synthetic HttpMethod that is simply absent from
        // BODY_METHODS/RESPONSE_METHODS, so they intentionally fall through to plain pass-through
        // (no encryption enforced); path scoping and downstream auth remain in effect.
        HttpMethod method = HttpMethod.valueOf(request.getMethod());

        // 1) Request body: decrypt it (POST/PUT/PATCH with application/jose), else enforce.
        Optional<HttpServletRequest> prepared = prepareRequest(request, response, method);
        if (prepared.isEmpty()) {
            return; // a problem response has been written
        }
        HttpServletRequest effectiveRequest = prepared.get();

        // 2) Response: always encrypted with the client's JWE-Response-Key CEK (never the request CEK).
        ResponseKeyResolution resolution = resolveResponseCek(request, response, method);
        if (resolution.problemWritten()) {
            return; // a problem response has been written
        }
        SecretKey responseCek = resolution.cek();

        if (responseCek == null) {
            filterChain.doFilter(effectiveRequest, response);
            return;
        }

        // The client sent Accept: application/jose for enforcement; present an MVC-friendly Accept so
        // content negotiation matches the controller's real output, then encrypt what it produced.
        // ContentCachingResponseWrapper caches the body and (its flushBuffer is a no-op) defers commit,
        // so the response stays uncommitted until we write the JWE here.
        HttpServletRequest negotiableRequest =
                new AcceptOverridingHttpServletRequest(effectiveRequest, settings.downstreamAcceptHeader());
        ContentCachingResponseWrapper caching = new ContentCachingResponseWrapper(response);
        filterChain.doFilter(negotiableRequest, caching);
        writeResponse(caching, response, responseCek);
    }

    /**
     * Decrypts the request body for body methods (POST/PUT/PATCH) carrying {@code application/jose},
     * exposing the plaintext via {@link DecryptedHttpServletRequest}, and enforces encryption otherwise.
     *
     * @return the request to forward downstream, or {@link Optional#empty()} when a problem response has
     * already been written and processing must stop.
     */
    private Optional<HttpServletRequest> prepareRequest(HttpServletRequest request, HttpServletResponse response,
                                                        HttpMethod method) throws IOException {
        if (!BODY_METHODS.contains(method)) {
            return Optional.of(request);
        }
        if (JweProtocol.isJose(request.getContentType())) {
            Optional<byte[]> body = readBoundedBody(request, response);
            if (body.isEmpty()) {
                return Optional.empty(); // 413 problem already written
            }
            return Optional.of(decryptRequest(request, body.get()));
        }
        if (settings.requireEncryptedRequest()) {
            metrics.recordRequestRejected(JweMetrics.RejectionReason.ENCRYPTION_REQUIRED);
            problemWriter.write(request, response, JweErrorCode.REQUEST_ENCRYPTION_REQUIRED);
            return Optional.empty();
        }
        return Optional.of(request);
    }

    /**
     * Resolves the response CEK from the {@code JWE-Response-Key} header for response methods (GET and
     * the body methods), enforcing the encryption contract in strict mode. A present header is validated
     * identically in both modes - a bad/oversized envelope yields the same problem either way.
     */
    private ResponseKeyResolution resolveResponseCek(HttpServletRequest request, HttpServletResponse response,
                                                     HttpMethod method) throws IOException {
        // Other methods (DELETE/HEAD/OPTIONS/...) pass through without response encryption.
        if (!RESPONSE_METHODS.contains(method)) {
            return ResponseKeyResolution.passThrough();
        }
        boolean required = settings.requireEncryptedResponse();
        if (required && !acceptsJose(request)) {
            metrics.recordRequestRejected(JweMetrics.RejectionReason.RESPONSE_ENCRYPTION_REQUIRED);
            problemWriter.write(request, response, JweErrorCode.RESPONSE_ENCRYPTION_REQUIRED);
            return ResponseKeyResolution.stop();
        }
        String envelope = request.getHeader(settings.responseKeyHeader());
        if (envelope == null || envelope.isBlank()) {
            if (required) {
                metrics.recordRequestRejected(JweMetrics.RejectionReason.RESPONSE_KEY_REQUIRED);
                problemWriter.write(request, response, JweErrorCode.RESPONSE_KEY_REQUIRED);
                return ResponseKeyResolution.stop();
            }
            return ResponseKeyResolution.passThrough(); // lenient mode with no JWE-Response-Key header
        }
        SecretKey cek = recoverResponseCek(request, response, envelope);
        return cek == null ? ResponseKeyResolution.stop() : ResponseKeyResolution.encryptWith(cek);
    }

    /**
     * Outcome of {@link #resolveResponseCek}: {@code problemWritten} stops processing; otherwise
     * {@code cek} is the response key to encrypt with ({@code null} means pass through unencrypted).
     */
    private record ResponseKeyResolution(boolean problemWritten, SecretKey cek) {
        private static ResponseKeyResolution stop() {
            return new ResponseKeyResolution(true, null);
        }

        private static ResponseKeyResolution passThrough() {
            return new ResponseKeyResolution(false, null);
        }

        private static ResponseKeyResolution encryptWith(SecretKey cek) {
            return new ResponseKeyResolution(false, cek);
        }
    }

    /**
     * Reads the encrypted request body bounded by {@code maxPayloadBytes}; writes a 413 problem and
     * returns {@link Optional#empty()} if the body is (or declares itself) too large.
     */
    private Optional<byte[]> readBoundedBody(HttpServletRequest request, HttpServletResponse response) throws IOException {
        long max = settings.maxPayloadBytes();
        if (request.getContentLengthLong() > max) {
            metrics.recordRequestRejected(JweMetrics.RejectionReason.PAYLOAD_TOO_LARGE);
            problemWriter.write(request, response, JweErrorCode.PAYLOAD_TOO_LARGE);
            return Optional.empty();
        }
        byte[] body = request.getInputStream().readNBytes((int) Math.min(max + 1, Integer.MAX_VALUE));
        if (body.length > max) {
            metrics.recordRequestRejected(JweMetrics.RejectionReason.PAYLOAD_TOO_LARGE);
            problemWriter.write(request, response, JweErrorCode.PAYLOAD_TOO_LARGE);
            return Optional.empty();
        }
        return Optional.of(body);
    }

    private HttpServletRequest decryptRequest(HttpServletRequest request, byte[] body) {
        long startNanos = System.nanoTime();
        try {
            String compactJwe = new String(body, StandardCharsets.US_ASCII).trim();
            DecryptedJwe decrypted = JweRequestDecryptor.decrypt(compactJwe, keyStore::findByKeyId);

            if (!settings.isAllowedContentType(decrypted.contentType())) {
                throw new JweProtocolException(JweProtocolException.Reason.INVALID_CONTENT_TYPE,
                        "JWE 'cty' is missing or not on the content-type allowlist");
            }

            HttpServletRequest decryptedRequest = new DecryptedHttpServletRequest(
                    request, decrypted.plaintext(), JweProtocol.normalizeContentType(decrypted.contentType()));
            metrics.recordDecryption(true, null, Duration.ofNanos(System.nanoTime() - startNanos));
            return decryptedRequest;
        } catch (JweProtocolException e) {
            metrics.recordDecryption(false, e.getReason(), Duration.ofNanos(System.nanoTime() - startNanos));
            throw e;
        }
    }

    /**
     * Recovers the response CEK from a present {@code JWE-Response-Key} envelope, applying the same
     * guards in both strict and lenient mode: an oversized envelope yields {@code PAYLOAD_TOO_LARGE}
     * and a malformed/undecryptable one yields {@code RESPONSE_KEY_INVALID}. Returns {@code null} after
     * writing a problem response.
     *
     * <p>The envelope unwrap is itself an RSA decryption, so a failed unwrap is recorded on the
     * decryption meter as a failure (it would otherwise go uncounted), keyed by the same reason tags as
     * the request-body path.
     */
    private SecretKey recoverResponseCek(HttpServletRequest request, HttpServletResponse response, String envelope)
            throws IOException {
        if (envelope.getBytes(StandardCharsets.US_ASCII).length > settings.maxPayloadBytes()) {
            metrics.recordRequestRejected(JweMetrics.RejectionReason.PAYLOAD_TOO_LARGE);
            problemWriter.write(request, response, JweErrorCode.PAYLOAD_TOO_LARGE);
            return null;
        }
        long startNanos = System.nanoTime();
        try {
            return JweResponseEncryptor.recoverResponseCek(envelope.trim(), keyStore::findByKeyId);
        } catch (JweProtocolException e) {
            metrics.recordDecryption(false, e.getReason(), Duration.ofNanos(System.nanoTime() - startNanos));
            problemWriter.write(request, response, JweErrorCode.RESPONSE_KEY_INVALID);
            return null;
        }
    }

    private void writeResponse(ContentCachingResponseWrapper caching, HttpServletResponse response, SecretKey cek)
            throws IOException {
        if (response.isCommitted()) {
            // The downstream already committed (e.g. sendError/redirect); nothing left to encrypt.
            return;
        }
        byte[] body = caching.getContentAsByteArray();
        int status = caching.getStatus();
        boolean successful = status >= 200 && status < 300;

        if (!successful || body.length == 0) {
            // Do not encrypt error/empty responses; pass the cached body through unchanged.
            caching.copyBodyToResponse();
            return;
        }

        String cty = JweProtocol.normalizeContentType(caching.getContentType());
        String compactJwe;
        try {
            compactJwe = JweResponseEncryptor.encrypt(body, cek, cty != null ? cty : FALLBACK_RESPONSE_CTY);
        } catch (RuntimeException e) {
            metrics.recordResponseEncryption(false);
            throw e;
        }
        metrics.recordResponseEncryption(true);
        byte[] out = compactJwe.getBytes(StandardCharsets.US_ASCII);

        response.setContentType(JweProtocol.APPLICATION_JOSE_VALUE);
        response.setContentLength(out.length);
        response.getOutputStream().write(out);
    }

    private boolean acceptsJose(HttpServletRequest request) {
        String accept = request.getHeader(HttpHeaders.ACCEPT);
        if (accept == null) {
            return false;
        }
        for (String part : accept.split(",")) {
            String mediaType = part.trim();
            int semicolon = mediaType.indexOf(';');
            if (semicolon >= 0) {
                mediaType = mediaType.substring(0, semicolon).trim();
            }
            if (JweProtocol.APPLICATION_JOSE_VALUE.equalsIgnoreCase(mediaType)) {
                return true;
            }
        }
        return false;
    }
}
