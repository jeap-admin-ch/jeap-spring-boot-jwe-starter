package ch.admin.bit.jeap.jwe.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Writes {@code application/problem+json} (RFC 7807) error responses for JWE protocol failures and
 * logs a structured, secret-free entry for each. Error responses are never JWE-encrypted - a client
 * that failed the protocol could not decrypt them.
 *
 * <p>The problem body is serialized with Jackson, the JSON library Spring Boot already ships.
 */
final class JweProblemWriter {

    static final String APPLICATION_PROBLEM_JSON_VALUE = "application/problem+json";

    private static final Logger log = LoggerFactory.getLogger(JweProblemWriter.class);
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final String typeBaseUri;

    JweProblemWriter(String typeBaseUri) {
        this.typeBaseUri = typeBaseUri;
    }

    void write(HttpServletRequest request, HttpServletResponse response, JweErrorCode error) throws IOException {
        // Structured, secret-free log: code, method and path only - never key material or payloads.
        log.warn("JWE protocol error: code={} status={} method={} path={}",
                error.code(), error.status(), request.getMethod(), request.getRequestURI());

        if (response.isCommitted()) {
            return;
        }
        response.reset();
        response.setStatus(error.status());
        response.setContentType(APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        byte[] body = JSON.writeValueAsBytes(error.toProblemDetail(typeBaseUri));
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
