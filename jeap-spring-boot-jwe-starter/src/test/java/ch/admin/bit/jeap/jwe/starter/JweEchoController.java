package ch.admin.bit.jeap.jwe.starter;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Trivial echo controller used by the integration tests. It is unaware of JWE: it consumes and
 * produces plain JSON and relies on the servlet filter for decryption/encryption.
 *
 * <p>The echo endpoints live under {@code /api/...} so the default include ({@code /*api*}) applies;
 * {@code /public/...} is a non-API path that the default include must leave untouched (SCS scenario).
 */
@RestController
class JweEchoController {

    @PostMapping(path = "/api/echo",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> echo(@RequestBody Map<String, Object> body) {
        return body;
    }

    @GetMapping(path = "/api/echo", produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> get() {
        return Map.of("message", "hello");
    }

    /**
     * A non-API endpoint (e.g. an SCS-served resource) that the default include leaves unencrypted.
     */
    @GetMapping(path = "/public/info", produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> publicInfo() {
        return Map.of("info", "public");
    }
}
