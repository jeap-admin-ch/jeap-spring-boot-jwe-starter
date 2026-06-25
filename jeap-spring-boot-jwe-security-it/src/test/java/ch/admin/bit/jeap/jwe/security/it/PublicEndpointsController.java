package ch.admin.bit.jeap.jwe.security.it;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Public (unauthenticated) endpoints used to cover the non-OAuth cases of the coexistence matrix:
 *
 * <ul>
 *   <li>{@code POST /api/public/echo} — public but, because it matches the JWE include ({@code /*api*}),
 *       still transparently encrypted: <em>non-OAuth + encrypted</em>;</li>
 *   <li>{@code GET /public/info} — neither authenticated nor encrypted (not under an {@code *api*}
 *       segment, so the JWE filter ignores it): <em>non-OAuth + non-encrypted</em>.</li>
 * </ul>
 */
@RestController
class PublicEndpointsController {

    @PostMapping(path = "/api/public/echo",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> echo(@RequestBody Map<String, Object> body) {
        return body;
    }

    @GetMapping(path = "/public/info", produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> info() {
        return Map.of("info", "public");
    }
}
