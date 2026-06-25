package ch.admin.bit.jeap.jwe.security.it;

import ch.admin.bit.jeap.security.resource.token.JeapAuthenticationToken;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Secured echo controller used by the coexistence test. Like a real controller it is unaware of JWE
 * (it consumes/produces plain JSON and lets the filter decrypt/encrypt) and unaware of how
 * authentication happened (it just reads the authenticated principal). The endpoints live under
 * {@code /api/...} so both the jeap-security resource-server rules and the JWE filter's default
 * include ({@code /*api*}) apply.
 */
@RestController
class SecuredEchoController {

    @PostMapping(path = "/api/secure/echo",
            consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> echo(@RequestBody Map<String, Object> body) {
        return body;
    }

    /**
     * Returns the authenticated subject, proving the jeap principal reaches the controller through the
     * JWE-wrapped request.
     */
    @GetMapping(path = "/api/secure/whoami", produces = MediaType.APPLICATION_JSON_VALUE)
    Map<String, Object> whoami(JeapAuthenticationToken authentication) {
        return Map.of("subject", authentication.getTokenSubject());
    }
}
