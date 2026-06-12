package ch.admin.bit.jeap.jwe.web;

import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * Exposes the backend's active public RSA keys as a JWK Set (RFC 7517) so clients can fetch the key
 * they need to encrypt requests.
 *
 * <p>The set is rendered straight from the {@link JweKeyStore}: the store owns the
 * newest-active-version-first ordering, so a client can use {@code keys[0]} as the current encryption
 * key. The endpoint must not reorder the set. Private material is stripped by Nimbus via
 * {@link JweRsaKeys#toPublicJwkSetJson} - only public parameters are ever emitted, and the
 * controller holds no crypto logic of its own.
 *
 * <p>The request path is configurable through {@code jeap.jwe.jwks.path} (default
 * {@code /.well-known/jwks.json}); the placeholder is resolved at mapping registration time. Because
 * the response is rendered live from the cache, a key refresh is reflected without a restart.
 */
@RestController
public class JweJwksController {

    /**
     * Default JWKS path; the single source of truth shared with the {@code jeap.jwe.jwks.path} property default.
     */
    public static final String DEFAULT_JWKS_PATH = "/.well-known/jwks.json";

    /**
     * Conservative cache lifetime; short enough that rotated keys propagate quickly (correctness over caching).
     */
    private static final Duration CACHE_MAX_AGE = Duration.ofSeconds(60);

    private final JweKeyStore keyStore;

    public JweJwksController(JweKeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @GetMapping(path = "${jeap.jwe.jwks.path:" + DEFAULT_JWKS_PATH + "}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> jwkSet() {
        String jwkSetJson = JweRsaKeys.toPublicJwkSetJson(keyStore.activeKeys());
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .cacheControl(CacheControl.maxAge(CACHE_MAX_AGE).cachePublic())
                .body(jwkSetJson);
    }
}
