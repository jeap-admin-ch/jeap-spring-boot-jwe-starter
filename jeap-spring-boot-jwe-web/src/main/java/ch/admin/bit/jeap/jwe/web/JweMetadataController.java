package ch.admin.bit.jeap.jwe.web;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes the JWE protocol configuration a client needs to interoperate - primarily the content-type
 * allowlist - at a stable, encryption-excluded path (default {@code /.well-known/jwe-configuration}).
 * It is the server-side counterpart a frontend reads together with the JWKS.
 */
@RestController
public class JweMetadataController {

    /**
     * Default path of the JWE configuration endpoint; shared with the {@code jeap.jwe.metadata.path}
     * property default and the filter exclusion so they cannot drift.
     */
    public static final String DEFAULT_METADATA_PATH = "/.well-known/jwe-configuration";

    private final JweConfigurationMetadata metadata;

    public JweMetadataController(JweConfigurationMetadata metadata) {
        this.metadata = metadata;
    }

    @GetMapping(path = "${jeap.jwe.metadata.path:" + DEFAULT_METADATA_PATH + "}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public JweConfigurationMetadata configuration() {
        return metadata;
    }
}
