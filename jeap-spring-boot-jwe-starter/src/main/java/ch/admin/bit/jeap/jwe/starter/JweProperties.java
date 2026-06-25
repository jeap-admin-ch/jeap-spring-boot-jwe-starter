package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.web.JweFilterSettings;
import ch.admin.bit.jeap.jwe.web.JweJwksController;
import ch.admin.bit.jeap.jwe.web.JweMetadataController;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for the jEAP JWE end-to-end encryption starter.
 *
 * <p>All security-relevant parameters are configurable here. Enabling the starter
 * is strictly opt-in via {@link #enabled}; when disabled the dependency has no effect on the
 * application.
 */
@Getter
@Setter
@ToString
@ConfigurationProperties(prefix = "jeap.jwe")
public class JweProperties {

    /**
     * Master switch for the JWE starter. When {@code false} no JWE beans are
     * created and existing endpoints behave exactly as before. Enabled by default when the
     * starter is on the classpath.
     */
    private boolean enabled = true;

    @NestedConfigurationProperty
    private final Jwks jwks = new Jwks();

    @NestedConfigurationProperty
    private final Vault vault = new Vault();

    @NestedConfigurationProperty
    private final Refresh refresh = new Refresh();

    @NestedConfigurationProperty
    private final Filter filter = new Filter();

    @NestedConfigurationProperty
    private final Metadata metadata = new Metadata();

    @NestedConfigurationProperty
    private final Test test = new Test();

    @NestedConfigurationProperty
    private final Security security = new Security();

    /**
     * Settings for the JWKS endpoint that exposes the active public keys (RFC 7517).
     */
    @Getter
    @Setter
    @ToString
    public static class Jwks {
        /**
         * Path under which the JWK Set of active public keys is served. Shares its default with the
         * controller mapping ({@link JweJwksController#DEFAULT_JWKS_PATH}) to keep them from drifting.
         */
        private String path = JweJwksController.DEFAULT_JWKS_PATH;
    }

    /**
     * Vault transit settings used to export the RSA key pairs. Only Spring Cloud Vault is
     * used; the starter does not depend on jeap-vault-starter.
     */
    @Getter
    @Setter
    @ToString
    public static class Vault {
        /**
         * Name of the Vault transit key (created as an exportable {@code rsa-4096} key)
         * whose active versions are exported. Required in Vault mode.
         */
        private String transitKeyName;

        /**
         * Transit secret-engine path. Defaults to {@code transit/<jeap.vault.system-name>}
         * when {@code jeap.vault.system-name} is set.
         */
        private String secretEnginePath;

        /**
         * Minimum accepted Vault key version. Key versions below this value are neither
         * loaded nor served via the JWKS endpoint.
         */
        private int minKeyVersion = 1;
    }

    /**
     * Periodic key-refresh settings including the exponential-backoff retry applied on Vault
     * outages.
     */
    @Getter
    @Setter
    @ToString
    public static class Refresh {
        /**
         * Interval at which Vault is checked for new key versions.
         */
        private Duration interval = Duration.ofMinutes(5);

        /**
         * Initial delay before the first retry after a failed refresh. A value of {@code 0} means
         * retries fire immediately (back-to-back), still bounded by {@link #maxAttempts}.
         */
        private Duration initialBackoff = Duration.ofSeconds(1);

        /**
         * Multiplier applied to the backoff delay between consecutive retries.
         */
        private double backoffMultiplier = 2.0;

        /**
         * Maximum delay between retries.
         */
        private Duration maxBackoff = Duration.ofMinutes(1);

        /**
         * Maximum number of retry attempts per refresh cycle.
         */
        private int maxAttempts = 5;
    }

    /**
     * Settings for the JWE servlet filter that transparently decrypts requests and encrypts
     * responses on the servlet stack: exclusions, ordering, the content-type allowlist, the
     * response-key header name, the mandatory-encryption toggles and the payload size limit.
     */
    @Getter
    @Setter
    @ToString
    public static class Filter {
        /**
         * Default order of the JWE servlet filter. Runs after the Spring Security filter chain
         * (registered at order {@code -100}) so decryption applies to already-authenticated
         * requests, and early enough to wrap the request before the {@code DispatcherServlet}.
         */
        public static final int DEFAULT_ORDER = 0;

        /**
         * Default JWE payload content type ({@code cty}) accepted on the allowlist.
         */
        public static final String DEFAULT_CONTENT_TYPE = "application/json";

        /**
         * Default name of the header carrying the client-supplied response-key envelope.
         */
        public static final String DEFAULT_RESPONSE_KEY_HEADER = "JWE-Response-Key";

        /**
         * Default include pattern: any path whose first segment contains {@code api} and everything
         * under it (e.g. {@code /api}, {@code /api/orders}, {@code /v1api/x}). {@code *} is an
         * intra-segment wildcard (does not span {@code /}).
         */
        public static final String DEFAULT_INCLUDED_PATH = "/*api*/**";

        /**
         * Path patterns (Spring {@code PathPattern} syntax) the filter applies to. Defaults to the API
         * paths ({@value #DEFAULT_INCLUDED_PATH}) so a Self-Contained-System app's static resources and
         * SPA shell are not encrypted. Evaluated <strong>before</strong> {@link #excludedPaths}.
         */
        private List<String> includedPaths = new ArrayList<>(List.of(DEFAULT_INCLUDED_PATH));

        /**
         * Path patterns (Spring {@code PathPattern} syntax) excluded from encryption, on top of the
         * built-in jEAP defaults (actuator, the JWKS endpoint, the protocol-metadata endpoint and the
         * jEAP SSE endpoint). Evaluated <strong>after</strong> {@link #includedPaths} (excludes win).
         * Requests not matched by an include, or matched by an exclude, are passed through unchanged.
         */
        private List<String> excludedPaths = new ArrayList<>();

        /**
         * Order of the JWE servlet filter in the servlet filter chain.
         */
        private int order = DEFAULT_ORDER;

        /**
         * Allowed JWE payload content types (the {@code cty} protected-header value). Inbound
         * requests whose {@code cty} is not on this list are rejected; the list is also exposed to
         * clients via the protocol-metadata endpoint.
         */
        private List<String> contentTypeAllowlist = new ArrayList<>(List.of(DEFAULT_CONTENT_TYPE));

        /**
         * Name of the request header carrying the client-supplied, RSA-wrapped content-encryption
         * key used to encrypt the response of a GET request.
         */
        private String responseKeyHeader = DEFAULT_RESPONSE_KEY_HEADER;

        /**
         * Whether an encrypted request body is mandatory on non-excluded paths for body methods
         * (POST/PUT/PATCH). When {@code true}, a plaintext body is rejected with HTTP 415.
         */
        private boolean requireEncryptedRequest = true;

        /**
         * Whether an encrypted response is mandatory on non-excluded paths for GET. When {@code true},
         * a GET that does not request encryption is rejected with HTTP 406, and one that requests it
         * without a response-key envelope with HTTP 400.
         */
        private boolean requireEncryptedResponse = true;

        /**
         * Base URI for the {@code type} field of the {@code application/problem+json} error responses.
         * The error {@code code} is appended as a path segment.
         */
        private String problemTypeBaseUri = JweFilterSettings.DEFAULT_PROBLEM_TYPE_BASE_URI;

        /**
         * Maximum size in bytes of an encrypted request body and of the response-key envelope header;
         * larger requests are rejected with HTTP 413.
         */
        private long maxPayloadBytes = JweFilterSettings.DEFAULT_MAX_PAYLOAD_BYTES;
    }

    /**
     * Settings for the JWE protocol-metadata endpoint that exposes the content-type allowlist and the
     * other client-facing protocol facts.
     */
    @Getter
    @Setter
    @ToString
    public static class Metadata {
        /**
         * Path under which the client-facing JWE configuration (content-type allowlist, supported
         * algorithms, JWKS path, response-key header) is served. Always excluded from encryption.
         */
        private String path = JweMetadataController.DEFAULT_METADATA_PATH;
    }

    /**
     * Static test mode: use statically provided RSA keys without any Vault
     * connection. No key refresh is performed in this mode.
     */
    @Getter
    @Setter
    @ToString
    public static class Test {
        /**
         * Enables the static test-key mode. When {@code true} Vault is not contacted.
         */
        private boolean enabled = false;

        /**
         * PEM-encoded RSA private keys used as static test keys. Excluded from {@code toString}
         * (rendered redacted) so private key material is never leaked to logs.
         */
        @ToString.Exclude
        private List<String> keys = new ArrayList<>();

        @ToString.Include(name = "keys")
        private String keysRedacted() {
            return keys.isEmpty() ? "[]" : "[**redacted, " + keys.size() + " entries**]";
        }
    }

    /**
     * Spring Security integration. Only relevant when Spring Security is on the classpath; otherwise
     * these settings have no effect.
     */
    @Getter
    @Setter
    @ToString
    public static class Security {
        /**
         * Whether the starter contributes a Spring Security filter chain that permits unauthenticated
         * access to the public JWKS and protocol-metadata endpoints (so clients can fetch the public
         * key before they authenticate). Enabled by default. Set to {@code false} to manage access to
         * these paths yourself. Has no effect when Spring Security is not on the classpath.
         */
        private boolean permitWellKnownEndpoints = true;
    }
}
