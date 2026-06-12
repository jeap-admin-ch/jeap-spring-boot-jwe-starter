package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.web.JweJwksController;
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
    private final Test test = new Test();

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
         * Initial delay before the first retry after a failed refresh.
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
}
