package ch.admin.bit.jeap.jwe.keymanagement;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.VaultTemplate;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

import java.net.URI;
import java.util.Map;

/**
 * Base class for the Vault transit integration tests. Owns a single Vault dev container (transit engine
 * enabled) shared across all subclasses via the Testcontainers singleton-container pattern.
 */
abstract class AbstractVaultTransitIT {

    protected static final String ENGINE = "transit";
    private static final String TOKEN = "root-token";

    @SuppressWarnings("resource")
    private static final VaultContainer<?> VAULT =
            new VaultContainer<>(DockerImageName.parse("hashicorp/vault:1.21.2")
                    .asCompatibleSubstituteFor("hashicorp/vault"))
                    .withVaultToken(TOKEN)
                    .withInitCommand("secrets enable transit");

    static {
        VAULT.start();
    }

    protected VaultOperations vaultOperations;

    @BeforeEach
    void initVaultOperations() {
        VaultEndpoint endpoint = VaultEndpoint.from(URI.create(VAULT.getHttpHostAddress()));
        vaultOperations = new VaultTemplate(endpoint, new TokenAuthentication(TOKEN));
    }

    /**
     * Creates an exportable {@code rsa-4096} transit key (version 1).
     */
    protected void createExportableRsa4096Key(String name) {
        vaultOperations.write(ENGINE + "/keys/" + name, Map.of("type", "rsa-4096", "exportable", true));
    }

    /**
     * Rotates the transit key, adding a new active version.
     */
    protected void rotate(String name) {
        vaultOperations.write(ENGINE + "/keys/" + name + "/rotate", Map.of());
    }
}
