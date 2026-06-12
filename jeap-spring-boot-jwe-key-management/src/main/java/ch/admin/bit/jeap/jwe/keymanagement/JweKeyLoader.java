package ch.admin.bit.jeap.jwe.keymanagement;

import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Loads keys from a {@link JweKeySource} into an {@link InMemoryJweKeyStore}.
 */
public class JweKeyLoader {

    private static final Logger log = LoggerFactory.getLogger(JweKeyLoader.class);

    private final InMemoryJweKeyStore keyStore;
    private final JweKeySource keySource;

    public JweKeyLoader(InMemoryJweKeyStore keyStore, JweKeySource keySource) {
        this.keyStore = keyStore;
        this.keySource = keySource;
    }

    /**
     * Performs the initial, single-attempt key load and populates the store. Throws
     * {@link JweKeyLoadException} if the source fails or yields no active key.
     */
    public void loadOrThrow() {
        List<RSAKey> keys = load();
        keyStore.replaceKeys(keys);
        log.info("Loaded {} active JWE key version(s) at startup: {}.", keys.size(), keyIds(keys));
    }

    /**
     * Re-exports the active versions and atomically swaps the cache, picking up rotations (new
     * {@code latest_version}) and evictions (advanced {@code min_decryption_version}). Throws
     * {@link JweKeyLoadException} on any failure (source error or no active key) <em>before</em>
     * touching the cache, so the current snapshot is left untouched and the caller can apply its
     * outage policy (kept-cache + backoff).
     */
    public void refresh() {
        List<RSAKey> keys = load();
        keyStore.replaceKeys(keys);
        log.info("Refreshed JWE keys: {} active version(s) {}.", keys.size(), keyIds(keys));
    }

    private List<RSAKey> load() {
        List<RSAKey> keys;
        try {
            keys = keySource.loadActiveKeys();
        } catch (RuntimeException e) {
            throw new JweKeyLoadException(
                    "Failed to load JWE encryption keys. If Vault is required, verify that it is reachable, the "
                            + "authentication is valid, and the transit key exists and is exportable (rsa-4096). "
                            + "Cause: " + e.getMessage(), e);
        }
        if (keys.isEmpty()) {
            throw new JweKeyLoadException(
                    "No active 4096-bit JWE keys were available. Check jeap.jwe.vault.min-key-version and the transit key's "
                            + "active version window (min_decryption_version..latest_version).");
        }
        return keys;
    }

    private static List<String> keyIds(List<RSAKey> keys) {
        return keys.stream().map(RSAKey::getKeyID).toList();
    }
}
