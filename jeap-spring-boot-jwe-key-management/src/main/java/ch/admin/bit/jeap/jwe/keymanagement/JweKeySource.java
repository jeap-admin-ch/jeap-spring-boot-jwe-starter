package ch.admin.bit.jeap.jwe.keymanagement;

import com.nimbusds.jose.jwk.RSAKey;

import java.util.List;

/**
 * Supplies the currently active RSA key pairs that populate the {@link JweKeyStore}.
 *
 * <p>Two implementations sit behind this abstraction, selected by configuration: a static,
 * Vault-free source for the test mode ({@link StaticJweKeySource}) and the Vault transit
 * source for production ({@code VaultJweKeySource}). The store loads from the source at
 * startup and on each refresh cycle; the source is responsible only for producing
 * validated keys, not for caching or ordering.
 */
public interface JweKeySource {

    /**
     * Loads the active key pairs (with private material) from the backing store. Each key is validated
     * as 4096-bit and carries a stable {@code kid}.
     *
     * <p>Contract: returns a <strong>non-empty</strong> list or <strong>throws</strong>. An
     * implementation must never return an empty list to signal "no keys" - it throws (e.g.
     * {@link ch.admin.bit.jeap.jwe.crypto.JweKeyValidationException}) instead, so callers can treat an
     * empty active-version window as a load failure rather than silently wiping the cache.
     */
    List<RSAKey> loadActiveKeys();
}
