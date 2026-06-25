package ch.admin.bit.jeap.jwe.web;

import ch.admin.bit.jeap.jwe.keymanagement.JweKeyStore;
import com.nimbusds.jose.jwk.RSAKey;

import java.util.List;
import java.util.Optional;

/**
 * Test fixtures for {@link JweKeyStore} stubs, shared across the web filter tests.
 */
final class TestJweKeyStores {

    private TestJweKeyStores() {
    }

    /**
     * A store holding a single active key, resolvable by its own {@code kid}.
     */
    static JweKeyStore single(RSAKey key) {
        return new JweKeyStore() {
            @Override
            public List<RSAKey> activeKeys() {
                return List.of(key);
            }

            @Override
            public Optional<RSAKey> currentEncryptionKey() {
                return Optional.of(key);
            }

            @Override
            public Optional<RSAKey> findByKeyId(String keyId) {
                return key.getKeyID().equals(keyId) ? Optional.of(key) : Optional.empty();
            }
        };
    }

    /**
     * An empty store (no active keys).
     */
    static JweKeyStore none() {
        return new JweKeyStore() {
            @Override
            public List<RSAKey> activeKeys() {
                return List.of();
            }

            @Override
            public Optional<RSAKey> currentEncryptionKey() {
                return Optional.empty();
            }

            @Override
            public Optional<RSAKey> findByKeyId(String keyId) {
                return Optional.empty();
            }
        };
    }
}
