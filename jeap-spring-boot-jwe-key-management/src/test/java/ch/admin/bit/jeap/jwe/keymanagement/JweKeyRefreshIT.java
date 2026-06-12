package ch.admin.bit.jeap.jwe.keymanagement;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test of the periodic refresh against a real Vault dev container: rotating the
 * transit key and running a refresh picks up the new version atomically (new latest becomes the current
 * encryption key), and advancing {@code min_decryption_version} evicts versions that dropped out of the
 * active window.
 */
class JweKeyRefreshIT extends AbstractVaultTransitIT {

    @Test
    void refresh_picksUpRotationAndPromotesNewLatestVersion() {
        String keyName = "refresh-rotation-key";
        createExportableRsa4096Key(keyName);
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        JweKeyLoader loader = new JweKeyLoader(store, new VaultJweKeySource(vaultOperations, ENGINE, keyName, 1));
        loader.loadOrThrow();
        assertThat(store.currentEncryptionKey()).get().extracting(RSAKey::getKeyID).isEqualTo(keyName + ":1");

        rotate(keyName); // -> latest_version = 2
        loader.refresh();

        assertThat(store.activeKeys()).extracting(RSAKey::getKeyID).containsExactly(keyName + ":2", keyName + ":1");
        assertThat(store.currentEncryptionKey()).get().extracting(RSAKey::getKeyID).isEqualTo(keyName + ":2");
    }

    @Test
    void refresh_evictsVersionsBelowMinDecryptionVersion() {
        String keyName = "refresh-eviction-key";
        createExportableRsa4096Key(keyName);
        rotate(keyName);
        rotate(keyName); // versions 1..3
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        JweKeyLoader loader = new JweKeyLoader(store, new VaultJweKeySource(vaultOperations, ENGINE, keyName, 1));
        loader.loadOrThrow();
        assertThat(store.activeKeys()).hasSize(3);

        // Advance the active window so versions 1 and 2 are no longer decryptable.
        vaultOperations.write(ENGINE + "/keys/" + keyName + "/config", Map.of("min_decryption_version", 3));
        loader.refresh();

        assertThat(store.activeKeys()).extracting(RSAKey::getKeyID).containsExactly(keyName + ":3");
        assertThat(store.findByKeyId(keyName + ":1")).isEmpty();
        assertThat(store.findByKeyId(keyName + ":2")).isEmpty();
    }
}
