package ch.admin.bit.jeap.jwe.keymanagement;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test of {@link VaultJweKeySource} against a real Vault dev container.
 *
 * <p>Each test creates its own exportable {@code rsa-4096} transit key (no shared mutable state, so the
 * tests are order-independent). The test verifies that all active versions are exported with matching
 * {@code kid}s, that the {@code min_decryption_version}/{@code latest_version} window and
 * {@code jeap.jwe.vault.min-key-version} are honored, that the newest version becomes the current encryption key
 * (newest-first via the store), and that a rotation promotes the new latest version while older versions
 * remain decryptable.
 */
class VaultJweKeySourceIT extends AbstractVaultTransitIT {

    @Test
    void loadActiveKeys_exportsAllActiveVersionsAs4096BitKeysWithMatchingKids() {
        String keyName = "all-versions-key";
        createExportableRsa4096Key(keyName);
        rotate(keyName); // -> latest_version = 2

        List<RSAKey> keys = new VaultJweKeySource(vaultOperations, ENGINE, keyName, 1).loadActiveKeys();

        assertThat(keys).extracting(RSAKey::getKeyID)
                .containsExactlyInAnyOrder(keyName + ":1", keyName + ":2");
        assertThat(keys).allSatisfy(key -> {
            assertThat(key.size()).isEqualTo(4096);
            assertThat(key.isPrivate()).isTrue();
        });
    }

    @Test
    void store_exposesLatestVersionAsCurrentEncryptionKey() {
        String keyName = "current-key";
        createExportableRsa4096Key(keyName);
        rotate(keyName); // -> latest_version = 2
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();

        store.replaceKeys(new VaultJweKeySource(vaultOperations, ENGINE, keyName, 1).loadActiveKeys());

        assertThat(store.activeKeys()).extracting(RSAKey::getKeyID)
                .containsExactly(keyName + ":2", keyName + ":1");
        assertThat(store.currentEncryptionKey()).get()
                .extracting(RSAKey::getKeyID).isEqualTo(keyName + ":2");
        assertThat(store.findByKeyId(keyName + ":1")).isPresent();
    }

    @Test
    void loadActiveKeys_honorsMinVersion() {
        String keyName = "min-version-key";
        createExportableRsa4096Key(keyName);
        rotate(keyName); // -> latest_version = 2

        List<RSAKey> keys = new VaultJweKeySource(vaultOperations, ENGINE, keyName, 2).loadActiveKeys();

        assertThat(keys).extracting(RSAKey::getKeyID).containsExactly(keyName + ":2");
    }

    @Test
    void loadActiveKeys_afterRotation_promotesNewLatestVersionAndKeepsOlderVersions() {
        String keyName = "rotating-key";
        createExportableRsa4096Key(keyName);
        rotate(keyName); // -> latest_version = 2
        VaultJweKeySource source = new VaultJweKeySource(vaultOperations, ENGINE, keyName, 1);
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();

        rotate(keyName); // -> latest_version = 3
        store.replaceKeys(source.loadActiveKeys());

        assertThat(store.activeKeys()).extracting(RSAKey::getKeyID)
                .containsExactly(keyName + ":3", keyName + ":2", keyName + ":1");
        assertThat(store.currentEncryptionKey()).get()
                .extracting(RSAKey::getKeyID).isEqualTo(keyName + ":3");
        // Prior versions remain available for decryption during the rotation grace period.
        assertThat(store.findByKeyId(keyName + ":1")).isPresent();
    }
}
