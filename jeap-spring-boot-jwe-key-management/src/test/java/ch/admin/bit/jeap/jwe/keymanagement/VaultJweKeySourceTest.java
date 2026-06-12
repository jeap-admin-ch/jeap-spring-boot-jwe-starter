package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweKeyValidationException;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import org.junit.jupiter.api.Test;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the error branches of {@link VaultJweKeySource} (the happy path is covered against a
 * real Vault container by {@code VaultJweKeySourceIT}). Vault responses are stubbed so each failure mode
 * can be triggered deterministically.
 */
class VaultJweKeySourceTest {

    private static final String ENGINE = "transit";
    private static final String KEY = "my-jwe-key";

    private final VaultOperations vaultOperations = mock(VaultOperations.class);
    private final VaultJweKeySource source = new VaultJweKeySource(vaultOperations, ENGINE, KEY, 1);

    @Test
    void loadActiveKeys_throwsWhenKeyMetadataIsMissing() {
        when(vaultOperations.read(ENGINE + "/keys/" + KEY)).thenReturn(null);

        assertThatThrownBy(source::loadActiveKeys)
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("No Vault response")
                .hasMessageContaining(ENGINE + "/keys/" + KEY);
    }

    @Test
    void loadActiveKeys_throwsWhenLatestVersionFieldIsMissing() {
        when(vaultOperations.read(ENGINE + "/keys/" + KEY)).thenReturn(response(Map.of("min_decryption_version", 1)));

        assertThatThrownBy(source::loadActiveKeys)
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("latest_version");
    }

    @Test
    void loadActiveKeys_throwsWhenExportHasNoKeysMap() {
        stubMetadata(1, 1);
        when(vaultOperations.read(exportPath(1))).thenReturn(response(Map.of("name", KEY)));

        assertThatThrownBy(source::loadActiveKeys)
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("returned no keys");
    }

    @Test
    void loadActiveKeys_throwsWhenExportedKeyIsNotAPemString() {
        stubMetadata(1, 1);
        when(vaultOperations.read(exportPath(1))).thenReturn(response(Map.of("keys", Map.of("1", 42))));

        assertThatThrownBy(source::loadActiveKeys)
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("did not contain a PEM-encoded key");
    }

    @Test
    void loadActiveKeys_throwsWhenActiveWindowIsEmpty() {
        // min-version (5) above latest_version (2) -> empty window.
        VaultJweKeySource highMinVersion = new VaultJweKeySource(vaultOperations, ENGINE, KEY, 5);
        stubMetadata(1, 2);

        assertThatThrownBy(highMinVersion::loadActiveKeys)
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("no active versions in the window");
    }

    @Test
    void loadActiveKeys_parsesExportedPemIntoValidatedVersionedKey() {
        stubMetadata(1, 1);
        when(vaultOperations.read(exportPath(1)))
                .thenReturn(response(Map.of("keys", Map.of("1", JweTestKeys.rsa4096Pem(0)))));

        assertThat(source.loadActiveKeys())
                .singleElement()
                .satisfies(key -> {
                    assertThat(key.getKeyID()).isEqualTo(KEY + ":1");
                    assertThat(key.size()).isEqualTo(4096);
                });
    }

    private void stubMetadata(int minDecryptionVersion, int latestVersion) {
        when(vaultOperations.read(ENGINE + "/keys/" + KEY)).thenReturn(response(
                Map.of("latest_version", latestVersion, "min_decryption_version", minDecryptionVersion)));
    }

    private String exportPath(int version) {
        return ENGINE + "/export/encryption-key/" + KEY + "/" + version;
    }

    private static VaultResponse response(Map<String, Object> data) {
        VaultResponse response = new VaultResponse();
        response.setData(data);
        return response;
    }
}
