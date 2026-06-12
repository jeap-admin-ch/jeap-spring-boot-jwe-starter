package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Builds stubbed {@link VaultOperations} for the starter wiring tests, so the transit metadata + export
 * responses are configured in one place instead of being rebuilt in each test class. Real Vault
 * behaviour is covered by the Testcontainers integration tests in the key-management module.
 */
final class StubVaultTransit {

    private StubVaultTransit() {
    }

    /**
     * A transit key with a single active version (1), exported as a real 4096-bit test key.
     */
    static VaultOperations withSingleVersion(String enginePath, String keyName) {
        return withVersions(enginePath, keyName, 1, 1);
    }

    /**
     * A transit key whose active window is {@code minDecryptionVersion..latestVersion}, each exportable.
     */
    static VaultOperations withVersions(String enginePath, String keyName, int minDecryptionVersion, int latestVersion) {
        VaultOperations vaultOperations = mock(VaultOperations.class);
        when(vaultOperations.read(enginePath + "/keys/" + keyName)).thenReturn(
                response(Map.of("latest_version", latestVersion, "min_decryption_version", minDecryptionVersion)));
        for (int version = minDecryptionVersion; version <= latestVersion; version++) {
            VaultResponse export = response(Map.of("keys", Map.of(String.valueOf(version), JweTestKeys.rsa4096Pem(version - 1))));
            when(vaultOperations.read(enginePath + "/export/encryption-key/" + keyName + "/" + version)).thenReturn(export);
        }
        return vaultOperations;
    }

    /**
     * A Vault that is unreachable: every read throws, simulating a transient outage.
     */
    static VaultOperations unreachable(String message) {
        VaultOperations vaultOperations = mock(VaultOperations.class);
        when(vaultOperations.read(anyString())).thenThrow(new RuntimeException(message));
        return vaultOperations;
    }

    private static VaultResponse response(Map<String, Object> data) {
        VaultResponse response = new VaultResponse();
        response.setData(data);
        return response;
    }
}
