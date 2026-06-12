package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweKeyValidationException;
import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Vault-backed {@link JweKeySource}: the production key source.
 *
 * <p>Reads the transit key's active-version window and exports the RSA key pair of every active
 * version through Spring Cloud Vault ({@link VaultOperations}):
 * <ul>
 *   <li>{@code GET <engine>/keys/<name>} → {@code latest_version} and {@code min_decryption_version},
 *       which bound the window;</li>
 *   <li>{@code GET <engine>/export/encryption-key/<name>/<version>} → the PEM-encoded key pair for
 *       each version in the window (the transit key must be created {@code exportable=true}, type
 *       {@code rsa-4096}).</li>
 * </ul>
 *
 * <p>The window starts at {@code max(min_decryption_version, jeap.jwe.vault.min-key-version)} so versions below
 * the configured minimum are never loaded, and ends at {@code latest_version} (the current encryption
 * key). Each PEM is parsed and validated as 4096-bit via {@link JweRsaKeys#fromPem(String, String)}
 * and assigned the {@code <name>:<version>} {@code kid}, identical to the JWKS output. The
 * {@link JweKeyStore} orders the result newest-version first, exposing {@code latest_version} at
 * {@code keys[0]}. Key material stays in the JVM heap.
 *
 * <p>Required Vault policy: read capability on {@code <engine>/keys/<name>} and on
 * {@code <engine>/export/encryption-key/<name>}.
 */
public class VaultJweKeySource implements JweKeySource {

    private final VaultOperations vaultOperations;
    private final String secretEnginePath;
    private final String transitKeyName;
    private final int minVersion;

    public VaultJweKeySource(VaultOperations vaultOperations, String secretEnginePath, String transitKeyName, int minVersion) {
        this.vaultOperations = vaultOperations;
        this.secretEnginePath = secretEnginePath;
        this.transitKeyName = transitKeyName;
        this.minVersion = minVersion;
    }

    @Override
    public List<RSAKey> loadActiveKeys() {
        Map<String, Object> metadata = readData(keyMetadataPath());
        int latestVersion = intValue(metadata, "latest_version");
        int minDecryptionVersion = intValue(metadata, "min_decryption_version");
        int fromVersion = Math.max(Math.max(minDecryptionVersion, minVersion), 1);

        List<RSAKey> keys = new ArrayList<>();
        for (int version = fromVersion; version <= latestVersion; version++) {
            keys.add(exportKey(version));
        }
        if (keys.isEmpty()) {
            throw new JweKeyValidationException(
                    "Vault transit key '" + transitKeyName + "' has no active versions in the window "
                            + fromVersion + ".." + latestVersion + " (check min_decryption_version and jeap.jwe.vault.min-key-version).");
        }
        return keys;
    }

    private RSAKey exportKey(int version) {
        Map<String, Object> data = readData(exportPath(version));
        if (!(data.get("keys") instanceof Map<?, ?> versionedKeys)) {
            throw new JweKeyValidationException(
                    "Vault export for '" + transitKeyName + "' v" + version + " returned no keys; is the transit key exportable?");
        }
        if (!(versionedKeys.get(String.valueOf(version)) instanceof String pem)) {
            throw new JweKeyValidationException(
                    "Vault export for '" + transitKeyName + "' v" + version + " did not contain a PEM-encoded key.");
        }
        return JweRsaKeys.fromPem(pem, JweRsaKeys.keyId(transitKeyName, version));
    }

    private Map<String, Object> readData(String path) {
        VaultResponse response = vaultOperations.read(path);
        Map<String, Object> data;
        if (response == null || (data = response.getData()) == null) {
            throw new JweKeyValidationException(
                    "No Vault response for '" + path + "'; check the transit key name and the read policy.");
        }
        return data;
    }

    private int intValue(Map<String, Object> data, String field) {
        if (!(data.get(field) instanceof Number number)) {
            throw new JweKeyValidationException("Vault transit metadata is missing the numeric field '" + field + "'.");
        }
        return number.intValue();
    }

    private String keyMetadataPath() {
        return secretEnginePath + "/keys/" + transitKeyName;
    }

    private String exportPath(int version) {
        return secretEnginePath + "/export/encryption-key/" + transitKeyName + "/" + version;
    }
}
