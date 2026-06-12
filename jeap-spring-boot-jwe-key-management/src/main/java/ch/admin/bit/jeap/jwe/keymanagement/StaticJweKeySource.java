package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweKeyValidationException;
import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import com.nimbusds.jose.jwk.RSAKey;

import java.util.List;
import java.util.stream.IntStream;

/**
 * Static, Vault-free {@link JweKeySource} for the test mode.
 *
 * <p>Loads RSA key pairs from PEM strings provided through configuration ({@code jeap.jwe.test.keys}),
 * so the encryption logic can be integration-tested in CI/CD without a Vault instance. Each PEM is
 * parsed and validated as 4096-bit through {@link JweRsaKeys#fromPem(String, String)} and
 * assigned a stable {@code kid} of {@code <keyName>:<version>}, mirroring the Vault source so kids are
 * identical for an equivalent key.
 *
 * <p>Versions are assigned in configuration order starting at 1, so <strong>later entries are newer
 * versions</strong>; the {@link JweKeyStore} orders them newest-first, making the last configured key
 * the current encryption key. No refresh is performed in this mode.
 */
public class StaticJweKeySource implements JweKeySource {

    private final String keyName;
    private final List<String> pemKeys;

    public StaticJweKeySource(String keyName, List<String> pemKeys) {
        this.keyName = keyName;
        this.pemKeys = List.copyOf(pemKeys);
    }

    @Override
    public List<RSAKey> loadActiveKeys() {
        if (pemKeys.isEmpty()) {
            throw new JweKeyValidationException(
                    "No static test keys configured; set jeap.jwe.test.keys when jeap.jwe.test.enabled=true.");
        }
        return IntStream.range(0, pemKeys.size())
                .mapToObj(index -> JweRsaKeys.fromPem(pemKeys.get(index), JweRsaKeys.keyId(keyName, index + 1)))
                .toList();
    }
}
