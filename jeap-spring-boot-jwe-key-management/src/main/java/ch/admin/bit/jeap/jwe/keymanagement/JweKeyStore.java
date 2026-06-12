package ch.admin.bit.jeap.jwe.keymanagement;

import com.nimbusds.jose.jwk.RSAKey;

import java.util.List;
import java.util.Optional;

/**
 * Read access to the currently active RSA key material the starter operates on.
 */
public interface JweKeyStore {

    /**
     * The active keys ordered newest-active-version first. Never {@code null}; empty only before the
     * first successful load.
     */
    List<RSAKey> activeKeys();

    /**
     * The current encryption key: the newest active version, i.e. the first element of
     * {@link #activeKeys()}. Empty only when no keys are loaded.
     */
    Optional<RSAKey> currentEncryptionKey();

    /**
     * Looks up an active key by its {@code kid} (the {@code <transitKeyName>:<version>} scheme of
     * {@code JweRsaKeys}), used to select the decryption key for an incoming message.
     */
    Optional<RSAKey> findByKeyId(String keyId);
}
