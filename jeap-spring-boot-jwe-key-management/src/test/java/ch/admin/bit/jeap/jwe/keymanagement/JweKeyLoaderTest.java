package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JweKeyLoaderTest {

    private final RSAKey key = JweRsaKeys.from(JweTestKeys.rsa4096(0), JweRsaKeys.keyId("k", 1));

    @Test
    void loadOrThrowPopulatesStoreFromSource() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        JweKeyLoader loader = new JweKeyLoader(store, () -> List.of(key));

        loader.loadOrThrow();

        assertThat(store.currentEncryptionKey()).contains(key);
    }

    @Test
    void loadOrThrowFailsFastWhenSourceYieldsNoKeys() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        JweKeyLoader loader = new JweKeyLoader(store, List::of);

        assertThatThrownBy(loader::loadOrThrow)
                .isInstanceOf(JweKeyLoadException.class)
                .hasMessageContaining("No active 4096-bit JWE keys");
        assertThat(store.activeKeys()).isEmpty();
    }

    @Test
    void refreshSwapsCacheWithNewlyLoadedKeys() {
        RSAKey v2 = JweRsaKeys.from(JweTestKeys.rsa4096(1), JweRsaKeys.keyId("k", 2));
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(key));

        new JweKeyLoader(store, () -> List.of(key, v2)).refresh();

        assertThat(store.activeKeys()).containsExactly(v2, key);
        assertThat(store.currentEncryptionKey()).contains(v2);
    }

    @Test
    void refreshThrowsAndKeepsCacheWhenSourceReturnsNoKeys() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(key));
        JweKeyLoader loader = new JweKeyLoader(store, List::of);

        assertThatThrownBy(loader::refresh)
                .isInstanceOf(JweKeyLoadException.class)
                .hasMessageContaining("No active 4096-bit JWE keys");
        assertThat(store.activeKeys()).containsExactly(key);
    }

    @Test
    void loadOrThrowWrapsSourceFailureWithActionableMessage() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        JweKeyLoader loader = new JweKeyLoader(store, () -> {
            throw new IllegalStateException("vault down");
        });

        assertThatThrownBy(loader::loadOrThrow)
                .isInstanceOf(JweKeyLoadException.class)
                .hasMessageContaining("Failed to load JWE encryption keys")
                .hasMessageContaining("vault down")
                .hasCauseInstanceOf(IllegalStateException.class);
    }
}
