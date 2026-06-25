package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweRsaKeys;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InMemoryJweKeyStoreTest {

    private static final String KEY_NAME = "payment-key";
    public static final String PAYMENT_KEY_1 = "payment-key:1";

    private final RSAKey v1 = JweRsaKeys.from(JweTestKeys.rsa4096(0), JweRsaKeys.keyId(KEY_NAME, 1));
    private final RSAKey v2 = JweRsaKeys.from(JweTestKeys.rsa4096(1), JweRsaKeys.keyId(KEY_NAME, 2));
    private final RSAKey v3 = JweRsaKeys.from(JweTestKeys.rsa4096(2), JweRsaKeys.keyId(KEY_NAME, 3));

    @Test
    void emptyByDefault() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();

        assertThat(store.activeKeys()).isEmpty();
        assertThat(store.currentEncryptionKey()).isEmpty();
        assertThat(store.findByKeyId(PAYMENT_KEY_1)).isEmpty();
    }

    @Test
    void replaceKeysOrdersNewestVersionFirstRegardlessOfInputOrder() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();

        store.replaceKeys(List.of(v1, v3, v2));

        assertThat(store.activeKeys()).containsExactly(v3, v2, v1);
        assertThat(store.currentEncryptionKey()).contains(v3);
    }

    @Test
    void findByKeyIdHitAndMiss() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(v1, v2));

        assertThat(store.findByKeyId("payment-key:2")).contains(v2);
        assertThat(store.findByKeyId(PAYMENT_KEY_1)).contains(v1);
        assertThat(store.findByKeyId("payment-key:99")).isEmpty();
    }

    @Test
    void replaceKeysRejectsNonNumericVersionSuffix() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        RSAKey malformed = JweRsaKeys.from(JweTestKeys.rsa4096(0), KEY_NAME + ":abc");
        List<RSAKey> keys = List.of(malformed);

        assertThatThrownBy(() -> store.replaceKeys(keys))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("non-numeric version");
    }

    @Test
    void replaceKeysSwapsSnapshotAtomically() {
        InMemoryJweKeyStore store = new InMemoryJweKeyStore();
        store.replaceKeys(List.of(v1));
        List<RSAKey> beforeSwap = store.activeKeys();

        store.replaceKeys(List.of(v2, v3));

        // The previously returned snapshot is unaffected by the swap (immutable view).
        assertThat(beforeSwap).containsExactly(v1);
        assertThat(store.activeKeys()).containsExactly(v3, v2);
        assertThat(store.currentEncryptionKey()).contains(v3);
        assertThat(store.findByKeyId(PAYMENT_KEY_1)).isEmpty();
    }
}
