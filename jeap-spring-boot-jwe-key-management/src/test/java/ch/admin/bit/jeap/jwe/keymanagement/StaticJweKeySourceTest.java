package ch.admin.bit.jeap.jwe.keymanagement;

import ch.admin.bit.jeap.jwe.crypto.JweKeyValidationException;
import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StaticJweKeySourceTest {

    public static final String TEST_KEY = "test-key";

    @Test
    void loadActiveKeysAssignsStableVersionedKidsInConfigOrder() {
        StaticJweKeySource source = new StaticJweKeySource(
                TEST_KEY, List.of(JweTestKeys.rsa4096Pem(0), JweTestKeys.rsa4096Pem(1)));

        List<RSAKey> keys = source.loadActiveKeys();

        assertThat(keys).extracting(RSAKey::getKeyID).containsExactly("test-key:1", "test-key:2");
        assertThat(keys).allSatisfy(key -> {
            assertThat(key.size()).isEqualTo(4096);
            assertThat(key.isPrivate()).isTrue();
        });
    }

    @Test
    void loadActiveKeysRejectsUndersizedKey() {
        String pem2048 = JweTestKeys.pem(JweTestKeys.generate(2048));
        StaticJweKeySource source = new StaticJweKeySource(TEST_KEY, List.of(pem2048));

        assertThatThrownBy(source::loadActiveKeys)
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("4096");
    }

    @Test
    void loadActiveKeysFailsWhenNoKeysConfigured() {
        StaticJweKeySource source = new StaticJweKeySource(TEST_KEY, List.of());

        assertThatThrownBy(source::loadActiveKeys)
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("jeap.jwe.test.keys");
    }
}
