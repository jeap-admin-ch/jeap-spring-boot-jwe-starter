package ch.admin.bit.jeap.jwe.crypto;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JweRsaKeysTest {

    private static KeyPair rsa4096;
    private static KeyPair rsa2048;
    private static KeyPair rsa3072;

    @BeforeAll
    static void generateKeys() throws Exception {
        rsa4096 = rsa(4096);
        rsa2048 = rsa(2048);
        rsa3072 = rsa(3072);
    }

    @Test
    void from_with4096Key_buildsEncryptionRsaKey() {
        RSAKey key = JweRsaKeys.from(rsa4096, "my-key:1");

        assertThat(key.size()).isEqualTo(4096);
        assertThat(key.getKeyID()).isEqualTo("my-key:1");
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        assertThat(key.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
        assertThat(key.isPrivate()).isTrue();
    }

    @Test
    void from_with2048Key_rejected() {
        assertThatThrownBy(() -> JweRsaKeys.from(rsa2048, "k:1"))
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("4096");
    }

    @Test
    void from_with3072Key_rejected() {
        assertThatThrownBy(() -> JweRsaKeys.from(rsa3072, "k:1"))
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("4096");
    }

    @Test
    void from_withNonRsaKey_rejected() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(256);
        KeyPair ec = gen.generateKeyPair();

        assertThatThrownBy(() -> JweRsaKeys.from(ec, "k:1"))
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("RSA");
    }

    @Test
    void fromPem_roundTripsPrivateRsaKey() {
        String pem = pem(rsa4096);

        RSAKey key = JweRsaKeys.fromPem(pem, "my-key:2");

        assertThat(key.size()).isEqualTo(4096);
        assertThat(key.getKeyID()).isEqualTo("my-key:2");
        assertThat(key.isPrivate()).isTrue();
        assertThat(key.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        assertThat(key.getAlgorithm()).isEqualTo(JWEAlgorithm.RSA_OAEP_256);
    }

    @Test
    void fromPem_with2048Key_rejected() {
        String pem = pem(rsa2048);
        assertThatThrownBy(() -> JweRsaKeys.fromPem(pem, "k:1"))
                .isInstanceOf(JweKeyValidationException.class)
                .hasMessageContaining("4096");
    }

    @Test
    void keyId_followsTransitKeyNameVersionScheme() {
        assertThat(JweRsaKeys.keyId("payment-key", 3)).isEqualTo("payment-key:3");
    }

    @Test
    void keyId_isStableForSameInput() {
        assertThat(JweRsaKeys.keyId("k", 7)).isEqualTo(JweRsaKeys.keyId("k", 7));
    }

    @Test
    void keyId_rejectsBlankNameAndInvalidVersion() {
        assertThatThrownBy(() -> JweRsaKeys.keyId("  ", 1)).isInstanceOf(JweKeyValidationException.class);
        assertThatThrownBy(() -> JweRsaKeys.keyId("k", 0)).isInstanceOf(JweKeyValidationException.class);
    }

    @Test
    void publicJwkSet_containsPublicParamsOnly() {
        RSAKey key = JweRsaKeys.from(rsa4096, "my-key:1");

        String json = JweRsaKeys.toPublicJwkSetJson(List.of(key));

        assertThat(json)
                .contains("\"kty\":\"RSA\"")
                .contains("\"use\":\"enc\"")
                .contains("\"kid\":\"my-key:1\"")
                .contains("RSA-OAEP-256")
                .contains("\"n\":")
                .contains("\"e\":")
                .doesNotContain("\"d\":")
                .doesNotContain("\"p\":")
                .doesNotContain("\"q\":")
                .doesNotContain("\"dp\":")
                .doesNotContain("\"dq\":")
                .doesNotContain("\"qi\":");
    }

    @Test
    void publicJwkSet_toStringHasNoPrivateMaterial() {
        RSAKey key = JweRsaKeys.from(rsa4096, "my-key:1");

        JWKSet publicSet = JweRsaKeys.toPublicJwkSet(List.of(key));

        assertThat(publicSet.toString()).doesNotContain("\"d\":");
    }

    private static KeyPair rsa(int size) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(size);
        return generator.generateKeyPair();
    }

    private static String pem(KeyPair keyPair) {
        return block("PUBLIC KEY", keyPair.getPublic().getEncoded()) + "\n"
                + block("PRIVATE KEY", keyPair.getPrivate().getEncoded());
    }

    private static String block(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----";
    }
}
