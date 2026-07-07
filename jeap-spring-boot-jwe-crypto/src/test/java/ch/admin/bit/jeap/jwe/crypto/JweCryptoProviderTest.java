package ch.admin.bit.jeap.jwe.crypto;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the Amazon Corretto Crypto Provider (ACCP) integration: the provider is installed, it is
 * actually used by the JWE crypto when healthy, and the code falls back to the JDK provider when it is
 * not — without ever failing the crypto round trip.
 */
class JweCryptoProviderTest {

    private static final String KID = "test-key:1";
    private static RSAKey key;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        key = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                .privateKey(pair.getPrivate())
                .keyID(KID)
                .build();
    }

    @Test
    void enabledFlagMatchesProviderRegistration() {
        // Referencing JweCryptoProvider triggers its static installation block.
        boolean enabled = JweCryptoProvider.isCorrettoEnabled();
        Provider provider = Security.getProvider(AmazonCorrettoCryptoProvider.PROVIDER_NAME);
        if (enabled) {
            assertThat(provider).as("a healthy ACCP must stay registered with the JCA").isNotNull();
        } else {
            assertThat(provider).as("an unhealthy ACCP must be removed so the JDK provider is used").isNull();
        }
    }

    @Test
    void corretoIsHealthyOnShippedPlatforms() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        boolean shipped = (os.contains("linux") && arch.equals("amd64"))
                || (os.contains("mac") && arch.equals("aarch64"));
        if (shipped) {
            assertThat(JweCryptoProvider.isCorrettoEnabled())
                    .as("ACCP native library is shipped for %s/%s and should be healthy", os, arch)
                    .isTrue();
        }
    }

    @Test
    void corretoIsTheResolvedProviderForSupportedCiphersWhenEnabled() throws Exception {
        JweCryptoProvider.ensureInstalled();
        if (!JweCryptoProvider.isCorrettoEnabled()) {
            return; // platform without ACCP: nothing to assert beyond the graceful fallback
        }
        // With ACCP installed at top priority, default JCA resolution must pick it for the JWE
        // primitives: AES-GCM (content encryption) and the generic RSA-OAEP padding that
        // JweRsaOaep256Decrypter uses for the RSA-OAEP-256 key unwrap (the SHA-256 digest is
        // supplied via the OAEPParameterSpec; the "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        // transformation Nimbus's own RSADecrypter would request is not registered by ACCP).
        assertThat(Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName())
                .isEqualTo(AmazonCorrettoCryptoProvider.PROVIDER_NAME);
        assertThat(Cipher.getInstance("RSA/ECB/OAEPPadding").getProvider().getName())
                .isEqualTo(AmazonCorrettoCryptoProvider.PROVIDER_NAME);
    }

    @Test
    void fullRoundTripWorksThroughTheSelectedProvider() throws Exception {
        // Request: RSA-OAEP-256 + A256GCM, decrypted via JweRequestDecryptor (applies ACCP when healthy).
        JWEObject request = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .keyID(KID).contentType("application/json").build(),
                new Payload("{\"hello\":\"world\"}"));
        request.encrypt(new RSAEncrypter(key.toRSAPublicKey()));

        DecryptedJwe decrypted = JweRequestDecryptor.decrypt(request.serialize(),
                keyId -> KID.equals(keyId) ? Optional.of(key) : Optional.empty());
        assertThat(new String(decrypted.plaintext(), UTF_8)).isEqualTo("{\"hello\":\"world\"}");

        // Response: direct A256GCM with a fresh CEK, encrypted via JweResponseEncryptor (applies ACCP).
        SecretKey cek = aes256();
        String responseJwe = JweResponseEncryptor.encrypt(
                "{\"answer\":42}".getBytes(UTF_8), cek, "application/json");
        JWEObject parsed = JWEObject.parse(responseJwe);
        parsed.decrypt(new com.nimbusds.jose.crypto.DirectDecrypter(cek));
        assertThat(new String(parsed.getPayload().toBytes(), UTF_8)).isEqualTo("{\"answer\":42}");
    }

    private static SecretKey aes256() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        return generator.generateKey();
    }
}
