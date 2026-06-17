package ch.admin.bit.jeap.jwe.starter;

import ch.admin.bit.jeap.jwe.test.JweTestKeys;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwePropertiesTest {

    @Test
    void toStringDoesNotLeakStaticPrivateKeyMaterial() {
        JweProperties properties = new JweProperties();
        properties.getTest().setEnabled(true);
        properties.getTest().getKeys().add(JweTestKeys.rsa4096Pem(0));

        String rendered = properties.toString();

        assertThat(rendered)
                .doesNotContain("BEGIN PRIVATE KEY")
                .doesNotContain("BEGIN RSA PRIVATE KEY")
                .contains("redacted")
                .contains("1 entries");
    }

    @Test
    void toStringRendersEmptyKeyListPlainly() {
        assertThat(new JweProperties().toString()).contains("keys=[]");
    }
}
