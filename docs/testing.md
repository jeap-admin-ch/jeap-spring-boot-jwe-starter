# Testing Without Vault

The starter provides a static test mode that works without any Vault connection. This is
useful for integration tests, local development, and CI environments.

## Static Test Mode

Enable test mode and provide PEM-encoded RSA private keys:

```yaml
jeap:
  jwe:
    test:
      enabled: true
      keys:
        - |
          -----BEGIN PRIVATE KEY-----
          ...4096-bit RSA key in PKCS#8 format...
          -----END PRIVATE KEY-----
```

In this mode:

- No Vault connection is made.
- No periodic refresh is scheduled.
- Keys are loaded once at startup from the configuration.
- The JWKS endpoint serves the corresponding public keys.

## JweTestKeys Utility

The `jeap-spring-boot-jwe-test` module provides pre-generated 4096-bit RSA test keys:

```xml

<dependency>
    <groupId>ch.admin.bit.jeap</groupId>
    <artifactId>jeap-spring-boot-jwe-test</artifactId>
    <scope>test</scope>
</dependency>
```

Usage in tests:

```java
import ch.admin.bit.jeap.jwe.test.JweTestKeys;

// PEM (public + private, as Vault export emits) for the jeap.jwe.test.keys property
String pem = JweTestKeys.rsa4096Pem(0);   // index 0, 1, or 2 — three reusable key pairs

        // The underlying java.security.KeyPair
        KeyPair keyPair = JweTestKeys.rsa4096(0);

        // A Nimbus RSAKey (with a kid), e.g. to act as the client and build a request JWE
        RSAKey rsaKey = JweRsaKeys.from(JweTestKeys.rsa4096(0), "my-jwe-key:1");
```

## Spring Boot Test Configuration

The key PEMs are generated at runtime, so feed them in with `@DynamicPropertySource` (an annotation
`properties = {…}` attribute only accepts compile-time constants):

```java

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MyIntegrationTest {

    @DynamicPropertySource
    static void jweKeys(DynamicPropertyRegistry registry) {
        registry.add("jeap.jwe.enabled", () -> true);
        registry.add("jeap.jwe.test.enabled", () -> true);
        registry.add("spring.cloud.vault.enabled", () -> false);
        registry.add("jeap.jwe.test.keys[0]", () -> JweTestKeys.rsa4096Pem(0));
    }
    // ...
}
```

## Encrypted Round-Trip Tests

Static test mode is enough to integration-test the full servlet-filter contract — request
decryption and response encryption — without Vault or Docker. A test acts as the client using
Nimbus: fetch a public key from the JWKS endpoint, build the request JWE
(`RSA-OAEP-256` + `A256GCM`), POST it, and decrypt the `dir`/`A256GCM` response with the CEK it
chose. For GET, send `Accept: application/jose` plus a `JWE-Response-Key` envelope. See
`JweFilterStaticModeIT` for a complete example covering happy paths, multi-version keys,
exclusions and the `problem+json` error table.

If your service also uses `jeap-spring-boot-security-starter`, `JweSecurityIntegrationIT` (in the
`jeap-spring-boot-jwe-security-it` module) shows the same static-key approach combined with a real
jeap-security resource server — minting test tokens with `JwsBuilderFactory` and asserting the
authentication / decryption ordering. See [Using with jeap-security](servlet-filter.md#using-with-jeap-security).

## Disabling the Starter in Tests

If a test does not need JWE at all:

```yaml
jeap:
  jwe:
    enabled: false
```

## Related

- [Getting started](getting-started.md)
- [Configuration reference](configuration.md)
- [Servlet filter](servlet-filter.md)
- [Client integration](client-integration.md)
- [Key management](key-management.md)
