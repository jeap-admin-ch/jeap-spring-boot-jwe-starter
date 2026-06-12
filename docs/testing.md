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

// Get PEM string for use in application properties
String pem = JweTestKeys.rsa4096Pem(0);  // index 0, 1, or 2

// Get Nimbus RSAKey for direct use
RSAKey rsaKey = JweTestKeys.rsa4096(0);
```

## Spring Boot Test Configuration

A typical integration test setup:

```java

@SpringBootTest(properties = {
        "jeap.jwe.test.enabled=true",
        "jeap.jwe.test.keys[0]=" + JweTestKeys.RSA_4096_PEM_0
})
class MyIntegrationTest {
    // ...
}
```

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
- [Key management](key-management.md)
