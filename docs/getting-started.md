# Getting Started

## Add the dependency

```xml

<dependency>
    <groupId>ch.admin.bit.jeap</groupId>
    <artifactId>jeap-spring-boot-jwe-starter</artifactId>
</dependency>
```

The starter is **active by default** when on the classpath. Set `jeap.jwe.enabled=false` to
disable it explicitly.

## Vault mode (production)

Configure the Vault transit key name. The secret-engine path defaults to
`transit/<jeap.vault.system-name>` when that property is set.

```yaml
jeap:
  jwe:
    vault:
      transit-key-name: my-jwe-key
```

The Vault transit key must be created as an **exportable rsa-4096** key:

```bash
vault write transit/<system>/keys/my-jwe-key type=rsa-4096 exportable=true
```

On startup the starter exports the active key versions, validates they are 4096-bit RSA, and
caches them in memory. The [JWKS endpoint](jwks-endpoint.md) becomes available immediately.

## Static test mode (no Vault)

For integration tests that don't need a Vault instance:

```yaml
jeap:
  jwe:
    test:
      enabled: true
      keys:
        - |
          -----BEGIN PRIVATE KEY-----
          ...PEM-encoded RSA 4096-bit private key...
          -----END PRIVATE KEY-----
```

See [docs/testing.md](testing.md) for details on using `JweTestKeys` and writing tests.

## What happens at startup

1. The auto-configuration resolves the key source (Vault or static test).
2. `JweKeyLoader` performs a **fail-fast** initial load - the context refuses to start if keys
   cannot be loaded.
3. The [JWKS endpoint](jwks-endpoint.md) serves the public keys.
4. In Vault mode, a [periodic refresh](key-management.md) keeps keys in sync with Vault rotations.

## Related

- [Configuration reference](configuration.md)
- [Vault integration](vault-integration.md)
- [Testing without Vault](testing.md)
