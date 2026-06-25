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

The starter reads the key through **Spring Cloud Vault**, so the application must also have Vault
connectivity and authentication configured (`spring.cloud.vault.*`). The full prerequisites (transit
engine, policy, authentication) are in [Vault integration](vault-integration.md).

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

## Transparent encryption

The starter is **enabled by default** (set `jeap.jwe.enabled=false` to opt out). When enabled, the
[servlet filter](servlet-filter.md) transparently **decrypts** JWE request bodies and **encrypts**
responses on the paths it applies to — controllers keep working with plain JSON. Encryption is
mandatory on those paths (a plain request is rejected with a structured `problem+json` error).

**Which paths are encrypted.** By default only **API paths** are filtered: `jeap.jwe.filter.included-paths`
defaults to `[/*api*/**]`, i.e. any path whose first segment contains `api` (`/api/**`, `/v1api/**`,
…). This keeps a Self-Contained-System app from encrypting its static resources / SPA shell. If your
API does not live under an `*api*` segment, broaden `included-paths` (e.g. to `/**`). The actuator
base path (including health), the JWKS endpoint, the protocol-metadata endpoint and jEAP SSE are
always excluded. See [Servlet filter](servlet-filter.md) for the path model and request/response flow,
[Configuration reference](configuration.md) for every property, and
[Client integration](client-integration.md) for the client side.

## With jeap-security

Most jEAP services also run `jeap-spring-boot-security-starter`. The two work together — Spring
Security authenticates first (filter order `-100`), then the JWE filter decrypts (order `0`).

Clients must fetch the public key **before** they authenticate, so the JWKS and protocol-metadata
endpoints have to be reachable without a token. **The starter does this for you:** when Spring
Security is on the classpath it contributes a high-precedence `SecurityFilterChain` that permits
unauthenticated access to exactly those two paths (everything else stays protected by your
application's own chain). No manual `permitAll` rule is needed. Opt out with
`jeap.jwe.security.permit-well-known-endpoints=false` if you prefer to manage these paths yourself.

See [Using with jeap-security](servlet-filter.md#using-with-jeap-security) for the details.

## Related

- [Configuration reference](configuration.md)
- [Servlet filter](servlet-filter.md)
- [Client integration](client-integration.md)
- [Vault integration](vault-integration.md)
- [Testing without Vault](testing.md)
