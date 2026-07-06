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

## Integrating with jEAP

The starter is designed to drop into a standard jEAP service and compose with the other jEAP
starters. The typical integration points:

### With jeap-security

Most jEAP services also run `jeap-spring-boot-security-starter`. The two work together — Spring
Security authenticates first (filter order `-100`), then the JWE filter decrypts (order `0`).

Clients must fetch the public key **before** they authenticate, so the JWKS and protocol-metadata
endpoints have to be reachable without a token. **The starter does this for you:** when Spring
Security is on the classpath it contributes a high-precedence `SecurityFilterChain` that permits
unauthenticated access to exactly those two paths (everything else stays protected by your
application's own chain). No manual `permitAll` rule is needed. Opt out with
`jeap.jwe.security.permit-well-known-endpoints=false` if you prefer to manage these paths yourself.

See [Using with jeap-security](servlet-filter.md#using-with-jeap-security) for the details.

### Vault path convention

The transit secret-engine path follows the jEAP convention `transit/<jeap.vault.system-name>`:
when `jeap.vault.system-name` is set (as in services using the jEAP Vault integration), the
starter derives the path automatically and only `jeap.jwe.vault.transit-key-name` needs to be
configured. Without it, set `jeap.jwe.vault.secret-engine-path` explicitly
(see [Vault integration](vault-integration.md#secret-engine-path)).

### Metrics and governance

Add `jeap-spring-boot-monitoring-starter` and the JWE metrics activate automatically — including
the `jeap.jwe.encryption.active` gauge a Governance service scrapes to verify that end-to-end
encryption is genuinely enforced. Without a Micrometer `MeterRegistry` the starter runs
metrics-free. See [Observability (metrics)](observability.md).

### jEAP Server-Sent Events

The jEAP SSE endpoint (`jeap.sse.web.endpoint`, default `/ui-api/sse/events`) is excluded from
encryption by default — streaming responses cannot be encrypted by the filter, and jEAP SSE
carries only event IDs. Expose any other streaming/async endpoints on excluded paths too
(see [Servlet filter](servlet-filter.md#path-matching-includes-then-excludes)).

### Angular frontends: jeap-jwe-client

For Angular applications, use the companion library
**[jeap-jwe-client](https://jeap-admin-ch.github.io/docs/building-blocks/libraries/jeap-jwe-client/)** —
an npm module providing an `HttpInterceptor` that discovers this starter's JWKS and protocol
metadata, transparently encrypts requests and decrypts responses, and handles key rotation. Other
clients implement the documented protocol directly (see [Client integration](client-integration.md)).

## Related

- [Configuration reference](configuration.md)
- [Servlet filter](servlet-filter.md)
- [Client integration](client-integration.md)
- [Vault integration](vault-integration.md)
- [Security considerations](security-considerations.md)
- [Troubleshooting](troubleshooting.md)
- [Testing without Vault](testing.md)
