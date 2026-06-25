# Configuration Reference

All properties live under the `jeap.jwe` prefix.

## Core

| Property           | Type      | Default | Description                                             |
|--------------------|-----------|---------|---------------------------------------------------------|
| `jeap.jwe.enabled` | `boolean` | `true`  | Master switch. Set to `false` to disable all JWE beans. |

## JWKS Endpoint

| Property             | Type     | Default                  | Description                                                               |
|----------------------|----------|--------------------------|---------------------------------------------------------------------------|
| `jeap.jwe.jwks.path` | `String` | `/.well-known/jwks.json` | HTTP path for the JWKS endpoint. Must not overlap the actuator base path. |

## Vault

| Property                            | Type     | Default                            | Description                                                                                         |
|-------------------------------------|----------|------------------------------------|-----------------------------------------------------------------------------------------------------|
| `jeap.jwe.vault.transit-key-name`   | `String` | -                                  | Name of the exportable rsa-4096 Vault transit key. **Required** in Vault mode.                      |
| `jeap.jwe.vault.secret-engine-path` | `String` | `transit/<jeap.vault.system-name>` | Vault transit secret-engine mount path. Derived automatically when `jeap.vault.system-name` is set. |
| `jeap.jwe.vault.min-key-version`    | `int`    | `1`                                | Minimum accepted Vault key version. Versions below this are neither loaded nor served.              |

## Periodic Refresh

| Property                              | Type       | Default | Description                                                                                                                  |
|---------------------------------------|------------|---------|------------------------------------------------------------------------------------------------------------------------------|
| `jeap.jwe.refresh.interval`           | `Duration` | `5m`    | How often Vault is polled for new key versions.                                                                              |
| `jeap.jwe.refresh.initial-backoff`    | `Duration` | `1s`    | Initial delay before the first retry after a failed refresh. `0` means retries fire immediately (bounded by `max-attempts`). |
| `jeap.jwe.refresh.backoff-multiplier` | `double`   | `2.0`   | Multiplier applied between consecutive retries.                                                                              |
| `jeap.jwe.refresh.max-backoff`        | `Duration` | `1m`    | Maximum delay between retries.                                                                                               |
| `jeap.jwe.refresh.max-attempts`       | `int`      | `5`     | Maximum retry attempts per refresh cycle.                                                                                    |

## Servlet Filter

The servlet filter transparently decrypts JWE requests and encrypts responses on non-excluded
paths. See [Servlet filter](servlet-filter.md) for the request/response flow.

| Property                                     | Type           | Default                                  | Description                                                                                                                                                                      |
|----------------------------------------------|----------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jeap.jwe.filter.included-paths`             | `List<String>` | `[/*api*/**]`                            | Path patterns the filter applies to (`PathPattern` syntax). Defaults to API paths so an SCS app's static resources / SPA shell are not encrypted. Evaluated **before** excludes. |
| `jeap.jwe.filter.excluded-paths`             | `List<String>` | `[]`                                     | Additional path patterns excluded from encryption, on top of the built-in jEAP defaults (actuator, JWKS, metadata, SSE). Evaluated **after** includes (excludes win).            |
| `jeap.jwe.filter.order`                      | `int`          | `0`                                      | Order of the JWE filter in the servlet chain. Runs after the Spring Security filter chain (order `-100`) by default.                                                             |
| `jeap.jwe.filter.content-type-allowlist`     | `List<String>` | `[application/json]`                     | Allowed JWE payload content types (the `cty` header). Enforced on inbound requests and exposed to clients.                                                                       |
| `jeap.jwe.filter.response-key-header`        | `String`       | `JWE-Response-Key`                       | Request header carrying the client-supplied, RSA-wrapped content-encryption key used to encrypt a GET response.                                                                  |
| `jeap.jwe.filter.require-encrypted-request`  | `boolean`      | `true`                                   | Require an encrypted body on non-excluded POST/PUT/PATCH; a plaintext body is rejected with HTTP 415.                                                                            |
| `jeap.jwe.filter.require-encrypted-response` | `boolean`      | `true`                                   | Require encryption on non-excluded GET; without `Accept: application/jose` → 406, without a response-key envelope → 400.                                                         |
| `jeap.jwe.filter.problem-type-base-uri`      | `String`       | `https://jeap.bit.admin.ch/problems/jwe` | Base URI for the `type` field of `application/problem+json` errors; the error `code` is appended.                                                                                |
| `jeap.jwe.filter.max-payload-bytes`          | `long`         | `5242880` (5 MiB)                        | Max size of an encrypted request body and of the response-key header. Larger requests → HTTP 413.                                                                                |

The filter applies to a request when its path matches an **include** and no **exclude** — includes
are evaluated first, excludes second (excludes win). By default only API paths are included
(`/*api*/**`: any path whose first segment contains `api`, e.g. `/api/orders`), so a
Self-Contained-System app serving a frontend and static resources from the same Spring Boot server
does not encrypt those. Broaden `included-paths` (e.g. to `/**`) if your API lives elsewhere.

The JWKS, protocol-metadata and jEAP SSE endpoints are **always** excluded (encryption must never
lock out key distribution, and SSE carries only event IDs). Default actuator base path `/actuator`
is excluded; if you relocate actuator via `management.endpoints.web.base-path`, the new path is
excluded instead.

Both `included-paths` and `excluded-paths` are **application-relative**: the filter strips
`server.servlet.context-path` before matching, so the patterns must not contain the context path
(just like `@RequestMapping` paths). The defaults work the same at `/` or under a context path. The
metadata endpoint, however, publishes these paths **prefixed with the context path** for client use
(see [Servlet filter → Context path](servlet-filter.md#context-path)).

## Protocol Metadata

| Property                 | Type     | Default                          | Description                                                                                                                                                                                                              |
|--------------------------|----------|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jeap.jwe.metadata.path` | `String` | `/.well-known/jwe-configuration` | Path of the client-facing JWE configuration endpoint (content-type allowlist, supported algorithms, JWKS path, response-key header, and the effective `includedPaths`/`excludedPaths`). Always excluded from encryption. |

## Security

| Property                                        | Type      | Default | Description                                                                                                                                                                                                                                                                                           |
|-------------------------------------------------|-----------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jeap.jwe.security.permit-well-known-endpoints` | `boolean` | `true`  | When Spring Security is on the classpath, contribute a `SecurityFilterChain` that permits unauthenticated access to the JWKS and protocol-metadata paths so clients can fetch the public key before authenticating. Set to `false` to manage these paths yourself. No effect without Spring Security. |

## Static Test Mode

| Property                | Type           | Default | Description                                                                             |
|-------------------------|----------------|---------|-----------------------------------------------------------------------------------------|
| `jeap.jwe.test.enabled` | `boolean`      | `false` | Enables static test-key mode. No Vault connection is made; no refresh is scheduled.     |
| `jeap.jwe.test.keys`    | `List<String>` | `[]`    | PEM-encoded RSA private keys (PKCS#8). At least one required when test mode is enabled. |

## Validation

The starter validates configuration at startup and fails fast on:

- Missing `jeap.jwe.vault.transit-key-name` in Vault mode
- Missing `jeap.jwe.vault.secret-engine-path` when `jeap.vault.system-name` is also absent
- Empty `jeap.jwe.test.keys` in test mode
- Non-positive refresh interval or invalid backoff parameters
- JWKS path overlapping the actuator base path

## Related

- [Getting started](getting-started.md)
- [Servlet filter](servlet-filter.md)
- [Client integration](client-integration.md)
- [Key management](key-management.md)
- [Vault integration](vault-integration.md)
