# Servlet Filter

The starter registers a servlet filter (`JweServletFilter`) that will transparently decrypt
incoming JWE requests and encrypt outgoing responses, so controllers work with plain JSON and never
see the encryption. Only **servlet** (Spring MVC / Jakarta Servlet) applications are supported;
reactive (WebFlux) stacks are out of scope.

## Request decryption

For a non-excluded request with `Content-Type: application/jose`, the filter:

1. parses the compact JWE and validates the protected header (`alg: RSA-OAEP-256`,
   `enc: A256GCM`, a present `kid`);
2. selects the matching private key from the in-memory key store by `kid` (any active key version
   is accepted, supporting the rotation grace period);
3. unwraps the content-encryption key (CEK) with RSA-OAEP-256 and decrypts the payload with
   A256GCM;
4. checks the JWE `cty` against the configured content-type allowlist
   (`jeap.jwe.filter.content-type-allowlist`, default `application/json`);
5. wraps the request so the `DispatcherServlet` and controllers see the plaintext body and the
   `cty` content type (overriding `getInputStream`, `getReader`, `getContentType`,
   `getHeader("Content-Type")`, `getContentLength`/`getContentLengthLong`).

The recovered CEK is kept for the duration of the request so the response can be encrypted with the
same key. Key material and plaintext are never logged. Decryption uses only Nimbus JOSE+JWT and the
JCA — no custom cryptography.

## Response encryption

The filter encrypts the controller's response as a compact JWE (`alg: dir`, `enc: A256GCM`) served
with `Content-Type: application/jose`. The content-encryption key (CEK) is **always** the one the
client supplies in the `JWE-Response-Key` header — a separate CEK from the request's, for **every**
method (GET and POST/PUT/PATCH alike). The request's CEK is used only to decrypt the request body and
is never reused for the response.

The client wraps a fresh 256-bit response CEK to the service's public key as a compact JWE
(RSA-OAEP-256 + A256GCM, payload = the 32-byte CEK) and sends it in the `JWE-Response-Key` header
together with `Accept: application/jose`. The filter unwraps it and encrypts the response with that
CEK; the client decrypts the response with the CEK it generated. A missing/invalid envelope yields
400, and an envelope larger than `jeap.jwe.filter.max-payload-bytes` yields 413.

The response `cty` reflects the controller's content type (e.g. `application/json`). A fresh IV is
generated per response. Only successful (2xx) responses are encrypted; error responses are returned
as-is (see below).

## Mandatory encryption & error handling

On non-excluded paths encryption is mandatory (configurable via
`jeap.jwe.filter.require-encrypted-request` / `require-encrypted-response`, both default `true`):

- **POST/PUT/PATCH** must send an encrypted body (`Content-Type: application/jose`).
- **GET and POST/PUT/PATCH** must request an encrypted response with `Accept: application/jose` and a
  `JWE-Response-Key` envelope.

Every protocol failure is returned as `application/problem+json` (RFC 7807) — never encrypted —
with a stable machine-readable `code`. The `type` URI is built from
`jeap.jwe.filter.problem-type-base-uri` (default `https://jeap.bit.admin.ch/problems/jwe`).

| Scenario                                                           | Status | `code`                              |
|--------------------------------------------------------------------|--------|-------------------------------------|
| POST/PUT/PATCH body not `application/jose`                         | 415    | `JWE_REQUEST_ENCRYPTION_REQUIRED`   |
| GET/POST/PUT/PATCH without `Accept: application/jose`              | 406    | `JWE_RESPONSE_ENCRYPTION_REQUIRED`  |
| jose Accept but no `JWE-Response-Key`                              | 400    | `JWE_RESPONSE_KEY_REQUIRED`         |
| Malformed `JWE-Response-Key` envelope                              | 400    | `JWE_RESPONSE_KEY_INVALID`          |
| Malformed request JWE                                              | 400    | `JWE_MALFORMED`                     |
| Unsupported `alg`/`enc`                                            | 400    | `JWE_UNSUPPORTED_ALGORITHM`         |
| Missing/disallowed `cty`                                           | 400    | `JWE_INVALID_CONTENT_TYPE`          |
| Unknown or decommissioned `kid`                                    | 400    | `JWE_UNKNOWN_KEY_ID` (refresh JWKS) |
| Encrypted request body exceeds `jeap.jwe.filter.max-payload-bytes` | 413    | `JWE_PAYLOAD_TOO_LARGE`             |

Each error is logged as a structured entry (code, status, method, path) without key material or
plaintext payloads.

> Async/streaming responses (e.g. `StreamingResponseBody`, SSE) on non-excluded paths are not
> supported by the encrypting filter; expose such endpoints on excluded paths.

## Security notes

- Each encrypted request (and each GET carrying a `JWE-Response-Key` envelope) performs one
  RSA-4096 private-key operation. Since this happens before application authentication, rate-limit
  the encrypted endpoints and/or order the JWE filter after authentication where feasible to limit
  unauthenticated decrypt amplification.
- The payload size limit (`jeap.jwe.filter.max-payload-bytes`, default 5 MiB) bounds the encrypted
  request body and the response-key header to prevent memory exhaustion from unauthenticated input.
- An unknown/decommissioned `kid` returns a distinct `JWE_UNKNOWN_KEY_ID` (so clients know to
  refresh their JWKS). `kid`s are already public via the JWKS endpoint, so this exposes nothing
  secret.

The full security picture — IV uniqueness, CEK lifetime, key handling, rotation
recommendations — is consolidated in [Security considerations](security-considerations.md).

## Registration

The filter is registered via a `FilterRegistrationBean` if the starter is not explicitly disabled (
`jeap.jwe.enabled=false`). A disabled starter contributes no filter at all; only the
protocol-metadata endpoint remains, publishing `"enabled": false` for clients.

Its position in the chain is configurable through `jeap.jwe.filter.order` (default `0`), which
places it after the Spring Security filter chain (registered at order `-100`) and early enough to
wrap the request before the `DispatcherServlet`.

## Using with jeap-security

The JWE filter composes cleanly with `jeap-spring-boot-security-starter`: Spring Security's filter
chain runs at order `-100`, so a request is **authenticated first** and only then decrypted by the
JWE filter at order `0`. Concretely:

- an unauthenticated request is rejected (e.g. `401`) by jeap-security **before** any RSA decryption,
  limiting unauthenticated decrypt amplification (see [Security notes](#security-notes));
- an authenticated but plaintext request still fails the JWE enforcement (`415`/`406`) **after**
  authentication succeeds;
- an authenticated, encrypted request round-trips, and the authenticated principal reaches the
  controller through the transparently decrypted request.

**Public discovery endpoints.** Clients must fetch the public key **before** they authenticate, so
the JWKS and protocol-metadata endpoints have to be reachable without a token. When Spring Security
is on the classpath, the starter contributes a high-precedence `SecurityFilterChain`
(`JweSecurityAutoConfiguration`) whose `securityMatcher` is scoped to exactly those configured paths
— both of them while JWE is on, the metadata path alone while `jeap.jwe.enabled=false`, where no
JWKS endpoint exists — and that permits all requests; every other path falls through to your
application's own chain,
so nothing else is opened. This composes with jeap-security (its chains run at `LOWEST_PRECEDENCE`
and are not `@ConditionalOnMissingBean`, so they keep protecting everything else). No manual
`permitAll` rule is needed. To manage these paths yourself, opt out with
`jeap.jwe.security.permit-well-known-endpoints=false`.

> The chain is contributed only when an `HttpSecurity` bean exists (i.e. the application actually
> uses Spring Security). In the rare case of an app that relies solely on Spring Boot's
> auto-generated default security chain (no jeap-security and no own `SecurityFilterChain`), adding
> any chain makes that default back off — opt out and configure security explicitly there. jeap
> services always register their own chain, so this does not affect them.

This coexistence is covered end-to-end by the `jeap-spring-boot-jwe-security-it` module, which runs the JWE filter
alongside a real jeap-security resource server (including that the JWKS and metadata endpoints are
reachable unauthenticated, and the opt-out leaves them protected).

## Path matching (includes, then excludes)

The filter applies to a request only when its path matches an **include** pattern and does **not**
match an **exclude** pattern — includes first, excludes second (excludes win). Everything else is
passed through **unchanged** (no decryption, no enforcement, no response encryption).

**Includes (`jeap.jwe.filter.included-paths`, default `[/*api*/**]`).** By default only API paths are
filtered: any path whose first segment contains `api` and everything under it (`*` is an
intra-segment wildcard, so `/*api*` matches `/api`, `/v1api`, ... and `/*api*/**` adds their
sub-paths). This is what keeps a Self-Contained-System app — one Spring Boot server hosting both the
REST API and the frontend/static resources — from encrypting its static assets or SPA shell. Broaden
it (e.g. add `/internal-api/**`) if your API is not under an `*api*` segment:

```yaml
jeap:
  jwe:
    filter:
      included-paths:
        - /api/**
        - /internal-api/**
```

**Excludes.** jEAP excludes known endpoints that are never encrypted, even if you broaden the includes:

- **Actuator** — the actuator base path and everything under it (`/actuator`, `/actuator/**`, or the
  value of `management.endpoints.web.base-path` if relocated).
- **JWKS endpoint** — the configured `jeap.jwe.jwks.path`, so clients can always fetch keys.
- **Protocol metadata** — `jeap.jwe.metadata.path`.
- **jEAP SSE** — the SSE endpoint (`jeap.sse.web.endpoint`, default `/ui-api/sse/events`) and its
  subpaths. SSE carries only event IDs, not payload data.

Add your own exclusions (for example public/unauthenticated API endpoints) with `PathPattern`
patterns via `jeap.jwe.filter.excluded-paths`; they extend the built-in defaults.

### Context path

`included-paths` and `excluded-paths` are matched against the **application-relative** path — the
filter strips `server.servlet.context-path` first (it matches the same normalized path Spring MVC
routes on, `RequestPath.pathWithinApplication()`). So the patterns must **not** contain the context
path, exactly like `@RequestMapping` paths and `management.endpoints.web.base-path`. The defaults work
unchanged whether the app is deployed at `/` or under a context path: with `server.servlet.context-path=/myapp`,
a request to `/myapp/api/orders` is matched as `/api/orders` and still hits the default `/*api*/**`
include.

The protocol-metadata endpoint is the exception: because a browser client matches the **full** request
URL (which includes the context path), the published `includedPaths`/`excludedPaths`/`jwksPath` are
**prefixed with the context path** so they are directly usable against the origin (see below).

## Protocol metadata endpoint

The starter exposes a small client-facing configuration document at
`jeap.jwe.metadata.path` (default `/.well-known/jwe-configuration`), always excluded from
encryption, so a frontend has a single discovery point alongside the JWKS:

```json
{
  "enabled": true,
  "contentTypeAllowlist": [
    "application/json"
  ],
  "keyEncryptionAlgorithm": "RSA-OAEP-256",
  "contentEncryptionMethod": "A256GCM",
  "jwksPath": "/.well-known/jwks.json",
  "responseKeyHeader": "JWE-Response-Key",
  "includedPaths": [
    "/*api*/**"
  ],
  "excludedPaths": [
    "/actuator",
    "/actuator/**",
    "/.well-known/jwks.json",
    "/.well-known/jwe-configuration",
    "/ui-api/sse/events",
    "/ui-api/sse/events/**"
  ]
}
```

`includedPaths` and `excludedPaths` are the **effective** patterns the filter applies (includes
first, excludes second; `excludedPaths` already includes the built-in jEAP defaults plus any
configured `jeap.jwe.filter.excluded-paths`), so a client can replicate the server's decision: a
request is encrypted iff its path matches an include and no exclude. It reflects the live
configuration and contains no security-sensitive material.

## Related

- [Client integration](client-integration.md)
- [Configuration reference](configuration.md)
- [JWKS endpoint](jwks-endpoint.md)
- [Key management](key-management.md)
- [Security considerations](security-considerations.md)
- [Troubleshooting](troubleshooting.md)
