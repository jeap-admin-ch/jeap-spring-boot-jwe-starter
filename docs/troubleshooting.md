# Troubleshooting

Symptom-oriented guide to the most common problems when operating or integrating the JWE
starter. Each entry names the observable symptom, the likely cause, and the fix. The error
tables it builds on live in [Servlet filter](servlet-filter.md#mandatory-encryption--error-handling)
(server view) and [Client integration](client-integration.md#error-handling) (client view).

## Startup failures (fail-fast)

The starter refuses to start the application context when it cannot load usable keys — by
design (see [Key management](key-management.md#startup-load-fail-fast)). Typical causes:

| Symptom at startup | Likely cause | Fix |
|--------------------|--------------|-----|
| Context fails with a Vault connection error | Vault unreachable, or `spring.cloud.vault.*` connectivity/authentication not configured | Configure Spring Cloud Vault (address, authentication); check network/policy. See [Vault integration](vault-integration.md#prerequisites). |
| Vault error mentioning the export endpoint or permission denied | Vault policy lacks `read`/`update` on `transit/<system>/*`, or the key is **not exportable** | Grant the policy; recreate the key with `exportable=true` (exportability cannot be enabled retroactively — create a new key). |
| `JweKeyValidationException` (key rejected) | Transit key is not `rsa-4096` (wrong type or size) | Create the key with `type=rsa-4096`; smaller keys are never accepted. |
| "No keys" although Vault is reachable | All exported versions are below `jeap.jwe.vault.min-key-version` | Lower `min-key-version`, or rotate the key until a version ≥ the minimum exists. |
| Startup validation error about the transit key name / secret-engine path | `jeap.jwe.vault.transit-key-name` missing, or neither `jeap.jwe.vault.secret-engine-path` nor `jeap.vault.system-name` set | Set the missing property. See [Configuration reference](configuration.md#validation). |
| Startup validation error in tests | `jeap.jwe.test.enabled=true` but `jeap.jwe.test.keys` is empty | Provide at least one PEM key, e.g. via `JweTestKeys` (see [Testing without Vault](testing.md)). |
| `IllegalStateException` about the JWKS path | `jeap.jwe.jwks.path` overlaps the actuator base path | Move the JWKS path or the actuator base path so they don't overlap. |

If you need to start **without** JWE (e.g. a test slice), disable the starter with
`jeap.jwe.enabled=false` instead of working around the fail-fast load.

## Requests are rejected with `problem+json` errors

All protocol rejections carry a stable `code`. The two most frequent in practice:

| Symptom | Cause | Fix |
|---------|-------|-----|
| `415 JWE_REQUEST_ENCRYPTION_REQUIRED` on POST/PUT/PATCH | The client sent a plaintext body on a path where encryption is mandatory | Encrypt the body as `application/jose` — or, if the path should not be encrypted, add it to `jeap.jwe.filter.excluded-paths`. |
| `406 JWE_RESPONSE_ENCRYPTION_REQUIRED` | Missing `Accept: application/jose` | Send the header; with [jeap-jwe-client](https://jeap-admin-ch.github.io/docs/building-blocks/libraries/jeap-jwe-client/) check that the request URL matches the server's published `includedPaths`. |
| `400 JWE_RESPONSE_KEY_REQUIRED` / `JWE_RESPONSE_KEY_INVALID` | Missing or malformed `JWE-Response-Key` envelope | Wrap a fresh 256-bit CEK as a compact JWE to the current public key (see [Client integration](client-integration.md#receiving-an-encrypted-response-get)). |
| `400 JWE_UNKNOWN_KEY_ID` | The client encrypted with a rotated-out or decommissioned `kid` (stale JWKS cache) | The client must re-fetch the JWKS and retry — this is the normal rotation signal, not a server fault. See [Key rotation](#key-rotation-issues). |
| `400 JWE_UNSUPPORTED_ALGORITHM` | JWE header uses something other than `RSA-OAEP-256` / `A256GCM` | Fix the client's protected header. |
| `400 JWE_INVALID_CONTENT_TYPE` | The JWE `cty` is missing or not allowlisted | Set `cty` to an entry of `jeap.jwe.filter.content-type-allowlist` (default `application/json`). |
| `413 JWE_PAYLOAD_TOO_LARGE` | Encrypted body or response-key header exceeds `jeap.jwe.filter.max-payload-bytes` (default 5 MiB) | Reduce the payload, or raise the limit deliberately. |

Note that error responses are **never encrypted** — a client must be prepared to receive
`application/problem+json` where it expected `application/jose`.

## Nothing is encrypted / the filter doesn't apply

The filter only touches requests whose **application-relative** path matches an include and no
exclude (see [Servlet filter → Path matching](servlet-filter.md#path-matching-includes-then-excludes)):

- **Your API is not under an `*api*` segment.** The default include is `/*api*/**`. A path like
  `/orders/42` never matches, so it passes through in plaintext without any enforcement.
  Broaden `jeap.jwe.filter.included-paths`.
- **Patterns contain the context path.** Include/exclude patterns are matched **after**
  `server.servlet.context-path` is stripped — `/myapp/api/**` never matches; write `/api/**`.
  (The metadata endpoint publishes the patterns *with* the context path — that is intentional,
  for browser clients matching full URLs.)
- **The path is excluded.** Actuator, JWKS, protocol metadata and jEAP SSE are always excluded;
  check `jeap.jwe.filter.excluded-paths` for additions.
- **The starter is disabled.** Check `jeap.jwe.enabled` and — the definitive signal — the
  `jeap.jwe.encryption.active` gauge (`1` only when both enforcement directions are on and keys
  are loaded; see [Observability](observability.md#verifying-end-to-end-encryption-governance)).

## Key-rotation issues

- **Clients fail with `JWE_UNKNOWN_KEY_ID` right after raising `min-key-version`.** Expected if
  clients were still using an evicted version: they must re-fetch the JWKS and retry
  ([jeap-jwe-client](https://jeap-admin-ch.github.io/docs/building-blocks/libraries/jeap-jwe-client/)
  does this automatically). To avoid the error spike, raise `min-key-version` only after one
  JWKS cache lifetime plus one refresh interval — see the
  [key-rotation recommendations](security-considerations.md#key-rotation-recommendations).
- **A rotated key doesn't show up.** New versions appear at the next refresh
  (`jeap.jwe.refresh.interval`, default 5 minutes). Check the `jeap.jwe.keys.current.version`
  gauge and the `jeap.jwe.key.refresh` counter for failed cycles.
- **Rotation appears to do nothing in tests.** Static test mode loads keys once and never
  refreshes — rotation semantics only exist in Vault mode.

## Vault outages at runtime

A failed refresh never empties the key store: the starter retries with exponential backoff and
then keeps serving the most recently cached keys ([Key management](key-management.md#outage-resilience)).
To diagnose:

- `jeap.jwe.key.refresh{result="failure"}` counts exhausted refresh cycles.
- `time() - jeap_jwe_key_refresh_timestamp_seconds` tells you how stale the cached keys are.
- Decryption and the JWKS endpoint keep working during the outage; only *new* key versions are
  delayed. No restart is needed — the next scheduled refresh recovers automatically.

## Streaming and async endpoints

The encrypting filter does not support async/streaming responses (`StreamingResponseBody`,
SSE) on filtered paths. Expose such endpoints on excluded paths — the jEAP SSE endpoint is
excluded by default for exactly this reason.

## Diagnosing with metrics

The fastest way to localize a problem (all meters under the `jeap.jwe.*` prefix, see
[Observability](observability.md)):

| Question | Meter |
|----------|-------|
| Is end-to-end encryption actually active? | `jeap.jwe.encryption.active` (should be `1`) |
| Are clients sending bad requests? | `jeap.jwe.request.rejected` (by `reason`), `jeap.jwe.decryption{result="failure"}` (by `reason`) |
| Are key refreshes failing? | `jeap.jwe.key.refresh{result="failure"}`, `jeap.jwe.key.refresh.timestamp` |
| Did the rotation land? | `jeap.jwe.keys.current.version`, `jeap.jwe.keys.active` |

No meters at all? Metrics activate only when a Micrometer `MeterRegistry` is present — in a
jEAP service, add `jeap-spring-boot-monitoring-starter`.

## Related

- [Servlet filter](servlet-filter.md)
- [Client integration](client-integration.md)
- [Key management](key-management.md)
- [Vault integration](vault-integration.md)
- [Observability (metrics)](observability.md)
- [Security considerations](security-considerations.md)
- [Testing without Vault](testing.md)
