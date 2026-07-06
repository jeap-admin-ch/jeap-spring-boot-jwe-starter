# Client Integration

This page describes the client side of the JWE protocol — what a frontend (or any HTTP client) must
do to talk to a service secured by the [servlet filter](servlet-filter.md).

> **Angular?** Don't implement this by hand. Use the official client library
> **[jeap-jwe-client](https://jeap-admin-ch.github.io/docs/building-blocks/libraries/jeap-jwe-client/)**
> ([source](https://github.com/jeap-admin-ch/jeap-jwe-client)) — an npm module that
> provides an Angular `HttpInterceptor` integrating directly with `jeap-spring-boot-jwe-starter`.
> It transparently fetches the JWKS, encrypts outgoing requests, attaches the response-key envelope
> and decrypts responses, so your application code keeps working with plain JSON. The rest
> of this page documents the underlying protocol for non-Angular clients or for understanding what
> the library does.

## Protocol at a glance

- **Algorithms:** the content-encryption key (CEK) is transported/derived with **RSA-OAEP-256**;
  payloads are encrypted with **A256GCM**. Responses use direct encryption (`alg: dir`).
- **Media type on the wire:** encrypted bodies are always `application/jose` (compact JWE).
- **Stateless:** every request is independent — no sessions or sticky routing. The client drives the
  CEK lifecycle per request/response pair.
- **Separate request/response CEKs:** the request body carries its own CEK (RSA-wrapped inside the
  request JWE); the response is encrypted with a **separate** CEK the client supplies in the
  `JWE-Response-Key` header. The request CEK is never reused for the response — so a client that wants
  an encrypted response always sends `JWE-Response-Key`, including on POST/PUT/PATCH.

## Discovery

Both discovery documents are served **unencrypted** (they are on the filter's exclusion list):

1. **JWKS** — active public keys at `jeap.jwe.jwks.path` (default `/.well-known/jwks.json`). Use the
   **first** key (`keys[0]`) as the current encryption key; echo its `kid` in the JWE header. The set
   contains all active versions during a rotation grace period, so a response encrypted under a
   slightly older `kid` still decrypts server-side.
2. **Protocol metadata** — at `jeap.jwe.metadata.path` (default `/.well-known/jwe-configuration`):

   ```json
   {
     "contentTypeAllowlist": ["application/json"],
     "keyEncryptionAlgorithm": "RSA-OAEP-256",
     "contentEncryptionMethod": "A256GCM",
     "jwksPath": "/.well-known/jwks.json",
     "responseKeyHeader": "JWE-Response-Key",
     "includedPaths": ["/*api*/**"],
     "excludedPaths": ["/actuator/**", "/.well-known/jwks.json", "/.well-known/jwe-configuration", "/ui-api/sse/events/**"]
   }
   ```

   `includedPaths`/`excludedPaths` are the server's **effective** path patterns (`PathPattern`
   syntax), excludes already including the jEAP defaults. A client can mirror the server's decision —
   encrypt a request iff its path matches an include and no exclude. These paths (and `jwksPath`) are
   **prefixed with the server's `server.servlet.context-path`** when one is configured, so they are
   directly usable against the origin: an app deployed at `/myapp` publishes `includedPaths:
   ["/myapp/*api*/**"]` and `jwksPath: "/myapp/.well-known/jwks.json"`. (The `jeap-jwe-client` library
   reads `includedPaths`/`excludedPaths` and uses them as the source of truth for its encrypt
   decision, mirroring the server; it appends any client-local excludes on top.)

**Caching & rotation:** the JWKS response carries a short `Cache-Control: max-age` — cache the keys
and refresh periodically. Always **re-fetch the JWKS and retry** when the server answers `400` with
`code: JWE_UNKNOWN_KEY_ID` (the key you used was rotated out or decommissioned).

## Header contract

| Direction  | Header             | POST/PUT/PATCH                                              | GET                                              |
|------------|--------------------|-------------------------------------------------------------|--------------------------------------------------|
| Request →  | `Content-Type`     | `application/jose` (the encrypted body)                     | — (no body)                                      |
| Request →  | `Accept`           | `application/jose` (**required** for an encrypted response) | `application/jose` (**required**)                |
| Request →  | `JWE-Response-Key` | **required** — RSA-wrapped response CEK envelope            | **required** — RSA-wrapped response CEK envelope |
| ← Response | `Content-Type`     | `application/jose`                                          | `application/jose`                               |

## Sending an encrypted request (POST/PUT/PATCH)

1. Fetch the current public key (`keys[0]`) from the JWKS endpoint.
2. Build the request JWE: protected header
   `{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"<keys[0].kid>","cty":"application/json"}`
   (`cty` must be on the content-type allowlist), payload = the plaintext JSON body. The JOSE library
   generates and RSA-wraps the request CEK for you; you do not need to keep it.
3. To receive an encrypted response, also generate a **separate** 256-bit response CEK, wrap it as a
   `JWE-Response-Key` envelope (see the GET flow below), and send it with `Accept: application/jose`.
4. Send the request with `Content-Type: application/jose` (and the headers from step 3).
5. The response comes back as `application/jose`, encrypted (`alg: dir`, `enc: A256GCM`) with your
   **response CEK** (not the request CEK). Decrypt it with the response CEK; the `cty` tells you how to
   interpret the plaintext (e.g. `application/json`).

A plaintext body on a non-excluded path is rejected with **415**; a missing `Accept: application/jose`
with **406**; a missing/invalid `JWE-Response-Key` with **400** — all as `problem+json`.

```
client                                              service (jwe-starter)
  | GET /.well-known/jwks.json  ─────────────────▶  | (excluded → plain)
  | ◀── 200 { keys: [ {kid, n, e, ...} ] }          |
  | POST /api/orders                                 |
  |   Content-Type: application/jose                 |
  |   Accept: application/jose                       |
  |   JWE-Response-Key: <JWE(RSA-OAEP-256, rCek)>    |
  |   <JWE(RSA-OAEP-256,A256GCM, reqCek)>  ────────▶ | decrypt body; unwrap rCek
  | ◀── 200 application/jose <JWE(dir,A256GCM,rCek)> | encrypt response with rCek (≠ reqCek)
  | decrypt with rCek                                |
```

## Receiving an encrypted response (GET)

A GET has no request body, so the client supplies the response CEK itself:

1. Generate a random 256-bit CEK.
2. Wrap it as a compact JWE — protected header `{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"<keys[0].kid>"}`,
   payload = the raw 32-byte CEK.
3. Send the request with `Accept: application/jose` and that envelope in the `JWE-Response-Key`
   header (its name is configurable; read it from the metadata document).
4. Decrypt the `application/jose` response (`alg: dir`, `enc: A256GCM`) with the CEK you generated.

Without `Accept: application/jose` the request is rejected with **406**; with it but without a valid
`JWE-Response-Key` envelope, with **400**.

```
client                                            service (jwe-starter)
  | GET /api/orders/42                             |
  |   Accept: application/jose                     |
  |   JWE-Response-Key: <JWE(RSA-OAEP-256, cek)> ▶ | unwrap cek
  | ◀── 200 application/jose <JWE(dir,A256GCM,cek)>| encrypt response with that cek
  | decrypt with the cek you generated             |
```

## Error handling

Errors are returned as `application/problem+json` (RFC 7807) with a stable `code`:

| `code`                             | Status | Client action                                      |
|------------------------------------|--------|----------------------------------------------------|
| `JWE_REQUEST_ENCRYPTION_REQUIRED`  | 415    | Encrypt the request body as `application/jose`.    |
| `JWE_RESPONSE_ENCRYPTION_REQUIRED` | 406    | Send `Accept: application/jose`.                   |
| `JWE_RESPONSE_KEY_REQUIRED`        | 400    | Add the `JWE-Response-Key` envelope.               |
| `JWE_RESPONSE_KEY_INVALID`         | 400    | Rebuild the response-key envelope.                 |
| `JWE_MALFORMED`                    | 400    | Fix the compact JWE.                               |
| `JWE_UNSUPPORTED_ALGORITHM`        | 400    | Use `RSA-OAEP-256` and `A256GCM`.                  |
| `JWE_INVALID_CONTENT_TYPE`         | 400    | Use an allowlisted `cty`.                          |
| `JWE_UNKNOWN_KEY_ID`               | 400    | **Refresh the JWKS** and retry with a current key. |
| `JWE_PAYLOAD_TOO_LARGE`            | 413    | Reduce the payload below the server's size limit.  |

The `JWE_UNKNOWN_KEY_ID` case is the rotation signal: if the server rotated or decommissioned keys,
re-fetch the JWKS and retry.

## Implementing your own client

- **Angular:** use [jeap-jwe-client](https://jeap-admin-ch.github.io/docs/building-blocks/libraries/jeap-jwe-client/)
  (Angular `HttpInterceptor`, built on the `jose` library) — no manual wiring needed.
- **Other JavaScript/TypeScript:** use [`jose`](https://github.com/panva/jose) (`CompactEncrypt`,
  `compactDecrypt`, `importJWK`) and follow the flows above.
- **Browser without a library:** the Web Crypto API (`SubtleCrypto`) supports RSA-OAEP (SHA-256) and
  AES-GCM directly.

## Related

- [jeap-jwe-client (Angular interceptor)](https://jeap-admin-ch.github.io/docs/building-blocks/libraries/jeap-jwe-client/)
- [Servlet filter](servlet-filter.md)
- [JWKS endpoint](jwks-endpoint.md)
- [Configuration reference](configuration.md)
- [Security considerations](security-considerations.md)
- [Troubleshooting](troubleshooting.md)
- [Testing without Vault](testing.md)
