# JWKS Endpoint

The starter exposes the active public keys as a JSON Web Key Set (RFC 7517) over HTTP. Clients
use this endpoint to retrieve the RSA public keys needed to encrypt payloads for this service.

## Path

Default: `/.well-known/jwks.json`

Customizable via `jeap.jwe.jwks.path`:

```yaml
jeap:
  jwe:
    jwks:
      path: /api/keys/jwks.json
```

The path must not overlap with the actuator base path (`management.endpoints.web.base-path`,
default `/actuator`). If it does, the starter fails at startup with an `IllegalStateException`.

## Response Format

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "enc",
      "kid": "my-jwe-key:3",
      "alg": "RSA-OAEP-256",
      "n": "..."
    }
  ]
}
```

- Only **public key parameters** are emitted (no private key material).
- Keys are ordered by version descending (highest/current version first).
- The `kid` format is `<transit-key-name>:<version>`.
- `alg` is always `RSA-OAEP-256`; `use` is always `enc`.

## Content Type

The endpoint produces `application/json`.

## Security

The endpoint is unauthenticated by design - public keys are meant to be distributed to clients.
When Spring Security is on the classpath, the starter automatically permits unauthenticated access
to the JWKS path (and the protocol-metadata path) via a dedicated `SecurityFilterChain`, so no
manual `permitAll` rule is required. Opt out with `jeap.jwe.security.permit-well-known-endpoints=false`
to manage access yourself (see [Using with jeap-security](servlet-filter.md#using-with-jeap-security)).

## Related

- [Configuration reference](configuration.md)
- [Key management](key-management.md)
- [Servlet filter](servlet-filter.md)
- [Client integration](client-integration.md)
