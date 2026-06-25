# Key Management

The starter manages RSA key material entirely in memory. Keys are loaded at startup and
periodically refreshed from Vault. The key store is the single source of truth for all
components (the [JWKS endpoint](jwks-endpoint.md) and the [servlet filter](servlet-filter.md) that
decrypts requests and encrypts responses).

## Key Store

`InMemoryJweKeyStore` holds an atomically-swapped snapshot of active RSA keys. Each snapshot
is an immutable, version-ordered list. The highest-versioned key is the "current" key (used
for encryption); all keys in the snapshot can be used for decryption.

Keys are identified by their `kid` in the format `<transit-key-name>:<version>` (e.g.
`my-jwe-key:3`).

## Startup Load (fail-fast)

`JweKeyLoader.loadOrThrow()` runs during context initialization. If the key source is
unreachable, returns no keys, or returns keys that fail validation (e.g. not 4096-bit RSA),
the application context **refuses to start**. This prevents the service from running without
usable encryption keys.

## Periodic Refresh

In Vault mode, `JweKeyRefreshScheduler` triggers a refresh at a configurable interval
(default: 5 minutes). Each refresh cycle:

1. Exports all active key versions from Vault.
2. Filters out versions below `jeap.jwe.vault.min-key-version`.
3. Validates each key (4096-bit RSA).
4. Atomically swaps the key store snapshot.

New keys from Vault rotations become available within one refresh interval. Old keys removed
via `min-key-version` eviction are dropped from the snapshot.

## Outage Resilience

If a refresh attempt fails (Vault unreachable, auth expired, etc.), the starter applies
exponential backoff retries within the same refresh cycle:

- Initial backoff: `jeap.jwe.refresh.initial-backoff` (default 1s)
- Multiplier: `jeap.jwe.refresh.backoff-multiplier` (default 2.0)
- Max backoff: `jeap.jwe.refresh.max-backoff` (default 1m)
- Max attempts: `jeap.jwe.refresh.max-attempts` (default 5)

If all retries fail, the **most recently cached keys remain in place**. The JWKS endpoint and
decryption continue to work with the cached snapshot. The next scheduled refresh will retry
from scratch.

## Key Validation

Every key loaded (from Vault or static config) must be:

- An RSA key pair (private + public)
- Exactly **4096 bits** in size

Keys that fail validation are rejected with a `JweKeyValidationException`. Smaller key sizes
are never accepted.

## Security Invariants

- Key material lives **exclusively in JVM heap memory**. It is never written to disk, logs,
  environment variables, or external caches.
- Key material is never logged. Log messages include only the `kid` identifiers.
- The `toString()` output of `JweProperties.Test` redacts key content.

## Related

- [Configuration reference](configuration.md)
- [Vault integration](vault-integration.md)
- [JWKS endpoint](jwks-endpoint.md)
- [Servlet filter](servlet-filter.md)
- [Client integration](client-integration.md)
