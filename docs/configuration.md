# Configuration Reference

All properties live under the `jeap.jwe` prefix.

## Core

| Property               | Type      | Default | Description                                                                            |
|------------------------|-----------|---------|----------------------------------------------------------------------------------------|
| `jeap.jwe.enabled`     | `boolean` | `true`  | Master switch. Set to `false` to disable all JWE beans.                                |

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

| Property                              | Type       | Default | Description                                                  |
|---------------------------------------|------------|---------|--------------------------------------------------------------|
| `jeap.jwe.refresh.interval`           | `Duration` | `5m`    | How often Vault is polled for new key versions.              |
| `jeap.jwe.refresh.initial-backoff`    | `Duration` | `1s`    | Initial delay before the first retry after a failed refresh. |
| `jeap.jwe.refresh.backoff-multiplier` | `double`   | `2.0`   | Multiplier applied between consecutive retries.              |
| `jeap.jwe.refresh.max-backoff`        | `Duration` | `1m`    | Maximum delay between retries.                               |
| `jeap.jwe.refresh.max-attempts`       | `int`      | `5`     | Maximum retry attempts per refresh cycle.                    |

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
- [Key management](key-management.md)
- [Vault integration](vault-integration.md)
