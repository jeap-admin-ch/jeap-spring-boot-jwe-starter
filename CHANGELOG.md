# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.3] - 2026-07-07

### Changed

- Install the Amazon Corretto Crypto Provider eagerly at application startup instead of on the first encrypted request
- Route the RSA-OAEP-256 key unwrap through the generic JCA OAEP transformation so ACCP serves the RSA
  private-key operation (the SHA-256-specific transformation Nimbus requests is not registered by ACCP
  and silently fell back to the pure-Java JDK cipher)
- Cache the ready-to-use decrypter incl. the derived JCA private key per key version instead of rebuilding
  the private key via KeyFactory on every decrypt call
- Share one SecureRandom for response-IV generation instead of allocating a new one per encrypted response

## [1.2.2] - 2026-07-06

### Changed

- Docs: add a troubleshooting guide and a consolidated security-considerations page (IV uniqueness,
  CEK lifetime, key-rotation recommendations)
- Docs: add a Vault key-rotation sequence diagram and extend getting-started with a jEAP integration guide
- Docs: link the jeap-jwe-client library via its jEAP docs page

## [1.2.1] - 2026-07-03

### Fixed

- Register the JWE meters through a Micrometer `MeterBinder` instead of at bean construction, so they
  are bound only after all `MeterFilter`s are applied - eliminates the `PrometheusMeterRegistry`
  startup warning "A MeterFilter is being configured after a Meter has been registered".

## [1.2.0] - 2026-06-30

### Changed

- Update parent from 8.3.3 to 8.3.4

## [1.1.0] - 2026-06-26

### Added

- Observability: Micrometer metrics for decryption success/failure and latency, response encryption,
  Vault key-refresh status, active/current key versions, and a governance gauge
  (`jeap.jwe.encryption.active`) to verify end-to-end encryption is active. Activates automatically
  when a `MeterRegistry` is present (optional dependency, no-op otherwise).
- Use the Amazon Corretto Crypto Provider (ACCP) to accelerate the JWE RSA-OAEP and AES-GCM
  operations, with a transparent fallback to the JDK provider when the native library is unavailable
  (same approach as jeap-crypto-core).

## [1.0.0] - 2026-06-25

### Added

- JWE servlet filter providing transparent JWE request encryption/decryption

## [0.2.0] - 2026-06-23

### Changed

- Update parent from 8.3.2 to 8.3.3

## [0.1.0] - 2026-06-22

### Changed

- Update parent from 8.3.1 to 8.3.2

## [0.0.3] - 2026-06-18

### Changed
- Update parent from 8.2.0 to 8.3.1

## [0.0.2] - 2026-06-17

### Fixed

- Sonar issues
- Deprecated spring boot starter

## [0.0.1] - 2026-06-12

### Added

- Key management, both in-memory and using vault
- Public key exposure using a JWKS endpoint
