# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.20.0] - 2026-08-19

### Changed

- Update parent from 8.12.0 to 8.12.1

## [1.19.0] - 2026-08-18

### Changed

- Publish the master switch `jeap.jwe.enabled` as `enabled` in the protocol metadata, and keep the
  metadata endpoint answering while JWE is disabled, so clients can follow the switch instead of
  carrying their own build-time copy of it. Turn off with `jeap.jwe.metadata.publish-when-disabled=false`.
- The well-known security chain is now contributed whenever the metadata endpoint exists (previously
  only while `jeap.jwe.enabled=true`), so a disabled service does not answer discovery with `401`.
  While disabled it permits only the metadata path — there is no JWKS endpoint.

### Upgrade notes

- **Services running with `jeap.jwe.enabled=false` change behaviour on this upgrade.** They now serve
  a public, read-only endpoint at `jeap.jwe.metadata.path` (payload: `{"enabled": false}`, no key
  material) and, with Spring Security on the classpath, contribute the well-known `SecurityFilterChain`
  at order `-100`. As documented for that chain, contributing one makes Spring Boot's auto-generated
  default security chain back off in applications that rely on it. Set
  `jeap.jwe.metadata.publish-when-disabled=false` to keep the previous behaviour — no endpoint, no chain.
- `JweConfigurationMetadata` is a public record and its canonical constructor gained a leading
  `boolean enabled`, so code constructing or deconstructing it does not compile against this version
  unchanged. On the wire the field is purely additive; a client deserializing the document into its own
  DTO with `FAIL_ON_UNKNOWN_PROPERTIES` enabled has to accept it.

## [1.18.0] - 2026-08-18

### Changed

- Update parent from 8.11.0 to 8.12.0

## [1.17.0] - 2026-08-17

### Changed

- Update parent from 8.10.0 to 8.11.0

## [1.16.0] - 2026-08-13

### Changed

- Update parent from 8.9.1 to 8.10.0

## [1.15.0] - 2026-08-12

### Changed

- Update parent from 8.8.0 to 8.9.1

## [1.14.0] - 2026-08-11

### Changed

- Update parent from 8.7.1 to 8.8.0

## [1.13.0] - 2026-08-10

### Changed

- Update parent from 8.7.0 to 8.7.1

## [1.12.0] - 2026-08-08

### Changed

- Update parent from 8.6.1 to 8.7.0

## [1.11.0] - 2026-08-04

### Changed

- Update parent from 8.6.0 to 8.6.1

## [1.10.0] - 2026-08-01

### Changed

- Update parent from 8.5.6 to 8.6.0

## [1.9.0] - 2026-07-28

### Changed

- Update parent from 8.5.5 to 8.5.6

## [1.8.0] - 2026-07-25

### Changed

- Update parent from 8.5.4 to 8.5.5

## [1.7.0] - 2026-07-23

### Changed

- Update parent from 8.5.3 to 8.5.4

## [1.6.0] - 2026-07-23

### Changed

- Update parent from 8.5.2 to 8.5.3

## [1.5.0] - 2026-07-22

### Changed

- Update parent from 8.5.0 to 8.5.2

## [1.4.0] - 2026-07-15

### Changed

- Update parent from 8.4.0 to 8.5.0

## [1.3.0] - 2026-07-13

### Changed

- Update parent from 8.3.4 to 8.4.0

## [1.2.3] - 2026-07-07

### Changed

- Install the Amazon Corretto Crypto Provider eagerly at application startup instead of on the first encrypted request
- Route the RSA-OAEP-256 key unwrap through the generic JCA OAEP transformation so ACCP serves the RSA private-key operation
- Cache the ready-to-use decrypter incl. the derived JCA private key per key version, evicting retired versions on key refresh
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
