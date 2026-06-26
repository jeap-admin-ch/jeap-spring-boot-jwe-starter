# jEAP Spring Boot JSON Web Encryption (JWE) Starter

The jeap-spring-boot-jwe-starter provides transparent JWE-based end-to-end encryption support for jEAP Spring Boot
services. It automatically exposes the backend public keys as a JWKS endpoint, manages Vault-backed RSA key material
including refresh and rotation support, and decrypts incoming application/jose requests before they reach Spring MVC
controllers. For protected endpoints, the starter also encrypts JSON responses as JWE, supports configurable exclusions
such as actuator and JWKS endpoints, and provides structured error responses for invalid or missing encryption protocol
data. It is designed to use established JOSE libraries and standard algorithms such as RSA-OAEP-256 and A256GCM, without
requiring application controllers to implement encryption logic themselves.

> **Angular frontends:** use the companion library
> **[jeap-jwe-client](https://github.com/jeap-admin-ch/jeap-jwe-client)** — an npm module providing an
> Angular `HttpInterceptor` that integrates with this starter and transparently encrypts requests and
> decrypts responses. See [Client integration](docs/client-integration.md) for the protocol details.

## Modules

| Module                                | Purpose                                                                                                                                                                                                            |
|---------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `jeap-spring-boot-jwe-crypto`         | Crypto utilities (Nimbus). RSA key factory, 4096-bit validation, JWK Set conversion. No Spring dependency.                                                                                                         |
| `jeap-spring-boot-jwe-key-management` | Key-store abstraction (`JweKeyStore`), in-memory cache, key sources (static test + Vault transit), loader, and periodic refresher with exponential backoff.                                                        |
| `jeap-spring-boot-jwe-web`            | Servlet stack: JWKS endpoint, the JWE servlet filter (request decryption / response encryption), mandatory-encryption enforcement with RFC 7807 errors, and the protocol-metadata endpoint.                        |
| `jeap-spring-boot-jwe-starter`        | Auto-configuration, configuration properties (`jeap.jwe.*`), bean wiring.                                                                                                                                          |
| `jeap-spring-boot-jwe-test`           | Shared test infrastructure (reusable 4096-bit RSA test keys). Test scope only.                                                                                                                                     |
| `jeap-spring-boot-jwe-security-it`    | Integration tests proving the starter coexists with `jeap-spring-boot-security-starter` (Bearer-token auth + transparent JWE). Test sources only; keeps the jeap-security dependency out of the published starter. |

Dependency direction: `crypto` ← `key-management` ← `web` ← `starter`. The `…-security-it`
module is a test-only leaf depending on `…-starter`.

## Documentation

| Topic                    | File                                                     |
|--------------------------|----------------------------------------------------------|
| Architecture overview    | [docs/architecture.md](docs/architecture.md)             |
| Quick setup              | [docs/getting-started.md](docs/getting-started.md)       |
| Configuration reference  | [docs/configuration.md](docs/configuration.md)           |
| Servlet filter           | [docs/servlet-filter.md](docs/servlet-filter.md)         |
| Client integration       | [docs/client-integration.md](docs/client-integration.md) |
| Key management internals | [docs/key-management.md](docs/key-management.md)         |
| JWKS endpoint            | [docs/jwks-endpoint.md](docs/jwks-endpoint.md)           |
| Vault integration        | [docs/vault-integration.md](docs/vault-integration.md)   |
| Observability (metrics)  | [docs/observability.md](docs/observability.md)           |
| Testing without Vault    | [docs/testing.md](docs/testing.md)                       |

## See

- jeap-jwe-client (Angular HTTP interceptor): https://github.com/jeap-admin-ch/jeap-jwe-client
- JSON Web Encryption (JWE): https://datatracker.ietf.org/doc/rfc7516/
- JSON Web Key (JWK): https://datatracker.ietf.org/doc/rfc7517/

## Changes

This library is versioned using [Semantic Versioning](http://semver.org/) and all changes are documented in
[CHANGELOG.md](./CHANGELOG.md) following the format defined in [Keep a Changelog](http://keepachangelog.com/).

## Note

This repository is part the open source distribution of jEAP.
See [github.com/jeap-admin-ch/jeap](https://github.com/jeap-admin-ch/jeap)
for more information.

## License

This repository is Open Source Software licensed under the [Apache License 2.0](./LICENSE).
