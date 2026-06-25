# AGENTS.md

Guidance for AI coding agents working in this repository. Human contributors may also
find it useful. Keep this file up to date as the project evolves.

## Project

`jeap-spring-boot-jwe-starter` is a jEAP Spring Boot starter that provides transparent
**JWE-based end-to-end encryption** for jEAP Spring Boot services:

- Manages Vault-backed RSA key material (load at startup, refresh, rotation).
- Exposes the backend public keys as a **JWKS endpoint** (RFC 7517).
- Decrypts incoming `application/jose` requests and encrypts responses, transparently to
  controllers, via a servlet filter (`JweServletFilter`), with mandatory-encryption
  enforcement returning RFC 7807 `problem+json` errors.

Algorithms: `RSA-OAEP-256` for the content-encryption-key, `A256GCM` for the payload.
Only established JOSE libraries are used (Nimbus JOSE+JWT on the server). **No custom
cryptography.**

## Repository layout

```
docs/                                      # Documentation
pom.xml                                    # Parent POM (packaging=pom); declares the modules below
jeap-spring-boot-jwe-crypto/               # Pure JOSE/crypto (Nimbus); no Spring
jeap-spring-boot-jwe-key-management/       # Key-store abstraction, cache, static + Vault key sources
jeap-spring-boot-jwe-web/                  # JWKS + metadata endpoints, JWE servlet filter (servlet stack only)
jeap-spring-boot-jwe-starter/              # @AutoConfiguration, configuration properties, wiring
jeap-spring-boot-jwe-test/                 # Shared test infrastructure (reusable RSA test keys), test scope
jeap-spring-boot-jwe-security-it/          # Coexistence ITs with jeap-spring-boot-security-starter (test-only, but published)
Jenkinsfile                                # jEAP build pipeline (master / feature / hotfix)
publiccode.yml, CHANGELOG.md, LICENSE, SECURITY.md, THIRD-PARTY-LICENSES.md
```

### Module structure

Mirrors the `jeap-crypto` layout (`jeap-crypto-vault`, `jeap-crypto-vault-starter`).
Dependency direction is acyclic: `crypto` ← `key-management` ← `web` ← `starter`.

- `…-jwe-crypto` — pure JOSE/crypto utilities (Nimbus): RSA key factory, 4096-bit
  validation, JWK Set conversion. No Spring.
- `…-jwe-key-management` — key-store abstraction (`JweKeyStore`) with an atomically-swapped
  in-memory cache (`InMemoryJweKeyStore`) and two `JweKeySource`s: the static test source
  (`StaticJweKeySource`) and the Vault transit source (`VaultJweKeySource`). A `JweKeyLoader`
  performs the fail-fast startup load; `JweKeyRefresher` + `JweKeyRefreshScheduler` do the
  periodic, outage-resilient refresh. Depends on Spring Cloud Vault.
- `…-jwe-web` — the web layer: the JWKS endpoint (`JweJwksController`), the protocol-metadata
  endpoint (`JweMetadataController`) and the servlet filter (`JweServletFilter`) for request
  decryption / response encryption, including the include/exclude path model (`JweFilterPaths`)
  and the `problem+json` error writer (`JweProblemWriter`, serialized with Jackson). Depends on
  key-management. **Servlet stack only** (see constraint below).
- `…-jwe-starter` — `@AutoConfiguration` (`JweAutoConfiguration`, `JweVaultAutoConfiguration`,
  `JweWebAutoConfiguration`), configuration properties, wiring. Depends on key-management and
  web.
- `…-jwe-test` — shared test infrastructure (reusable 4096-bit RSA test keys via `JweTestKeys`);
  depended on with `<scope>test</scope>`. Not for production use.
- `…-jwe-security-it` — integration tests proving the JWE filter coexists with
  `jeap-spring-boot-security-starter` (auth at order `-100`, JWE at order `0`). Isolates the
  jeap-security dependency to a test scope so it never reaches the published starter. Has only
  test sources, so it attaches an empty javadoc jar (Maven Central requires one).

> **Servlet-only support.** This starter targets the Spring MVC / Jakarta Servlet stack
> only. Reactive (Spring WebFlux) is **not** supported. Web beans are gated on a servlet
> web application type (e.g. `@ConditionalOnWebApplication(type = SERVLET)`), and the
> request/response encryption is implemented as a `jakarta.servlet.Filter`.

## Build & test

Use the Maven wrapper (`./mvnw`). Toolchain: **Java 25**, parent
`ch.admin.bit.jeap:jeap-internal-spring-boot-parent:8.3.3`.

```bash
./mvnw clean install          # full build + tests
./mvnw test                   # unit tests
./mvnw verify                 # includes integration tests + license checks
./mvnw -pl <module> test      # test a single module
```

- Features must be covered by **Spring Boot integration tests**.
- Vault-backed behavior is tested against a Vault dev container configured via a
  `docker/vault-test-config.sh` script with the transit engine + approle auth (see
  `jeap-crypto` for the pattern). The **static test mode** (no Vault) must allow the
  encryption logic to be integration-tested in CI without a Vault instance.

### Testing principles

- **Prefer tests with as little mocking as possible** — exercise real components and real
  wiring over mocks/stubs wherever practical.
- **When Vault integration is the thing under test, use a real Vault test container**
  (Testcontainers), not a stub. This applies to key export, periodic refresh, and outage
  resilience tests.
- **When Vault integration is not the main concern**, you may stub Vault access to keep the
  test focused and fast (e.g. testing the JWKS endpoint, key model, or cache behavior).
- **If the Vault stub is reused in more than one place, extract it into a dedicated Maven
  submodule for test infrastructure** (e.g. `jeap-spring-boot-jwe-test`) rather than copying
  it across modules; depend on it with `<scope>test</scope>`.

## jEAP conventions

- Base package: `ch.admin.bit.jeap.…`.
- Auto-configuration: `@AutoConfiguration` classes registered in
  `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.
- Gate Vault integration with `@ConditionalOnProperty("spring.cloud.vault.enabled")`
  (`matchIfMissing = true`), so services without encryption configured are unaffected
  (opt-in / backward compatible).
- Vault access via Spring Cloud Vault `VaultOperations` / `VaultTemplate`. This starter
  depends **only on Spring Cloud Vault**, not on `jeap-vault-starter`.
- Transit secret-engine path convention: default `transit/<jeap.vault.system-name>`.
- Configuration via `@ConfigurationProperties` (prefix `jeap.jwe`; see `JweProperties`).
  All security-relevant parameters are configurable: Vault address,
  transit key name, auth method, refresh interval, JWKS path, minimum accepted key
  version.
- Prefer the **jeap-mcp-service** tools and **Context7 MCP** for jEAP/library
  documentation and examples before generic web search. `jeap-crypto` is the closest
  reference implementation for Vault key management.

## Security constraints (do not violate)

- RSA keys must be **4096 bits**; smaller keys are rejected (validate on load).
- RSA key material lives **exclusively in the JVM heap**. Never write key material to
  file systems, logs, environment variables, or external caches.
- Never log plaintext payloads or key material.
- A Vault outage must not break decryption for keys already loaded; serve the most
  recently cached keys and retry with exponential backoff.
- Fail fast at startup if Vault is required but unreachable.

## Code comments

- Instead, write **self-contained comments** that explain the *what* and *why* without
  requiring the reader to look up an external document. For example, write
  "Key material never leaves the JVM heap" rather than "Key material never leaves the JVM
  heap (JIRA-123)".
- **Do not create `package-info.java` files.** They are not used in this project.

## Versioning and Commits

- Commit Message: Use the JIRA ID from the branch name as a prefix (if available), do not use conventional commit
  messages. Keep messages concise and to the point. Example: `JIRA-1234 Implement feature X`.
- Semantic Versioning; all changes documented in [CHANGELOG.md](./CHANGELOG.md) (Keep a Changelog format).
- `setPomVersions.sh` updates the version across all module POMs.
- When working on a feature branch, increase the version to `x.y.z-SNAPSHOT` in the POMs.
- When bumping the version, also update the changelog, and update version/date in `publiccode.yml`.
- Changelog: Add a new section for the updated version, add a "### Changed" section beneath it, describe the changes on
  the feature branch, and set today's date for the new version
- Changelog: Keep changelog entries concise and to the point. Lean towards single-line entries.
- When the version on a feature branch has not yet been bumped compared to master, ask the user if a major, minor or
  patch version bump should be performed, and update the version accordingly.
